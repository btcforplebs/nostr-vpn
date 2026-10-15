use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinEncodable as _, BinEncoder};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[cfg(test)]
use crate::config::CLOUDFLARE_DOH_URL;
use crate::config::{ExitDnsConfig, ExitDnsResolverConfig};

#[cfg(test)]
const DOH_HOST: &str = "cloudflare-dns.com";
const DOH_CONTENT_TYPE: &str = "application/dns-message";
const DOH_TIMEOUT: Duration = Duration::from_secs(3);
const WIREGUARD_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const WIREGUARD_DNS_RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// How long a fast negative answer (NXDOMAIN, SERVFAIL, REFUSED, or NOERROR
/// with no records) from one server waits for a real answer from another.
/// Returning nothing is faster than recursing, so without the hold a server
/// that is up but broken wins every lookup because it is broken. The hold
/// only runs while another server's lookup is still outstanding.
///
/// 2 s: a lost first packet is retransmitted after
/// `WIREGUARD_DNS_RETRY_INTERVAL`, and the answer to that retransmit needs a
/// round trip on top. A hold equal to the retry interval expires just as the
/// retransmit goes out, so the real answer always loses. Keep this equal to
/// the phone forwarder's `MOBILE_DNS_NEGATIVE_ANSWER_HOLD`.
const WIREGUARD_DNS_NEGATIVE_ANSWER_HOLD: Duration = Duration::from_secs(2);
/// A server with a query unanswered for this long is silent: off, asleep or
/// unreachable. A silent server's lookup no longer keeps a negative answer
/// waiting, so switching a server off costs the hold once and then nothing.
/// Keep this equal to the phone forwarder's `MOBILE_DNS_BOX_SILENT_AFTER`.
const WIREGUARD_DNS_SERVER_SILENT_AFTER: Duration = Duration::from_secs(3);
pub const SECURE_DNS_MAX_MESSAGE_BYTES: usize = 4_096;

#[derive(Clone)]
pub struct SecureDnsResolver {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    counters: Arc<SecureDnsAtomicCounters>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecureDnsCounters {
    pub queries: u64,
    pub successes: u64,
    pub failures: u64,
}

#[derive(Default)]
struct SecureDnsAtomicCounters {
    queries: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
}

#[derive(Clone)]
pub struct WireGuardDnsResolver {
    servers: Vec<SocketAddr>,
    silence: ServerSilence,
}

/// Per server, when its oldest unanswered query was sent; `None` once any
/// datagram has come back from it.
#[derive(Clone)]
struct ServerSilence(Arc<Mutex<Vec<Option<tokio::time::Instant>>>>);

impl ServerSilence {
    fn sent(&self, server: usize, now: tokio::time::Instant) {
        if let Ok(mut since) = self.0.lock() {
            since[server].get_or_insert(now);
        }
    }

    fn heard(&self, server: usize) {
        if let Ok(mut since) = self.0.lock() {
            since[server] = None;
        }
    }

    /// When every one of `servers` will be silent; `None` while one of them
    /// has nothing unanswered.
    fn all_silent_at(&self, servers: &[usize]) -> Option<tokio::time::Instant> {
        let since = self.0.lock().ok()?;
        let mut latest = tokio::time::Instant::now();
        for server in servers {
            latest = latest.max(since[*server]? + WIREGUARD_DNS_SERVER_SILENT_AFTER);
        }
        Some(latest)
    }
}

#[allow(
    clippy::double_must_use,
    reason = "async_trait adds must_use to generated Future-returning methods"
)]
#[async_trait::async_trait]
pub trait SecureDnsLookup: Send + Sync {
    async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, SecureDnsError>;
}

impl SecureDnsResolver {
    pub fn new() -> Result<Self, SecureDnsError> {
        let config = ExitDnsConfig::default()
            .resolver_config(None)
            .expect("built-in DoH settings are valid");
        Self::from_resolver_config(&config)
    }

    pub fn from_resolver_config(config: &ExitDnsResolverConfig) -> Result<Self, SecureDnsError> {
        let ExitDnsResolverConfig::Doh { url, bootstrap_ips } = config else {
            return Err(SecureDnsError::InvalidDohConfig(
                "encrypted DNS requires a DoH resolver plan".to_string(),
            ));
        };
        Self::with_endpoint(url, bootstrap_ips)
    }

    fn with_endpoint(endpoint: &str, bootstrap_ips: &[IpAddr]) -> Result<Self, SecureDnsError> {
        let endpoint = validate_doh_resolver(endpoint, bootstrap_ips)?;
        let port = endpoint
            .port_or_known_default()
            .expect("validated HTTPS URL has a port");
        let bootstrap = bootstrap_ips
            .iter()
            .copied()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        Self::with_endpoint_and_bootstrap(endpoint, &bootstrap)
    }

    fn with_endpoint_and_bootstrap(
        endpoint: reqwest::Url,
        bootstrap: &[SocketAddr],
    ) -> Result<Self, SecureDnsError> {
        let host = endpoint.host_str().expect("validated DoH URL has a host");
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(DOH_TIMEOUT)
            .timeout(DOH_TIMEOUT)
            .http2_adaptive_window(true)
            .resolve_to_addrs(host, bootstrap)
            .build()
            .map_err(SecureDnsError::ClientBuild)?;
        Ok(Self {
            client,
            endpoint,
            counters: Arc::new(SecureDnsAtomicCounters::default()),
        })
    }

    #[cfg(test)]
    fn with_bootstrap(bootstrap: &[SocketAddr]) -> Result<Self, SecureDnsError> {
        let ips = bootstrap
            .iter()
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        let endpoint = validate_doh_resolver(CLOUDFLARE_DOH_URL, &ips)?;
        Self::with_endpoint_and_bootstrap(endpoint, bootstrap)
    }

    async fn resolve_query(&self, query: &[u8]) -> Result<Vec<u8>, SecureDnsError> {
        self.counters.queries.fetch_add(1, Ordering::Relaxed);
        let result = self.resolve_query_inner(query).await;
        if result.is_ok() {
            self.counters.successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn resolve_query_inner(&self, query: &[u8]) -> Result<Vec<u8>, SecureDnsError> {
        let request = validated_query(query)?;
        match self.resolve_query_once(query, &request).await {
            Err(SecureDnsError::Request(_)) => self.resolve_query_once(query, &request).await,
            result => result,
        }
    }

    async fn resolve_query_once(
        &self,
        query: &[u8],
        request: &Message,
    ) -> Result<Vec<u8>, SecureDnsError> {
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, DOH_CONTENT_TYPE)
            .header(CONTENT_TYPE, DOH_CONTENT_TYPE)
            .body(query.to_vec())
            .send()
            .await
            .map_err(SecureDnsError::Request)?;

        if !response.status().is_success() {
            return Err(SecureDnsError::HttpStatus(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some(DOH_CONTENT_TYPE) {
            return Err(SecureDnsError::ContentType);
        }
        if response
            .content_length()
            .is_some_and(|length| length > SECURE_DNS_MAX_MESSAGE_BYTES as u64)
        {
            return Err(SecureDnsError::ResponseTooLarge);
        }

        let mut packet = Vec::with_capacity(512);
        while let Some(chunk) = response.chunk().await.map_err(SecureDnsError::Request)? {
            if packet.len().saturating_add(chunk.len()) > SECURE_DNS_MAX_MESSAGE_BYTES {
                return Err(SecureDnsError::ResponseTooLarge);
            }
            packet.extend_from_slice(&chunk);
        }
        validated_response(request, &packet)?;
        Ok(packet)
    }

    #[cfg(test)]
    fn with_test_endpoint(client: reqwest::Client, endpoint: &'static str) -> Self {
        Self {
            client,
            endpoint: reqwest::Url::parse(endpoint).expect("test DoH URL"),
            counters: Arc::new(SecureDnsAtomicCounters::default()),
        }
    }

    pub fn counters(&self) -> SecureDnsCounters {
        SecureDnsCounters {
            queries: self.counters.queries.load(Ordering::Relaxed),
            successes: self.counters.successes.load(Ordering::Relaxed),
            failures: self.counters.failures.load(Ordering::Relaxed),
        }
    }
}

pub fn validate_doh_resolver(
    endpoint: &str,
    bootstrap_ips: &[IpAddr],
) -> Result<reqwest::Url, SecureDnsError> {
    let endpoint = reqwest::Url::parse(endpoint)
        .map_err(|error| SecureDnsError::InvalidDohConfig(error.to_string()))?;
    if endpoint.scheme() != "https" {
        return Err(SecureDnsError::InvalidDohConfig(
            "DoH URL must use https".to_string(),
        ));
    }
    if endpoint.username() != "" || endpoint.password().is_some() {
        return Err(SecureDnsError::InvalidDohConfig(
            "DoH URL must not contain credentials".to_string(),
        ));
    }
    if endpoint.fragment().is_some() {
        return Err(SecureDnsError::InvalidDohConfig(
            "DoH URL must not contain a fragment".to_string(),
        ));
    }
    if endpoint.host_str().is_none() {
        return Err(SecureDnsError::InvalidDohConfig(
            "DoH URL has no host".to_string(),
        ));
    }
    if endpoint.port_or_known_default().is_none() {
        return Err(SecureDnsError::InvalidDohConfig(
            "DoH URL has no usable HTTPS port".to_string(),
        ));
    }
    if bootstrap_ips.is_empty() {
        return Err(SecureDnsError::InvalidDohConfig(
            "DoH requires at least one bootstrap IP".to_string(),
        ));
    }
    Ok(endpoint)
}

impl WireGuardDnsResolver {
    pub fn new(servers: &[IpAddr]) -> Result<Self, SecureDnsError> {
        Self::with_servers(
            servers
                .iter()
                .copied()
                .map(|server| SocketAddr::new(server, 53))
                .collect(),
        )
    }

    fn with_servers(servers: Vec<SocketAddr>) -> Result<Self, SecureDnsError> {
        if servers.is_empty() {
            return Err(SecureDnsError::NoWireGuardDnsServers);
        }
        let silence = ServerSilence(Arc::new(Mutex::new(vec![None; servers.len()])));
        Ok(Self { servers, silence })
    }

    /// Asks every server at once and returns the first real answer, so a
    /// silent server costs nothing while another one answers. A fast
    /// negative answer is held while another server may still answer for
    /// real, and is returned when none does.
    async fn resolve_query(&self, query: &[u8]) -> Result<Vec<u8>, SecureDnsError> {
        let request = Arc::new(validated_query(query)?);
        let query: Arc<[u8]> = Arc::from(query);
        let now = tokio::time::Instant::now();
        let mut lookups = tokio::task::JoinSet::new();
        for (index, server) in self.servers.iter().copied().enumerate() {
            self.silence.sent(index, now);
            let (query, request) = (Arc::clone(&query), Arc::clone(&request));
            let silence = self.silence.clone();
            lookups.spawn(async move {
                let heard = || silence.heard(index);
                (
                    index,
                    Self::resolve_via_server(server, &query, &request, heard).await,
                )
            });
        }
        let result = self.race(&mut lookups).await;
        // The losers run out their own deadlines, so a late answer still
        // clears its server's silence. Cancelling them would mark a server
        // that is merely slower than the winner as silent.
        lookups.detach_all();
        result
    }

    async fn race(
        &self,
        lookups: &mut tokio::task::JoinSet<(usize, Result<Vec<u8>, SecureDnsError>)>,
    ) -> Result<Vec<u8>, SecureDnsError> {
        let mut outstanding = (0..self.servers.len()).collect::<Vec<_>>();
        let mut held: Option<(Vec<u8>, tokio::time::Instant)> = None;
        let mut last_error = None;
        loop {
            let next = match &held {
                None => lookups.join_next().await,
                Some((_, hold_until)) => {
                    let wait_until = self
                        .silence
                        .all_silent_at(&outstanding)
                        .map_or(*hold_until, |silent_at| silent_at.min(*hold_until));
                    if tokio::time::Instant::now() >= wait_until {
                        break;
                    }
                    match tokio::time::timeout_at(wait_until, lookups.join_next()).await {
                        Ok(next) => next,
                        // A server heard from meanwhile is no longer silent.
                        Err(_) => continue,
                    }
                }
            };
            let Some(joined) = next else { break };
            let (index, result) = match joined {
                Ok(joined) => joined,
                Err(error) => {
                    last_error = Some(SecureDnsError::WireGuardDnsIo(std::io::Error::other(error)));
                    continue;
                }
            };
            outstanding.retain(|server| *server != index);
            match result {
                Ok(response) if dns_answer_has_records(&response) => return Ok(response),
                Ok(response) => {
                    held.get_or_insert((
                        response,
                        tokio::time::Instant::now() + WIREGUARD_DNS_NEGATIVE_ANSWER_HOLD,
                    ));
                }
                Err(error) => last_error = Some(error),
            }
        }
        match held {
            Some((response, _)) => Ok(response),
            None => Err(last_error.unwrap_or(SecureDnsError::NoWireGuardDnsServers)),
        }
    }

    async fn resolve_via_server(
        server: SocketAddr,
        query: &[u8],
        request: &Message,
        heard: impl Fn(),
    ) -> Result<Vec<u8>, SecureDnsError> {
        let bind = match server {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let response = tokio::time::timeout(WIREGUARD_DNS_TIMEOUT, async {
            let socket = tokio::net::UdpSocket::bind(bind).await?;
            socket.connect(server).await?;
            socket.send(query).await?;
            let mut packet = vec![0_u8; SECURE_DNS_MAX_MESSAGE_BYTES];
            // The first UDP packet can be lost while the exit session opens.
            // Retry on this socket within the existing per-server deadline so
            // callers need not repeat their first lookup after startup.
            let mut retry = tokio::time::interval_at(
                tokio::time::Instant::now() + WIREGUARD_DNS_RETRY_INTERVAL,
                WIREGUARD_DNS_RETRY_INTERVAL,
            );
            retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    received = socket.recv(&mut packet) => {
                        packet.truncate(received?);
                        heard();
                        return Ok::<_, std::io::Error>(packet);
                    }
                    _ = retry.tick() => { socket.send(query).await?; }
                }
            }
        })
        .await
        .map_err(|_| SecureDnsError::WireGuardDnsTimeout(server))?
        .map_err(SecureDnsError::WireGuardDnsIo)?;
        let parsed = validated_response(request, &response)?;
        if !parsed.metadata.truncation {
            return Ok(response);
        }

        tokio::time::timeout(WIREGUARD_DNS_TIMEOUT, async {
            let mut stream = tokio::net::TcpStream::connect(server).await?;
            let query_length = u16::try_from(query.len()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "DNS query too large")
            })?;
            stream.write_all(&query_length.to_be_bytes()).await?;
            stream.write_all(query).await?;
            let response_length = usize::from(stream.read_u16().await?);
            if !(12..=SECURE_DNS_MAX_MESSAGE_BYTES).contains(&response_length) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "DNS response length is invalid",
                ));
            }
            let mut response = vec![0_u8; response_length];
            stream.read_exact(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        })
        .await
        .map_err(|_| SecureDnsError::WireGuardDnsTimeout(server))?
        .map_err(SecureDnsError::WireGuardDnsIo)
        .and_then(|response| {
            validated_response(request, &response)?;
            Ok(response)
        })
    }
}

#[async_trait::async_trait]
impl SecureDnsLookup for SecureDnsResolver {
    async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, SecureDnsError> {
        self.resolve_query(query).await
    }
}

#[async_trait::async_trait]
impl SecureDnsLookup for WireGuardDnsResolver {
    async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, SecureDnsError> {
        self.resolve_query(query).await
    }
}

#[derive(Debug, Error)]
pub enum SecureDnsError {
    #[error("DNS is unavailable until the selected exit is ready")]
    ExitNotReady,
    #[error("invalid encrypted DNS configuration: {0}")]
    InvalidDohConfig(String),
    #[error("failed to build secure DNS client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("invalid DNS query")]
    InvalidQuery,
    #[error("secure DNS request failed: {0}")]
    Request(reqwest::Error),
    #[error("secure DNS returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("secure DNS returned an invalid content type")]
    ContentType,
    #[error("secure DNS response exceeded the message limit")]
    ResponseTooLarge,
    #[error("secure DNS returned an invalid or unrelated response")]
    InvalidResponse,
    #[error("WireGuard exit did not configure a usable DNS server")]
    NoWireGuardDnsServers,
    #[error("WireGuard exit DNS request to {0} timed out")]
    WireGuardDnsTimeout(SocketAddr),
    #[error("WireGuard exit DNS request failed: {0}")]
    WireGuardDnsIo(std::io::Error),
}

fn validated_query(packet: &[u8]) -> Result<Message, SecureDnsError> {
    if !(12..=SECURE_DNS_MAX_MESSAGE_BYTES).contains(&packet.len()) {
        return Err(SecureDnsError::InvalidQuery);
    }
    let message = Message::from_vec(packet).map_err(|_| SecureDnsError::InvalidQuery)?;
    if message.metadata.message_type != MessageType::Query || message.queries.is_empty() {
        return Err(SecureDnsError::InvalidQuery);
    }
    Ok(message)
}

fn validated_response(request: &Message, packet: &[u8]) -> Result<Message, SecureDnsError> {
    let response = Message::from_vec(packet).map_err(|_| SecureDnsError::InvalidResponse)?;
    if response.metadata.message_type != MessageType::Response
        || response.id != request.id
        || response.metadata.op_code != request.metadata.op_code
        || response.queries != request.queries
    {
        return Err(SecureDnsError::InvalidResponse);
    }
    Ok(response)
}

/// Whether an answer is worth returning over a possible real one from
/// another server: NOERROR with at least one answer record. NXDOMAIN,
/// SERVFAIL, REFUSED and an empty NOERROR are negative. A truncated UDP
/// answer has already been asked again over TCP by `resolve_via_server`, so
/// an empty+TC reply never wins: it is judged by what TCP brings back.
fn dns_answer_has_records(message: &[u8]) -> bool {
    if message.len() < 12 {
        return false;
    }
    let rcode = message[3] & 0x0f;
    let answers = u16::from_be_bytes([message[6], message[7]]);
    rcode == 0 && answers > 0
}

pub fn build_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    build_error_response(query, ResponseCode::ServFail)
}

pub fn build_refused_response(query: &[u8]) -> Option<Vec<u8>> {
    build_error_response(query, ResponseCode::Refused)
}

fn build_error_response(query: &[u8], response_code: ResponseCode) -> Option<Vec<u8>> {
    let request = validated_query(query).ok()?;
    let mut response = Message::new(request.id, MessageType::Response, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = response_code;
    for query in request.queries {
        response.add_query(query);
    }
    let mut packet = Vec::new();
    response.emit(&mut BinEncoder::new(&mut packet)).ok()?;
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 512];
            let length = stream.read(&mut chunk).await.expect("fixture request");
            assert!(length > 0, "request ended before HTTP headers");
            request.extend_from_slice(&chunk[..length]);
            if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|length| length.trim().parse::<usize>().ok())
            .expect("content length");
        while request.len() - header_end < content_length {
            let mut chunk = [0_u8; 512];
            let length = stream.read(&mut chunk).await.expect("fixture body");
            assert!(length > 0, "request ended before DNS body");
            request.extend_from_slice(&chunk[..length]);
        }
        request
    }

    fn dns_query(id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii("secure.example.").expect("query name"),
            RecordType::A,
        ));
        encode(message)
    }

    fn dns_response(query: &[u8], id: u16) -> Vec<u8> {
        let request = Message::from_vec(query).expect("query");
        let mut message = Message::new(id, MessageType::Response, request.metadata.op_code);
        for query in request.queries {
            message.add_query(query);
        }
        encode(message)
    }

    fn encode(message: Message) -> Vec<u8> {
        let mut packet = Vec::new();
        message
            .emit(&mut BinEncoder::new(&mut packet))
            .expect("encode DNS message");
        packet
    }

    #[test]
    fn response_must_match_transaction_and_questions() {
        let query = dns_query(41);
        let request = validated_query(&query).expect("valid query");
        assert!(validated_response(&request, &dns_response(&query, 41)).is_ok());
        assert!(matches!(
            validated_response(&request, &dns_response(&query, 42)),
            Err(SecureDnsError::InvalidResponse)
        ));

        let unrelated = dns_query(41);
        let mut unrelated = Message::from_vec(&unrelated).expect("query");
        unrelated.queries.clear();
        unrelated.add_query(Query::query(
            Name::from_ascii("spoofed.example.").expect("query name"),
            RecordType::A,
        ));
        unrelated.metadata.message_type = MessageType::Response;
        assert!(matches!(
            validated_response(&request, &encode(unrelated)),
            Err(SecureDnsError::InvalidResponse)
        ));
    }

    #[test]
    fn malformed_queries_fail_closed_with_correlated_servfail() {
        assert!(build_servfail_response(&[0; 11]).is_none());
        let query = dns_query(77);
        let response = build_servfail_response(&query).expect("SERVFAIL");
        let response = Message::from_vec(&response).expect("response");
        assert_eq!(response.id, 77);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);
    }

    #[tokio::test]
    async fn production_client_rejects_plain_http() {
        let resolver = SecureDnsResolver::new().expect("resolver");
        let resolver =
            SecureDnsResolver::with_test_endpoint(resolver.client, "http://127.0.0.1:9/dns-query");
        assert!(matches!(
            SecureDnsLookup::resolve(&resolver, &dns_query(9)).await,
            Err(SecureDnsError::Request(_))
        ));
        assert_eq!(
            resolver.counters(),
            SecureDnsCounters {
                queries: 1,
                successes: 0,
                failures: 1,
            }
        );
    }

    #[test]
    fn custom_doh_requires_https_and_bootstrap_without_credentials() {
        let bootstrap = ["192.0.2.53".parse::<IpAddr>().unwrap()];
        assert!(matches!(
            SecureDnsResolver::with_endpoint("http://resolver.example/dns-query", &bootstrap),
            Err(SecureDnsError::InvalidDohConfig(_))
        ));
        assert!(matches!(
            SecureDnsResolver::with_endpoint("https://user@resolver.example/dns-query", &bootstrap),
            Err(SecureDnsError::InvalidDohConfig(_))
        ));
        assert!(matches!(
            SecureDnsResolver::with_endpoint("https://resolver.example/dns-query", &[]),
            Err(SecureDnsError::InvalidDohConfig(_))
        ));
        SecureDnsResolver::with_endpoint("https://resolver.example/dns-query", &bootstrap)
            .expect("strict custom DoH client");
    }

    #[tokio::test]
    async fn doh_uses_post_dns_message_and_validates_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let query = dns_query(912);
        let expected_query = query.clone();
        let response_packet = dns_response(&query, 912);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("fixture connection");
            let request = read_http_request(&mut stream).await;
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("HTTP headers")
                + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            assert!(headers.starts_with("post /dns-query http/1.1\r\n"));
            assert!(headers.contains("content-type: application/dns-message\r\n"));
            assert!(headers.contains("accept: application/dns-message\r\n"));
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|length| length.trim().parse::<usize>().ok())
                .expect("content length");
            assert_eq!(
                &request[header_end..header_end + content_length],
                expected_query.as_slice()
            );
            let response_headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_packet.len()
            );
            stream
                .write_all(response_headers.as_bytes())
                .await
                .expect("fixture response headers");
            stream
                .write_all(&response_packet)
                .await
                .expect("fixture response body");
        });
        let endpoint = Box::leak(format!("http://{address}/dns-query").into_boxed_str());
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("fixture client");
        let resolver = SecureDnsResolver::with_test_endpoint(client, endpoint);

        let response = resolver.resolve_query(&query).await.expect("DoH response");
        assert_eq!(Message::from_vec(&response).expect("DNS response").id, 912);
        assert_eq!(
            resolver.counters(),
            SecureDnsCounters {
                queries: 1,
                successes: 1,
                failures: 0,
            }
        );
        server.await.expect("fixture task");
    }

    #[tokio::test]
    async fn doh_retries_one_transient_request_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let query = dns_query(914);
        let expected_query = query.clone();
        let response_packet = dns_response(&query, 914);
        let server = tokio::spawn(async move {
            let (mut failed, _) = listener.accept().await.expect("first connection");
            let first_request = read_http_request(&mut failed).await;
            assert!(first_request.ends_with(&expected_query));
            drop(failed);

            let (mut recovered, _) = listener.accept().await.expect("retry connection");
            let second_request = read_http_request(&mut recovered).await;
            assert!(second_request.ends_with(&expected_query));
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_packet.len()
            );
            recovered
                .write_all(headers.as_bytes())
                .await
                .expect("retry response headers");
            recovered
                .write_all(&response_packet)
                .await
                .expect("retry response body");
        });
        let endpoint = Box::leak(format!("http://{address}/dns-query").into_boxed_str());
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("fixture client");
        let resolver = SecureDnsResolver::with_test_endpoint(client, endpoint);

        let response = resolver
            .resolve_query(&query)
            .await
            .expect("transient request recovered");
        assert_eq!(Message::from_vec(&response).expect("DNS response").id, 914);
        server.await.expect("fixture task");
    }

    #[tokio::test]
    async fn through_exit_dns_recovers_a_lost_first_query_without_application_retry() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("DNS fixture");
        let address = socket.local_addr().expect("DNS address");
        let query = dns_query(921);
        let expected = dns_response(&query, 921);
        let response = expected.clone();
        let server = tokio::spawn(async move {
            let mut packet = [0_u8; 512];
            let (first_length, first_peer) =
                socket.recv_from(&mut packet).await.expect("first query");
            let first = packet[..first_length].to_vec();
            // Simulate the first datagram disappearing while the exit path opens.
            let (length, peer) = socket
                .recv_from(&mut packet)
                .await
                .expect("retransmitted query");
            assert_eq!(peer, first_peer, "retry uses the same DNS socket");
            assert_eq!(&packet[..length], first.as_slice());
            socket.send_to(&response, peer).await.expect("DNS answer");
        });
        let resolver = WireGuardDnsResolver::with_servers(vec![address]).expect("exit DNS");
        let result =
            tokio::time::timeout(Duration::from_secs(2), resolver.resolve_query(&query)).await;
        server.abort();
        assert_eq!(
            result
                .expect("first lookup should recover within two seconds")
                .expect("DNS response"),
            expected
        );
    }

    /// How a test DNS server answers every query.
    #[derive(Clone, Copy)]
    struct Reply {
        delay: Duration,
        code: ResponseCode,
        records: bool,
        /// Ignore the first query, as if it were lost on the way.
        drop_first: bool,
        /// Answer with an unrelated transaction id.
        wrong_id: bool,
    }

    const REAL: Reply = Reply {
        delay: Duration::ZERO,
        code: ResponseCode::NoError,
        records: true,
        drop_first: false,
        wrong_id: false,
    };

    fn negative(code: ResponseCode) -> Reply {
        Reply {
            code,
            records: false,
            ..REAL
        }
    }

    const NEGATIVES: [ResponseCode; 4] = [
        ResponseCode::NXDomain,
        ResponseCode::NoError,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ];

    async fn dns_fixture(reply: Reply) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("DNS fixture");
        let address = socket.local_addr().expect("DNS fixture address");
        let task = tokio::spawn(async move {
            let mut packet = [0_u8; SECURE_DNS_MAX_MESSAGE_BYTES];
            let mut dropped = !reply.drop_first;
            loop {
                let (length, peer) = socket.recv_from(&mut packet).await.expect("DNS query");
                if !std::mem::replace(&mut dropped, true) {
                    continue;
                }
                let request = Message::from_vec(&packet[..length]).expect("query");
                let id = if reply.wrong_id {
                    request.id.wrapping_add(1)
                } else {
                    request.id
                };
                let mut response =
                    Message::new(id, MessageType::Response, request.metadata.op_code);
                response.metadata.response_code = reply.code;
                for query in request.queries {
                    if reply.records {
                        response.add_answer(hickory_proto::rr::Record::from_rdata(
                            query.name.clone(),
                            30,
                            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                                Ipv4Addr::new(192, 0, 2, 1),
                            )),
                        ));
                    }
                    response.add_query(query);
                }
                tokio::time::sleep(reply.delay).await;
                socket
                    .send_to(&encode(response), peer)
                    .await
                    .expect("DNS answer");
            }
        });
        (address, task)
    }

    async fn silent_server() -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("silent DNS fixture")
    }

    fn has_answer_records(packet: &[u8]) -> bool {
        !Message::from_vec(packet)
            .expect("DNS answer")
            .answers
            .is_empty()
    }

    fn response_code(packet: &[u8]) -> ResponseCode {
        Message::from_vec(packet)
            .expect("DNS answer")
            .metadata
            .response_code
    }

    fn unanswered_since(
        resolver: &WireGuardDnsResolver,
        server: usize,
    ) -> Option<tokio::time::Instant> {
        resolver.silence.0.lock().expect("silence")[server]
    }

    #[tokio::test]
    async fn through_exit_dns_answers_from_a_healthy_server_while_another_is_silent() {
        const BOUND: Duration = Duration::from_millis(500);
        let silent = silent_server().await;
        let (healthy, fixture) = dns_fixture(REAL).await;
        // The silent server is listed first, so asking in order waits on it.
        let servers = vec![silent.local_addr().expect("silent address"), healthy];
        let query = dns_query(922);

        // Positive control: the previous one-at-a-time loop cannot meet the bound.
        let request = validated_query(&query).expect("query");
        let in_order = async {
            for server in &servers {
                if let Ok(response) =
                    WireGuardDnsResolver::resolve_via_server(*server, &query, &request, || ()).await
                {
                    return Ok(response);
                }
            }
            Err(())
        };
        assert!(
            tokio::time::timeout(BOUND, in_order).await.is_err(),
            "in-order lookup should still be waiting on the silent server"
        );

        let resolver = WireGuardDnsResolver::with_servers(servers).expect("exit DNS");
        let response = tokio::time::timeout(BOUND, resolver.resolve_query(&query))
            .await
            .expect("a silent server must not delay the healthy answer")
            .expect("DNS response");
        assert_eq!(Message::from_vec(&response).expect("DNS answer").id, 922);
        fixture.abort();
    }

    #[tokio::test]
    async fn through_exit_dns_holds_a_fast_negative_answer_for_a_slower_real_one() {
        for code in NEGATIVES {
            let (broken, broken_fixture) = dns_fixture(negative(code)).await;
            let (healthy, healthy_fixture) = dns_fixture(Reply {
                delay: Duration::from_millis(300),
                ..REAL
            })
            .await;
            let resolver =
                WireGuardDnsResolver::with_servers(vec![broken, healthy]).expect("exit DNS");
            let response = resolver
                .resolve_query(&dns_query(923))
                .await
                .expect("DNS response");
            assert!(
                has_answer_records(&response),
                "a fast {code:?} must not beat the real answer"
            );
            broken_fixture.abort();
            healthy_fixture.abort();
        }
    }

    #[tokio::test]
    async fn through_exit_dns_real_answer_to_a_retransmit_beats_a_held_negative() {
        // The retransmit goes out after a second and its answer needs a
        // round trip on top, as it would across the mesh.
        let (lossy, lossy_fixture) = dns_fixture(Reply {
            delay: Duration::from_millis(300),
            drop_first: true,
            ..REAL
        })
        .await;
        let (broken, broken_fixture) = dns_fixture(negative(ResponseCode::ServFail)).await;
        let resolver = WireGuardDnsResolver::with_servers(vec![lossy, broken]).expect("exit DNS");
        let response = resolver
            .resolve_query(&dns_query(926))
            .await
            .expect("DNS response");
        assert!(
            has_answer_records(&response),
            "the hold must outlast the retransmit of a lost first query"
        );
        lossy_fixture.abort();
        broken_fixture.abort();
    }

    #[tokio::test]
    async fn through_exit_dns_returns_a_held_negative_answer_after_the_hold() {
        let silent = silent_server().await;
        let (broken, fixture) = dns_fixture(negative(ResponseCode::ServFail)).await;
        let resolver = WireGuardDnsResolver::with_servers(vec![
            silent.local_addr().expect("silent address"),
            broken,
        ])
        .expect("exit DNS");
        let started = tokio::time::Instant::now();
        let response = resolver
            .resolve_query(&dns_query(924))
            .await
            .expect("held SERVFAIL");
        let elapsed = started.elapsed();
        assert_eq!(response_code(&response), ResponseCode::ServFail);
        assert!(
            elapsed >= WIREGUARD_DNS_NEGATIVE_ANSWER_HOLD,
            "SERVFAIL returned before the hold: {elapsed:?}"
        );
        assert!(
            elapsed < WIREGUARD_DNS_TIMEOUT,
            "the hold must not wait for the silent server to time out: {elapsed:?}"
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn through_exit_dns_returns_a_lone_negative_answer_without_holding() {
        for code in NEGATIVES {
            let (broken, fixture) = dns_fixture(negative(code)).await;
            let resolver = WireGuardDnsResolver::with_servers(vec![broken]).expect("exit DNS");
            let response = tokio::time::timeout(
                Duration::from_millis(500),
                resolver.resolve_query(&dns_query(925)),
            )
            .await
            .expect("nothing else can answer, so there is nothing to wait for")
            .expect("DNS response");
            assert_eq!(response_code(&response), code);
            fixture.abort();
        }
    }

    #[tokio::test]
    async fn through_exit_dns_stops_holding_once_the_other_server_goes_silent() {
        let silent = silent_server().await;
        let (broken, fixture) = dns_fixture(negative(ResponseCode::NXDomain)).await;
        let resolver = WireGuardDnsResolver::with_servers(vec![
            silent.local_addr().expect("silent address"),
            broken,
        ])
        .expect("exit DNS");
        // The silent server has had a query unanswered for most of the
        // silence window, so it goes silent well inside the hold.
        resolver.silence.sent(
            0,
            tokio::time::Instant::now() - WIREGUARD_DNS_SERVER_SILENT_AFTER
                + Duration::from_millis(300),
        );
        let started = tokio::time::Instant::now();
        let response = resolver
            .resolve_query(&dns_query(927))
            .await
            .expect("NXDOMAIN");
        let elapsed = started.elapsed();
        assert_eq!(response_code(&response), ResponseCode::NXDomain);
        assert!(
            elapsed < WIREGUARD_DNS_NEGATIVE_ANSWER_HOLD - Duration::from_millis(500),
            "a silent server must stop costing the hold: {elapsed:?}"
        );

        // Once silent, it costs nothing at all.
        let response = tokio::time::timeout(
            Duration::from_millis(500),
            resolver.resolve_query(&dns_query(928)),
        )
        .await
        .expect("a server already silent must not hold a negative answer")
        .expect("NXDOMAIN");
        assert_eq!(response_code(&response), ResponseCode::NXDomain);
        fixture.abort();
    }

    #[tokio::test]
    async fn through_exit_dns_any_datagram_clears_a_servers_silence() {
        let (unrelated, unrelated_fixture) = dns_fixture(Reply {
            wrong_id: true,
            ..REAL
        })
        .await;
        let (healthy, healthy_fixture) = dns_fixture(Reply {
            delay: Duration::from_millis(200),
            ..REAL
        })
        .await;
        let resolver =
            WireGuardDnsResolver::with_servers(vec![unrelated, healthy]).expect("exit DNS");
        resolver.silence.sent(
            0,
            tokio::time::Instant::now() - 2 * WIREGUARD_DNS_SERVER_SILENT_AFTER,
        );
        let response = resolver
            .resolve_query(&dns_query(929))
            .await
            .expect("DNS response");
        assert!(has_answer_records(&response));
        assert_eq!(
            unanswered_since(&resolver, 0),
            None,
            "a reply that fails validation still proves the server is up"
        );
        unrelated_fixture.abort();
        healthy_fixture.abort();
    }

    #[tokio::test]
    async fn through_exit_dns_a_server_slower_than_the_winner_is_not_silent() {
        let (fast, fast_fixture) = dns_fixture(REAL).await;
        let (slow, slow_fixture) = dns_fixture(Reply {
            delay: Duration::from_millis(200),
            ..REAL
        })
        .await;
        let resolver = WireGuardDnsResolver::with_servers(vec![fast, slow]).expect("exit DNS");
        resolver
            .resolve_query(&dns_query(930))
            .await
            .expect("DNS response");
        assert!(
            unanswered_since(&resolver, 1).is_some(),
            "slow answer still pending"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            unanswered_since(&resolver, 1),
            None,
            "the losing lookup must still hear the slow server's answer"
        );
        fast_fixture.abort();
        slow_fixture.abort();
    }

    #[tokio::test]
    async fn wireguard_dns_resolver_forwards_to_profile_server() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("fixture DNS server");
        let address = server.local_addr().expect("fixture DNS address");
        let query = dns_query(913);
        let expected_query = query.clone();
        let response = dns_response(&query, 913);
        let fixture = tokio::spawn(async move {
            let mut packet = [0_u8; SECURE_DNS_MAX_MESSAGE_BYTES];
            let (length, peer) = server.recv_from(&mut packet).await.expect("DNS query");
            assert_eq!(&packet[..length], expected_query.as_slice());
            server.send_to(&response, peer).await.expect("DNS response");
        });
        let resolver =
            WireGuardDnsResolver::with_servers(vec![address]).expect("WireGuard DNS resolver");

        let response = resolver
            .resolve(&query)
            .await
            .expect("profile DNS response");
        assert_eq!(Message::from_vec(&response).expect("DNS response").id, 913);
        fixture.await.expect("fixture task");
    }

    #[tokio::test]
    async fn redirected_bootstrap_cannot_downgrade_doh_to_plaintext() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("spoof listener");
        let address = listener.local_addr().expect("spoof address");
        let attacker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("spoof connection");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .ok();
        });
        let resolver = SecureDnsResolver::with_bootstrap(&[address]).expect("resolver");

        assert!(matches!(
            resolver.resolve_query(&dns_query(444)).await,
            Err(SecureDnsError::Request(_))
        ));
        attacker.await.expect("spoof task");
    }

    #[tokio::test]
    async fn forged_certificate_cannot_spoof_doh_response() {
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use tokio_rustls::TlsAcceptor;
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![DOH_HOST.to_string()]).expect("attacker certificate");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )
            .expect("attacker TLS config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("spoof TLS listener");
        let address = listener.local_addr().expect("spoof TLS address");
        let attacker = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("spoof TLS connection");
            assert!(
                acceptor.accept(stream).await.is_err(),
                "client must reject the untrusted certificate"
            );
        });
        let resolver = SecureDnsResolver::with_bootstrap(&[address]).expect("resolver");

        assert!(matches!(
            resolver.resolve_query(&dns_query(445)).await,
            Err(SecureDnsError::Request(_))
        ));
        attacker.await.expect("spoof TLS task");
    }

    #[tokio::test]
    #[ignore = "requires Internet access to the production DoH endpoint"]
    async fn live_doh_resolves_over_authenticated_tls() {
        let resolver = SecureDnsResolver::new().expect("resolver");
        let mut query = Message::new(700, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("example.com.").expect("query name"),
            RecordType::A,
        ));
        let response = resolver
            .resolve_query(&encode(query))
            .await
            .expect("authenticated live DoH response");
        let response = Message::from_vec(&response).expect("DNS response");
        assert_eq!(response.id, 700);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert!(!response.answers.is_empty());
    }
}
