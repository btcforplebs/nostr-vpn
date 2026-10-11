struct MobileDnsQuery<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &'a [u8],
}

enum MobileDnsPacketAction {
    Respond(Vec<u8>),
    ForwardViaExit,
}

/// One translated DNS flow, as seen from the answer coming back. The answer
/// cannot say which address the client originally asked, so UDP flows also key
/// on the DNS message ID: two sockets connected to different resolvers may
/// share a local port, and without it their answers would cross-wire. TCP
/// carries no per-packet ID (0 here); a second TCP stream on the same port is
/// refused instead, because the nameserver would see it as the same
/// connection.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MobileWireGuardDnsFlow {
    server: Ipv4Addr,
    protocol: u8,
    client_port: u16,
    query_id: u16,
}

/// Where the client sent the query, so the answer comes back from there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MobileDnsFlowOrigin {
    V4(Ipv4Addr),
    /// An IPv6 resolver, reached through the IPv4 path to the nameserver.
    V6 {
        resolver: Ipv6Addr,
        client: Ipv6Addr,
    },
}

impl MobileDnsFlowOrigin {
    /// Sent straight to a public resolver rather than to the stub.
    fn is_redirect(self) -> bool {
        match self {
            Self::V4(resolver) => is_dns_sinkhole_address(IpAddr::V4(resolver)),
            Self::V6 { .. } => true,
        }
    }
}

struct MobileDnsFlowEntry {
    origin: MobileDnsFlowOrigin,
    last_seen: Instant,
    /// A FIN went by; the stream gets a short grace period, not the idle one.
    closing: bool,
}

/// Bounded: a nameserver that is off answers nothing, and any app can spray
/// UDP/53 at a listed resolver, so entries must expire on their own.
const MOBILE_DNS_FLOW_CAPACITY: usize = 1024;
/// Most one socket may hold. A resolver pipelines a handful of lookups.
const MOBILE_DNS_FLOWS_PER_PORT: usize = 32;
/// What every port may hold however full the table is: an A and an AAAA.
const MOBILE_DNS_FLOWS_PER_PORT_FLOOR: usize = 2;
/// Kept for ports still under their floor. Flows past a port's floor share
/// only the rest, so filling the table takes hundreds of sockets, not 32.
const MOBILE_DNS_NEWCOMER_RESERVE: usize = MOBILE_DNS_FLOW_CAPACITY / 2;
/// Redirected queries never take the half of the table the stub relies on.
const MOBILE_DNS_REDIRECT_CAPACITY: usize = MOBILE_DNS_FLOW_CAPACITY / 2;
/// Resolvers retry long before this; an unanswered UDP flow is dead by then.
const MOBILE_DNS_UDP_FLOW_TTL: Duration = Duration::from_secs(15);
const MOBILE_DNS_TCP_FLOW_IDLE: Duration = Duration::from_secs(60);
const MOBILE_DNS_TCP_FLOW_CLOSING: Duration = Duration::from_secs(5);
const MOBILE_DNS_FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// A refused query may sweep early, but no more often than this: a sweep is a
/// full scan, and a sprayer would otherwise buy one with every packet.
const MOBILE_DNS_FLOW_PRESSURE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Flows plus the counts admission needs, kept in step on every insert and
/// removal so admitting a flow never scans the table. Expired flows still
/// count until the next sweep, at most a second late under pressure.
struct MobileDnsFlowTable {
    entries: HashMap<MobileWireGuardDnsFlow, MobileDnsFlowEntry>,
    per_port: HashMap<u16, usize>,
    redirected: usize,
    last_sweep: Instant,
}

impl MobileDnsFlowTable {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            per_port: HashMap::new(),
            redirected: 0,
            last_sweep: now,
        }
    }

    fn expired(flow: &MobileWireGuardDnsFlow, entry: &MobileDnsFlowEntry, now: Instant) -> bool {
        let lifetime = match (flow.protocol, entry.closing) {
            (6, true) => MOBILE_DNS_TCP_FLOW_CLOSING,
            (6, false) => MOBILE_DNS_TCP_FLOW_IDLE,
            _ => MOBILE_DNS_UDP_FLOW_TTL,
        };
        now.saturating_duration_since(entry.last_seen) >= lifetime
    }

    fn count_in(
        per_port: &mut HashMap<u16, usize>,
        redirected: &mut usize,
        port: u16,
        origin: MobileDnsFlowOrigin,
    ) {
        *per_port.entry(port).or_default() += 1;
        if origin.is_redirect() {
            *redirected += 1;
        }
    }

    fn count_out(
        per_port: &mut HashMap<u16, usize>,
        redirected: &mut usize,
        port: u16,
        origin: MobileDnsFlowOrigin,
    ) {
        if let Some(count) = per_port.get_mut(&port) {
            *count -= 1;
            if *count == 0 {
                per_port.remove(&port);
            }
        }
        if origin.is_redirect() {
            *redirected -= 1;
        }
    }

    fn insert(&mut self, flow: MobileWireGuardDnsFlow, entry: MobileDnsFlowEntry) {
        Self::count_in(
            &mut self.per_port,
            &mut self.redirected,
            flow.client_port,
            entry.origin,
        );
        if let Some(old) = self.entries.insert(flow, entry) {
            Self::count_out(
                &mut self.per_port,
                &mut self.redirected,
                flow.client_port,
                old.origin,
            );
        }
    }

    fn remove(&mut self, flow: &MobileWireGuardDnsFlow) {
        if let Some(old) = self.entries.remove(flow) {
            Self::count_out(
                &mut self.per_port,
                &mut self.redirected,
                flow.client_port,
                old.origin,
            );
        }
    }

    fn sweep(&mut self, now: Instant) {
        let Self {
            entries,
            per_port,
            redirected,
            ..
        } = self;
        entries.retain(|flow, entry| {
            let keep = !Self::expired(flow, entry, now);
            if !keep {
                Self::count_out(per_port, redirected, flow.client_port, entry.origin);
            }
            keep
        });
        self.last_sweep = now;
    }

    /// Record a query. `false` when the key is held by a live flow to a
    /// different origin: refusing beats answering one client with another's
    /// resolver address.
    fn record(
        &mut self,
        flow: MobileWireGuardDnsFlow,
        origin: MobileDnsFlowOrigin,
        tcp_flags: u8,
        now: Instant,
    ) -> bool {
        if now.saturating_duration_since(self.last_sweep) >= MOBILE_DNS_FLOW_SWEEP_INTERVAL {
            self.sweep(now);
        }
        if let Some(entry) = self.entries.get_mut(&flow) {
            if entry.origin != origin && !Self::expired(&flow, entry, now) {
                return false;
            }
            let closing = entry.closing || tcp_flags & TCP_FIN != 0;
            if tcp_flags & TCP_RST != 0 {
                self.remove(&flow);
            } else {
                // Through insert, so a changed origin moves the redirect count.
                self.insert(
                    flow,
                    MobileDnsFlowEntry {
                        origin,
                        last_seen: now,
                        closing,
                    },
                );
            }
            return true;
        }
        if tcp_flags & TCP_RST != 0 {
            // Nothing to tear down; still translate so the server sees it.
            return true;
        }
        if !self.admits(flow.client_port, origin)
            && now.saturating_duration_since(self.last_sweep)
                >= MOBILE_DNS_FLOW_PRESSURE_SWEEP_INTERVAL
        {
            self.sweep(now);
        }
        if !self.admits(flow.client_port, origin) {
            return false;
        }
        self.insert(
            flow,
            MobileDnsFlowEntry {
                origin,
                last_seen: now,
                closing: tcp_flags & TCP_FIN != 0,
            },
        );
        true
    }

    /// Admission, not eviction: a live flow is never pushed out to make room,
    /// because its answer would then match nothing while every other flow
    /// keeps getting answered and the status line stays green. Instead a full
    /// table refuses the newcomer, and the room it has is shared out:
    /// - every port may hold its floor (an A and an AAAA) until the table is
    ///   full, but flows past the floor stop once half the table is used, so
    ///   the other half is always there for ports that hold almost nothing.
    ///   A share that shrinks with contention would not do this: nothing is
    ///   evicted, so it cannot give back room already held;
    /// - no port holds more than 32;
    /// - queries redirected from hard-coded resolvers (which any app can send
    ///   from as many ports as it likes) may fill only half the table, so the
    ///   system resolver's lookups through the stub always have room.
    fn admits(&self, client_port: u16, origin: MobileDnsFlowOrigin) -> bool {
        let total = self.entries.len();
        if total >= MOBILE_DNS_FLOW_CAPACITY {
            return false;
        }
        if origin.is_redirect() && self.redirected >= MOBILE_DNS_REDIRECT_CAPACITY {
            return false;
        }
        let held = self.per_port.get(&client_port).copied().unwrap_or(0);
        if held < MOBILE_DNS_FLOWS_PER_PORT_FLOOR {
            return true;
        }
        held < MOBILE_DNS_FLOWS_PER_PORT
            && total < MOBILE_DNS_FLOW_CAPACITY - MOBILE_DNS_NEWCOMER_RESERVE
    }

    /// The server a TCP stream from this port to this resolver already uses:
    /// its follow-up segments must reach the same nameserver.
    fn tcp_stream_server(
        &self,
        servers: &[Ipv4Addr],
        client_port: u16,
        origin: MobileDnsFlowOrigin,
    ) -> Option<Ipv4Addr> {
        servers.iter().copied().find(|server| {
            let flow = MobileWireGuardDnsFlow {
                server: *server,
                protocol: 6,
                client_port,
                query_id: 0,
            };
            self.entries
                .get(&flow)
                .is_some_and(|entry| entry.origin == origin)
        })
    }

    /// The origin for an answer. A UDP answer consumes its flow, so a
    /// duplicate finds nothing; a TCP flow lives until RST, FIN grace or idle.
    fn answer(
        &mut self,
        flow: &MobileWireGuardDnsFlow,
        tcp_flags: u8,
        now: Instant,
    ) -> Option<MobileDnsFlowOrigin> {
        let entry = self.entries.get_mut(flow)?;
        if Self::expired(flow, entry, now) {
            self.remove(flow);
            return None;
        }
        let origin = entry.origin;
        if flow.protocol == 6 && tcp_flags & TCP_RST == 0 {
            entry.last_seen = now;
            entry.closing |= tcp_flags & TCP_FIN != 0;
        } else {
            self.remove(flow);
        }
        Some(origin)
    }
}

struct MobileExitDnsNat {
    local_dns_server: Ipv4Addr,
    servers: Vec<Ipv4Addr>,
    next_server: AtomicUsize,
    /// The tunnel's own IPv4 address: the source for IPv6 queries carried to
    /// the nameserver over IPv4. Without it IPv6 resolvers are refused, not
    /// redirected.
    ipv4_source: Option<Ipv4Addr>,
    /// The largest DNS message that still fits the tun MTU once rebuilt as
    /// IPv6 (40-byte header against IPv4's 20, plus 8 for UDP).
    ipv6_answer_budget: u16,
    flows: Mutex<MobileDnsFlowTable>,
    /// Unix time of the oldest query sent since the last answer, 0 when every
    /// query so far has been answered. A box that is off or unreachable never
    /// answers, so this is how status tells "connected" from "resolving".
    unanswered_since: AtomicU64,
}

impl MobileExitDnsNat {
    fn new(local_dns_server: Ipv4Addr, servers: Vec<Ipv4Addr>) -> Option<Self> {
        (!servers.is_empty()).then_some(Self {
            local_dns_server,
            servers,
            next_server: AtomicUsize::new(0),
            ipv4_source: None,
            ipv6_answer_budget: ipv6_dns_answer_budget(DEFAULT_MOBILE_MTU),
            flows: Mutex::new(MobileDnsFlowTable::new(Instant::now())),
            unanswered_since: AtomicU64::new(0),
        })
    }

    fn with_ipv4_source(mut self, ipv4_source: Option<Ipv4Addr>) -> Self {
        self.ipv4_source = ipv4_source;
        self
    }

    fn with_mtu(mut self, mtu: u16) -> Self {
        self.ipv6_answer_budget = ipv6_dns_answer_budget(mtu);
        self
    }

    fn rewrite_query(&self, packet: &mut [u8]) -> Option<Ipv4Addr> {
        let (_, destination, _, destination_port, _) = ipv4_transport_endpoints(packet)?;
        if destination != self.local_dns_server || destination_port != 53 {
            return None;
        }
        self.translate_query(packet, destination, Instant::now())
    }

    /// Plain DNS sent straight to a sinkholed public resolver, redirected to
    /// the network nameserver instead of refused. Plenty of apps hard-code
    /// `8.8.8.8:53` as a fallback; dropping it costs them a full timeout per
    /// lookup, while redirecting keeps them working and lands the query in
    /// the nameserver's log. Encrypted DNS cannot be redirected this way, so
    /// 443/853 still get refused by the sinkhole.
    ///
    /// UDP to an IPv6 resolver (including NAT64-synthesized ones) is carried
    /// to the nameserver as IPv4 and its answer translated back. TCP to an
    /// IPv6 resolver is left to the sinkhole's immediate reset; clients retry
    /// over UDP or the system resolver.
    fn redirect_public_resolver_query(&self, packet: &mut Vec<u8>) -> Option<Ipv4Addr> {
        self.redirect_public_resolver_query_at(packet, Instant::now())
    }

    fn redirect_public_resolver_query_at(
        &self,
        packet: &mut Vec<u8>,
        now: Instant,
    ) -> Option<Ipv4Addr> {
        if packet.first()? >> 4 == 6 {
            return self.redirect_ipv6_udp_query(packet, now);
        }
        let (_, destination, _, destination_port, protocol) = ipv4_transport_endpoints(packet)?;
        if destination_port != 53
            || !matches!(protocol, 6 | 17)
            || !is_dns_sinkhole_address(IpAddr::V4(destination))
        {
            return None;
        }
        self.translate_query(packet, destination, now)
    }

    fn redirect_ipv6_udp_query(&self, packet: &mut Vec<u8>, now: Instant) -> Option<Ipv4Addr> {
        let source_v4 = self.ipv4_source?;
        let (client, resolver, client_port, payload) = ipv6_udp_dns_query(packet)?;
        if !is_dns_sinkhole_address(IpAddr::V6(resolver)) {
            return None;
        }
        let query_id = dns_message_id(17, payload);
        let server = self.pick_server();
        let flow = MobileWireGuardDnsFlow {
            server,
            protocol: 17,
            client_port,
            query_id,
        };
        let origin = MobileDnsFlowOrigin::V6 { resolver, client };
        if !self.flows.lock().ok()?.record(flow, origin, 0, now) {
            return None;
        }
        // The answer grows by 20 bytes on the way back. Asking the nameserver
        // for no more than fits makes it truncate (TC) instead of sending an
        // answer the tun would have to drop.
        let mut payload = payload.to_vec();
        clamp_edns_udp_size(&mut payload, self.ipv6_answer_budget);
        let translated = build_ipv4_udp_packet(source_v4, server, client_port, 53, &payload)?;
        *packet = translated;
        self.mark_unanswered();
        Some(server)
    }

    fn pick_server(&self) -> Ipv4Addr {
        let index = self.next_server.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        self.servers[index]
    }

    fn mark_unanswered(&self) {
        let _ = self.unanswered_since.compare_exchange(
            0,
            unix_timestamp(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    fn translate_query(
        &self,
        packet: &mut [u8],
        destination: Ipv4Addr,
        now: Instant,
    ) -> Option<Ipv4Addr> {
        let (_, _, source_port, _, protocol) = ipv4_transport_endpoints(packet)?;
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let (query_id, tcp_flags) = match protocol {
            17 => (dns_message_id(17, packet.get(header_len + 8..)?), 0),
            _ => (0, tcp_flags_at(packet, header_len)?),
        };
        let mut flows = self.flows.lock().ok()?;
        // A TCP stream keeps the server it started on; a new stream or UDP
        // query rotates.
        let server = (protocol == 6)
            .then(|| {
                flows.tcp_stream_server(
                    &self.servers,
                    source_port,
                    MobileDnsFlowOrigin::V4(destination),
                )
            })
            .flatten()
            .unwrap_or_else(|| self.pick_server());
        let flow = MobileWireGuardDnsFlow {
            server,
            protocol,
            client_port: source_port,
            query_id,
        };
        if !flows.record(flow, MobileDnsFlowOrigin::V4(destination), tcp_flags, now) {
            return None;
        }
        drop(flows);
        rewrite_ipv4_destination(packet, destination, server);
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(packet);
        self.mark_unanswered();
        Some(server)
    }

    fn unanswered_since(&self) -> u64 {
        self.unanswered_since.load(Ordering::Relaxed)
    }

    fn rewrite_response(&self, packet: &mut Vec<u8>) -> bool {
        self.rewrite_response_at(packet, Instant::now())
    }

    fn rewrite_response_at(&self, packet: &mut Vec<u8>, now: Instant) -> bool {
        let Some((source, _, source_port, destination_port, protocol)) =
            ipv4_transport_endpoints(packet)
        else {
            return false;
        };
        if source_port != 53 {
            return false;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let (query_id, tcp_flags) = match protocol {
            17 => match packet.get(header_len + 8..) {
                Some(payload) => (dns_message_id(17, payload), 0),
                None => return false,
            },
            _ => match tcp_flags_at(packet, header_len) {
                Some(flags) => (0, flags),
                None => return false,
            },
        };
        let flow = MobileWireGuardDnsFlow {
            server: source,
            protocol,
            client_port: destination_port,
            query_id,
        };
        let Some(origin) = self
            .flows
            .lock()
            .ok()
            .and_then(|mut flows| flows.answer(&flow, tcp_flags, now))
        else {
            return false;
        };
        self.unanswered_since.store(0, Ordering::Relaxed);
        match origin {
            MobileDnsFlowOrigin::V4(original) => {
                rewrite_ipv4_source(packet, source, original);
                nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(packet);
                true
            }
            MobileDnsFlowOrigin::V6 { resolver, client } => {
                let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                let Some(payload) = packet.get(header_len + 8..total_len) else {
                    return false;
                };
                // Backstop for a nameserver that ignores the clamped EDNS size
                // or a query that had none: a truncated answer the client can
                // act on beats one the tun drops.
                let payload = truncate_dns_answer(payload, self.ipv6_answer_budget);
                let Some(translated) =
                    build_ipv6_udp_packet(resolver, client, 53, destination_port, &payload)
                else {
                    return false;
                };
                *packet = translated;
                true
            }
        }
    }
}

fn ipv6_dns_answer_budget(mtu: u16) -> u16 {
    mtu.saturating_sub(40 + 8).max(512)
}

/// Offset just past the domain name starting at `offset`.
fn skip_dns_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *message.get(offset)?;
        match length & 0xc0 {
            0xc0 => return Some(offset + 2).filter(|end| *end <= message.len()),
            0x00 if length == 0 => return Some(offset + 1),
            0x00 => offset += 1 + usize::from(length),
            _ => return None,
        }
    }
}

/// Offset just past the question section.
fn dns_questions_end(message: &[u8]) -> Option<usize> {
    let questions = u16::from_be_bytes([*message.get(4)?, *message.get(5)?]);
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(message, offset)? + 4;
    }
    (offset <= message.len()).then_some(offset)
}

/// Lower the EDNS0 UDP payload size the query advertises to `budget`. A query
/// with no OPT record already caps answers at 512 bytes.
fn clamp_edns_udp_size(message: &mut [u8], budget: u16) {
    let Some(mut offset) = dns_questions_end(message) else {
        return;
    };
    let count = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]);
    let records = u32::from(count(6)) + u32::from(count(8)) + u32::from(count(10));
    for _ in 0..records {
        let Some(name_end) = skip_dns_name(message, offset) else {
            return;
        };
        let Some(fixed) = message.get(name_end..name_end + 10) else {
            return;
        };
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdata_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        if record_type == 41 {
            let size = u16::from_be_bytes([fixed[2], fixed[3]]);
            if size > budget {
                message[name_end + 2..name_end + 4].copy_from_slice(&budget.to_be_bytes());
            }
            return;
        }
        offset = name_end + 10 + rdata_len;
    }
}

/// `answer` unchanged when it fits `budget`; otherwise its header and question
/// with TC set and no records, the standard "too big for UDP" reply.
fn truncate_dns_answer(answer: &[u8], budget: u16) -> std::borrow::Cow<'_, [u8]> {
    if answer.len() <= usize::from(budget) {
        return std::borrow::Cow::Borrowed(answer);
    }
    let keep = dns_questions_end(answer)
        .filter(|end| *end <= usize::from(budget))
        .unwrap_or(12);
    let mut truncated = answer[..keep].to_vec();
    truncated[2] |= 0x02;
    if keep == 12 {
        truncated[4..6].fill(0);
    }
    truncated[6..12].fill(0);
    std::borrow::Cow::Owned(truncated)
}

/// The DNS message ID that pairs a UDP answer with its query. TCP streams
/// carry a length prefix and may split messages, so they are not keyed on it.
fn dns_message_id(protocol: u8, payload: &[u8]) -> u16 {
    match (protocol, payload) {
        (17, [high, low, ..]) => u16::from_be_bytes([*high, *low]),
        _ => 0,
    }
}

fn tcp_flags_at(packet: &[u8], header_len: usize) -> Option<u8> {
    packet.get(header_len + 13).copied()
}

/// `(client, resolver, client_port, dns_payload)` for a plain UDP/53 query over
/// IPv6 with no extension headers.
fn ipv6_udp_dns_query(packet: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr, u16, &[u8])> {
    if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != 17 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let udp = packet.get(40..40 + payload_len)?;
    if udp.len() < 8 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if u16::from_be_bytes([udp[2], udp[3]]) != 53 || udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    Some((
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?),
        u16::from_be_bytes([udp[0], udp[1]]),
        &udp[8..udp_len],
    ))
}

fn build_ipv4_udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let total_len = u16::try_from(20 + 8 + payload.len()).ok()?;
    let mut packet = vec![0_u8; usize::from(total_len)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    // Non-zero placeholder so the finalizer computes a real checksum.
    packet[26..28].copy_from_slice(&[0xff, 0xff]);
    packet[28..].copy_from_slice(payload);
    nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut packet);
    Some(packet)
}

fn build_ipv6_udp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let mut packet = vec![0_u8; 40 + usize::from(udp_len)];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&udp_len.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..46].copy_from_slice(&udp_len.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    nostr_vpn_core::packet_checksums::finalize_ipv6_transport_checksum(&mut packet);
    Some(packet)
}

async fn mobile_dns_packet_action(
    packet: &[u8],
    app_config: &Arc<RwLock<AppConfig>>,
    secure_dns: Option<&dyn SecureDnsLookup>,
    magic_dns_server: Ipv4Addr,
    forward_public_via_wireguard: bool,
) -> Option<MobileDnsPacketAction> {
    let query = parse_mobile_magic_dns_query(packet, magic_dns_server)?;
    let response = {
        let app = app_config.read().ok()?;
        let records = build_magic_dns_records(&app);
        build_magic_dns_response_if_handled(query.payload, &records)
    };
    let response = match response {
        Some(response) => response,
        None if forward_public_via_wireguard => {
            return Some(MobileDnsPacketAction::ForwardViaExit);
        }
        None => match secure_dns {
            Some(resolver) => match resolver.resolve(query.payload).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(%error, "mobile secure DNS resolution failed closed");
                    build_servfail_response(query.payload)?
                }
            },
            None => build_magic_dns_server_failure_response(query.payload)?,
        },
    };
    build_mobile_dns_response_packet(&query, &response).map(MobileDnsPacketAction::Respond)
}

#[cfg(test)]
async fn mobile_magic_dns_response_packet(
    packet: &[u8],
    app_config: &Arc<RwLock<AppConfig>>,
    secure_dns: Option<&dyn SecureDnsLookup>,
    magic_dns_server: Ipv4Addr,
) -> Option<Vec<u8>> {
    match mobile_dns_packet_action(packet, app_config, secure_dns, magic_dns_server, false).await? {
        MobileDnsPacketAction::Respond(response) => Some(response),
        MobileDnsPacketAction::ForwardViaExit => None,
    }
}

fn ipv4_transport_endpoints(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, u8)> {
    if packet.len() < 24 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 4 || !matches!(packet[9], 6 | 17) {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 4 || packet.len() < total_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
    if fragment != 0 {
        return None;
    }
    Some((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
        packet[9],
    ))
}

fn parse_mobile_magic_dns_query(
    packet: &[u8],
    magic_dns_server: Ipv4Addr,
) -> Option<MobileDnsQuery<'_>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != 17 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
    if fragment != 0 {
        return None;
    }
    let magic_dns_octets = magic_dns_server.octets();
    if &packet[16..20] != magic_dns_octets.as_slice() {
        return None;
    }
    let destination = magic_dns_server;
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let udp = header_len;
    let source_port = u16::from_be_bytes([packet[udp], packet[udp + 1]]);
    let destination_port = u16::from_be_bytes([packet[udp + 2], packet[udp + 3]]);
    if destination_port != 53 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([packet[udp + 4], packet[udp + 5]]));
    if udp_len < 8 || udp + udp_len > total_len {
        return None;
    }
    Some(MobileDnsQuery {
        source,
        destination,
        source_port,
        destination_port,
        payload: &packet[udp + 8..udp + udp_len],
    })
}

fn build_mobile_dns_response_packet(
    query: &MobileDnsQuery<'_>,
    dns_response: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8_usize.checked_add(dns_response.len())?;
    let total_len = 20_usize.checked_add(udp_len)?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;
    let total_len_u16 = u16::try_from(total_len).ok()?;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&query.destination.octets());
    packet[16..20].copy_from_slice(&query.source.octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&query.destination_port.to_be_bytes());
    packet[22..24].copy_from_slice(&query.source_port.to_be_bytes());
    packet[24..26].copy_from_slice(&udp_len_u16.to_be_bytes());
    packet[28..].copy_from_slice(dns_response);
    Some(packet)
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum = sum.wrapping_add(u32::from(value));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded IPv4 checksum fits in u16")
}

fn ipv4_is_lan_endpoint_hint(ip: Ipv4Addr) -> bool {
    ip.is_private() && !ipv4_is_mesh_tunnel_ip(ip)
}

fn ipv4_is_mesh_tunnel_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10 && octets[1] == 44
}

#[cfg(debug_assertions)]
pub(crate) fn mobile_debug_log(message: impl AsRef<str>) {
    let dir = std::env::temp_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("nvpn-mobile-debug.log");
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = writeln!(file, "{:?} {}", SystemTime::now(), message.as_ref());
}

#[cfg(not(debug_assertions))]
pub(crate) fn mobile_debug_log(_message: impl AsRef<str>) {}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    strip_cidr(value.trim()).parse().ok()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn empty_config() -> MobileTunnelConfig {
    MobileTunnelConfig {
        config_path: String::new(),
        app_config_toml: String::new(),
        identity_nsec: String::new(),
        node_name: String::new(),
        network_id: String::new(),
        join_secret: String::new(),
        local_address: String::new(),
        local_address_ipv6: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        mtu: DEFAULT_MOBILE_MTU,
        peers: Vec::new(),
        peer_hints: HashMap::new(),
        bootstrap_peers: HashMap::new(),
        route_targets: Vec::new(),
        nostr_relays: Vec::new(),
        websocket_seed_urls: Vec::new(),
        stun_servers: Vec::new(),
        share_local_candidates: false,
        connect_to_non_roster_fips_peers: false,
        nostr_discovery_enabled: true,
        webrtc_enabled: false,
        excluded_routes: Vec::new(),
        dns_servers: Vec::new(),
        magic_dns_server: String::new(),
        network_dns: String::new(),
        network_dns_unavailable: false,
        dns_match_domains: Vec::new(),
        exit_dns: ExitDnsConfig::default(),
        wireguard_exit: None,
        join_requests_enabled: false,
        device_approval_pending: false,
        local_identity_confirmation_pending: false,
        pending_join_network_id: String::new(),
        pending_join_request_recipient: String::new(),
        pending_join_secret: String::new(),
        pending_join_requested_at: 0,
        error: String::new(),
    }
}
