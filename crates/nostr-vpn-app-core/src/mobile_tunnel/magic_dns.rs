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
    /// Fingerprint of the UDP query's question section (0 for TCP). The
    /// message ID alone is 16 bits and a stub reuses its port, so a slower
    /// box's answer to an earlier question could otherwise match a fresh flow
    /// and be handed to the phone as the answer to a different question.
    question: u64,
}

/// A UDP lookup the forwarder has finished with, by box: the answer it
/// delivered, or the copies it gave up on. A later datagram matching one of
/// these is a slower box's answer to a question already answered, and is
/// dropped rather than handed to the phone. Only keys the forwarder itself
/// sent are here, so a lookup the phone sends straight to a box's address
/// still gets its answer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MobileRetiredLookup {
    flow: MobileWireGuardDnsFlow,
    question: u64,
}

/// One lookup, across the boxes it was copied to.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MobileDnsLookupKey {
    client_port: u16,
    query_id: u16,
    question: u64,
}

/// What the forwarder knows about one box's liveness.
struct MobileDnsBoxState {
    address: Ipv4Addr,
    /// When the oldest query still unanswered by this box was sent; `None`
    /// once it has answered everything sent so far.
    unanswered_since: Option<Instant>,
}

impl MobileDnsBoxState {
    fn silent(&self, now: Instant) -> bool {
        self.unanswered_since
            .is_some_and(|since| now.saturating_duration_since(since) >= MOBILE_DNS_BOX_SILENT_AFTER)
    }
}

/// A negative answer waiting for a real one from another box.
struct MobileHeldAnswer {
    /// Already rewritten for the phone; delivered as-is when released.
    packet: Vec<u8>,
    since: Instant,
    flow: MobileWireGuardDnsFlow,
}

/// How long a fast negative answer (NXDOMAIN, SERVFAIL, REFUSED, or NOERROR
/// with no records) from one box waits for a real answer from another.
/// Returning nothing is faster than recursing, so without the hold a box
/// that is up but broken wins every lookup because it is broken. The hold
/// only runs while another box's copy is still outstanding: when every box
/// has answered negatively the answer goes straight through.
///
/// 2 s: the phone's resolver retransmits a lost first packet after about 1 s
/// (the same interval the desktop stub uses), and the real answer to that
/// retransmit needs a mesh round trip on top. A hold equal to the retry
/// interval expires just as the retransmit goes out, so the real answer
/// always loses. Keep this equal to the desktop value.
const MOBILE_DNS_NEGATIVE_ANSWER_HOLD: Duration = Duration::from_secs(2);
/// A box with a query unanswered for this long is silent: off, asleep or
/// unreachable. A silent box's copies no longer keep a negative answer
/// waiting, so switching a box off costs the hold once and then nothing,
/// instead of 2 s on every negative lookup (every AAAA for an IPv4-only
/// host, which iOS asks for everything). Longer than a cold recursion takes
/// on a healthy box, so a slow answer does not read as silence.
const MOBILE_DNS_BOX_SILENT_AFTER: Duration = Duration::from_secs(3);

/// Bounded: a nameserver that is off answers nothing, and any app can spray
/// UDP/53 at a listed resolver, so entries must expire on their own.
const MOBILE_DNS_FLOW_CAPACITY: usize = 1024;
/// Most one socket may hold, per DNS box. A resolver pipelines a handful of
/// lookups, and every lookup takes one flow per box it is sent to.
const MOBILE_DNS_FLOWS_PER_PORT: usize = 32;
/// What every port may hold however full the table is: an A and an AAAA,
/// per DNS box.
const MOBILE_DNS_FLOWS_PER_PORT_FLOOR: usize = 2;
/// Kept for ports still under their floor. Flows past a port's floor share
/// only the rest, so filling the table takes hundreds of sockets, not 32.
const MOBILE_DNS_NEWCOMER_RESERVE: usize = MOBILE_DNS_FLOW_CAPACITY / 2;
/// Redirected queries never take the half of the table the stub relies on.
const MOBILE_DNS_REDIRECT_CAPACITY: usize = MOBILE_DNS_FLOW_CAPACITY / 2;
/// Resolvers retry long before this; an unanswered UDP flow is dead by then.
const MOBILE_DNS_UDP_FLOW_TTL: Duration = Duration::from_secs(15);
const MOBILE_DNS_TCP_FLOW_IDLE: Duration = Duration::from_mins(1);
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
    /// Finished lookups, by box, with when they finished. Swept with the
    /// flows; never larger than one entry per box per flow the table has
    /// held in the last TTL, and capped so a flood cannot grow it past that.
    retired: HashMap<MobileRetiredLookup, Instant>,
    /// Negative answers waiting out their hold. One per lookup at most, and
    /// only while that lookup still has a copy outstanding.
    held: HashMap<MobileDnsLookupKey, MobileHeldAnswer>,
    /// Per-box liveness, in list order.
    boxes: Vec<MobileDnsBoxState>,
    /// How many boxes each UDP lookup is sent to, so the per-port limits
    /// count lookups rather than copies.
    fan_out: usize,
}

impl MobileDnsFlowTable {
    fn new(now: Instant, servers: &[Ipv4Addr]) -> Self {
        Self {
            entries: HashMap::new(),
            per_port: HashMap::new(),
            redirected: 0,
            last_sweep: now,
            retired: HashMap::new(),
            held: HashMap::new(),
            boxes: servers
                .iter()
                .map(|server| MobileDnsBoxState {
                    address: *server,
                    unanswered_since: None,
                })
                .collect(),
            fan_out: servers.len().max(1),
        }
    }

    fn box_state(&mut self, server: Ipv4Addr) -> Option<&mut MobileDnsBoxState> {
        self.boxes.iter_mut().find(|state| state.address == server)
    }

    fn box_silent(&self, server: Ipv4Addr, now: Instant) -> bool {
        self.boxes
            .iter()
            .find(|state| state.address == server)
            .is_some_and(|state| state.silent(now))
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
        self.retired.retain(|_, retired_at| {
            now.saturating_duration_since(*retired_at) < MOBILE_DNS_UDP_FLOW_TTL
        });
        // A held answer outlives its flows only until they would have
        // expired; past that the stub has given up and may have reused the
        // port and id, so it is dropped rather than released.
        self.held.retain(|_, held| {
            now.saturating_duration_since(held.since) < MOBILE_DNS_UDP_FLOW_TTL
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
        question: u64,
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
                        question,
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
                question,
            },
        );
        if let Some(state) = self.box_state(flow.server) {
            state.unanswered_since.get_or_insert(now);
        }
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
        if held < MOBILE_DNS_FLOWS_PER_PORT_FLOOR * self.fan_out {
            return true;
        }
        held < MOBILE_DNS_FLOWS_PER_PORT * self.fan_out
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

    /// The origin for an answer. A UDP answer consumes its own flow (the
    /// copies to the other boxes are retired by the caller once it decides
    /// the lookup is done); a TCP flow lives until RST, FIN grace or idle.
    /// `None` for a flow that does not exist, has expired, or was recorded
    /// for a different question than the one this answer carries.
    fn answer(
        &mut self,
        flow: &MobileWireGuardDnsFlow,
        question: u64,
        tcp_flags: u8,
        now: Instant,
    ) -> Option<MobileDnsFlowOrigin> {
        let entry = self.entries.get_mut(flow)?;
        if Self::expired(flow, entry, now) {
            self.remove(flow);
            return None;
        }
        if flow.protocol != 6 && entry.question != question {
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

    /// Whether a box that is still answering has a copy of this UDP lookup
    /// outstanding. A silent box's copy never comes back, so it does not
    /// count: waiting on it would charge every negative lookup the full hold
    /// for as long as that box is off.
    fn copies_outstanding(
        &self,
        flow: &MobileWireGuardDnsFlow,
        servers: &[Ipv4Addr],
        now: Instant,
    ) -> bool {
        servers.iter().any(|server| {
            !self.box_silent(*server, now)
                && self.entries.contains_key(&MobileWireGuardDnsFlow {
                    server: *server,
                    ..*flow
                })
        })
    }

    /// The lookup is done: drop every box's copy and remember the keys, so a
    /// slower box's answer is dropped instead of reaching the phone.
    fn retire(
        &mut self,
        flow: &MobileWireGuardDnsFlow,
        question: u64,
        servers: &[Ipv4Addr],
        now: Instant,
    ) {
        if self.retired.len() >= MOBILE_DNS_FLOW_CAPACITY * self.fan_out {
            self.sweep(now);
        }
        for server in servers {
            let flow = MobileWireGuardDnsFlow {
                server: *server,
                ..*flow
            };
            self.remove(&flow);
            if self.retired.len() < MOBILE_DNS_FLOW_CAPACITY * self.fan_out {
                self.retired
                    .insert(MobileRetiredLookup { flow, question }, now);
            }
        }
    }

    fn is_retired(&self, flow: &MobileWireGuardDnsFlow, question: u64, now: Instant) -> bool {
        self.retired
            .get(&MobileRetiredLookup {
                flow: *flow,
                question,
            })
            .is_some_and(|retired_at| {
                now.saturating_duration_since(*retired_at) < MOBILE_DNS_UDP_FLOW_TTL
            })
    }
}

/// What to do with a packet arriving from the direction of the boxes.
#[derive(Debug, PartialEq, Eq)]
enum MobileDnsInbound {
    /// Rewritten in place: hand it to the phone.
    Deliver,
    /// Consumed by the forwarder: a slower box's answer to a question the
    /// phone already has an answer for, or a negative answer being held.
    Drop,
    /// Not an answer to anything the forwarder sent: pass it through as is.
    Unrelated,
}

/// Rewrites in-tunnel DNS to the upstream boxes and the answers back. Every
/// UDP lookup is copied to every box and the first real answer wins, so no
/// box is primary and one that is asleep costs nothing. The price is paid
/// always, not just while a box sleeps: the phone sends one copy per box
/// over the mesh (cellular included), and every box sees every lookup in
/// its log. TCP cannot be copied: a stream goes to one box, the one that
/// answered most recently; it stays pointed there until some UDP answer
/// arrives from another box.
struct MobileExitDnsNat {
    local_dns_server: Ipv4Addr,
    servers: Vec<Ipv4Addr>,
    /// Index of the box whose answer arrived last: the one a new TCP stream
    /// is sent to, since it is known to be awake.
    answering_server: AtomicUsize,
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
    /// Woken when a negative answer is put on hold, so the release task
    /// sleeps until there is something to release.
    hold_notify: tokio::sync::Notify,
}

impl MobileExitDnsNat {
    fn new(local_dns_server: Ipv4Addr, servers: Vec<Ipv4Addr>) -> Option<Self> {
        (!servers.is_empty()).then_some(Self {
            local_dns_server,
            flows: Mutex::new(MobileDnsFlowTable::new(Instant::now(), &servers)),
            servers,
            answering_server: AtomicUsize::new(0),
            ipv4_source: None,
            ipv6_answer_budget: ipv6_dns_answer_budget(DEFAULT_MOBILE_MTU),
            unanswered_since: AtomicU64::new(0),
            hold_notify: tokio::sync::Notify::new(),
        })
    }

    /// Whether lookups are copied to more than one box, which is the only
    /// case a negative answer can ever be held.
    fn fans_out(&self) -> bool {
        self.servers.len() > 1
    }

    fn with_ipv4_source(mut self, ipv4_source: Option<Ipv4Addr>) -> Self {
        self.ipv4_source = ipv4_source;
        self
    }

    fn with_mtu(mut self, mtu: u16) -> Self {
        self.ipv6_answer_budget = ipv6_dns_answer_budget(mtu);
        self
    }

    /// Rewrite a query to the stub so it reaches the boxes. `packet` is
    /// rewritten for the first box; the returned copies, one per further box,
    /// have to be sent too. `None` when it is not a query for the stub or
    /// the flow table refuses it.
    fn rewrite_query(&self, packet: &mut [u8]) -> Option<Vec<Vec<u8>>> {
        self.rewrite_query_at(packet, Instant::now())
    }

    fn rewrite_query_at(&self, packet: &mut [u8], now: Instant) -> Option<Vec<Vec<u8>>> {
        let (_, destination, _, destination_port, _) = ipv4_transport_endpoints(packet)?;
        if destination != self.local_dns_server || destination_port != 53 {
            return None;
        }
        self.translate_query(packet, destination, now)
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
    fn redirect_public_resolver_query(&self, packet: &mut Vec<u8>) -> Option<Vec<Vec<u8>>> {
        self.redirect_public_resolver_query_at(packet, Instant::now())
    }

    fn redirect_public_resolver_query_at(
        &self,
        packet: &mut Vec<u8>,
        now: Instant,
    ) -> Option<Vec<Vec<u8>>> {
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

    fn redirect_ipv6_udp_query(
        &self,
        packet: &mut Vec<u8>,
        now: Instant,
    ) -> Option<Vec<Vec<u8>>> {
        let source_v4 = self.ipv4_source?;
        let (client, resolver, client_port, payload) = ipv6_udp_dns_query(packet)?;
        if !is_dns_sinkhole_address(IpAddr::V6(resolver)) {
            return None;
        }
        let query_id = dns_message_id(17, payload);
        let question = dns_question_fingerprint(payload);
        let origin = MobileDnsFlowOrigin::V6 { resolver, client };
        let servers = self.record_udp_flows(client_port, query_id, question, origin, now)?;
        // The answer grows by 20 bytes on the way back. Asking the nameserver
        // for no more than fits makes it truncate (TC) instead of sending an
        // answer the tun would have to drop.
        let mut payload = payload.to_vec();
        clamp_edns_udp_size(&mut payload, self.ipv6_answer_budget);
        let (first, rest) = servers.split_first()?;
        let copies = rest
            .iter()
            .map(|server| build_ipv4_udp_packet(source_v4, *server, client_port, 53, &payload))
            .collect::<Option<Vec<_>>>()?;
        *packet = build_ipv4_udp_packet(source_v4, *first, client_port, 53, &payload)?;
        self.mark_unanswered();
        Some(copies)
    }

    /// Record one UDP flow per box for this lookup. The boxes that admitted
    /// it, in list order; `None` when none did.
    fn record_udp_flows(
        &self,
        client_port: u16,
        query_id: u16,
        question: u64,
        origin: MobileDnsFlowOrigin,
        now: Instant,
    ) -> Option<Vec<Ipv4Addr>> {
        let mut flows = self.flows.lock().ok()?;
        let servers = self
            .servers
            .iter()
            .copied()
            .filter(|server| {
                let flow = MobileWireGuardDnsFlow {
                    server: *server,
                    protocol: 17,
                    client_port,
                    query_id,
                };
                flows.record(flow, origin, question, 0, now)
            })
            .collect::<Vec<_>>();
        (!servers.is_empty()).then_some(servers)
    }

    /// The box a new TCP stream goes to: the one that answered last, so a
    /// box that is asleep is not asked to open a stream it never will.
    fn answering_server(&self) -> Ipv4Addr {
        let index = self.answering_server.load(Ordering::Relaxed) % self.servers.len();
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
    ) -> Option<Vec<Vec<u8>>> {
        let (_, _, source_port, _, protocol) = ipv4_transport_endpoints(packet)?;
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let origin = MobileDnsFlowOrigin::V4(destination);
        let servers = if protocol == 17 {
            let payload = packet.get(header_len + 8..)?;
            let query_id = dns_message_id(17, payload);
            let question = dns_question_fingerprint(payload);
            self.record_udp_flows(source_port, query_id, question, origin, now)?
        } else {
            let tcp_flags = tcp_flags_at(packet, header_len)?;
            let mut flows = self.flows.lock().ok()?;
            // A TCP stream keeps the box it started on.
            let server = flows
                .tcp_stream_server(&self.servers, source_port, origin)
                .unwrap_or_else(|| self.answering_server());
            let flow = MobileWireGuardDnsFlow {
                server,
                protocol,
                client_port: source_port,
                query_id: 0,
            };
            if !flows.record(flow, origin, 0, tcp_flags, now) {
                return None;
            }
            vec![server]
        };
        let (first, rest) = servers.split_first()?;
        let copies = rest
            .iter()
            .map(|server| {
                let mut copy = packet.to_vec();
                rewrite_ipv4_destination(&mut copy, destination, *server);
                nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut copy);
                copy
            })
            .collect::<Vec<_>>();
        rewrite_ipv4_destination(packet, destination, *first);
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(packet);
        self.mark_unanswered();
        Some(copies)
    }

    fn unanswered_since(&self) -> u64 {
        self.unanswered_since.load(Ordering::Relaxed)
    }

    /// `true` when `packet` answered a forwarded lookup and was rewritten
    /// for the phone.
    fn rewrite_response(&self, packet: &mut Vec<u8>) -> bool {
        self.rewrite_response_at(packet, Instant::now())
    }

    fn rewrite_response_at(&self, packet: &mut Vec<u8>, now: Instant) -> bool {
        self.inbound_at(packet, now) == MobileDnsInbound::Deliver
    }

    /// `false` when the packet must not reach the phone. Everything the
    /// forwarder did not send is passed through untouched, including a
    /// lookup the phone made straight to a box's address.
    fn deliver_response(&self, packet: &mut Vec<u8>) -> bool {
        self.inbound_at(packet, Instant::now()) != MobileDnsInbound::Drop
    }

    fn inbound_at(&self, packet: &mut Vec<u8>, now: Instant) -> MobileDnsInbound {
        let Some((source, _, source_port, destination_port, protocol)) =
            ipv4_transport_endpoints(packet)
        else {
            return MobileDnsInbound::Unrelated;
        };
        if source_port != 53 {
            return MobileDnsInbound::Unrelated;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let (query_id, question, real_answer, tcp_flags) = match protocol {
            17 => match packet.get(header_len + 8..) {
                Some(payload) => (
                    dns_message_id(17, payload),
                    dns_question_fingerprint(payload),
                    dns_answer_has_records(payload),
                    0,
                ),
                None => return MobileDnsInbound::Unrelated,
            },
            _ => match tcp_flags_at(packet, header_len) {
                Some(flags) => (0, 0, true, flags),
                None => return MobileDnsInbound::Unrelated,
            },
        };
        let flow = MobileWireGuardDnsFlow {
            server: source,
            protocol,
            client_port: destination_port,
            query_id,
        };
        let Ok(mut flows) = self.flows.lock() else {
            return MobileDnsInbound::Unrelated;
        };
        // Any DNS datagram from a listed box proves it is up, whether or not
        // it still matches a flow: a real answer that arrives after the hold
        // released and retired its flow, or one whose copy was lost on the
        // mesh, must still clear the box's silence. Otherwise one slow or
        // lost lookup marks the good box silent, the broken box's instant
        // negative then goes out with no hold, and the good box never gets
        // to clear it because clearing needed it to win that race.
        if let Some(state) = flows.box_state(source) {
            state.unanswered_since = None;
        }
        let Some(origin) = flows.answer(&flow, question, tcp_flags, now) else {
            return if protocol == 17 && flows.is_retired(&flow, question, now) {
                MobileDnsInbound::Drop
            } else {
                MobileDnsInbound::Unrelated
            };
        };
        self.unanswered_since.store(0, Ordering::Relaxed);
        // A new TCP stream follows the box that last gave a real answer. A
        // negative one must not steer it: a box answering empty+TC to
        // everything would otherwise win every race and then be the phone's
        // only DNS over TCP, where nothing can be held.
        if protocol == 17
            && real_answer
            && let Some(index) = self.servers.iter().position(|server| *server == source)
        {
            self.answering_server.store(index, Ordering::Relaxed);
        }
        if protocol == 6 {
            drop(flows);
            return if self.rewrite_to_origin(packet, source, origin, header_len, destination_port)
            {
                MobileDnsInbound::Deliver
            } else {
                MobileDnsInbound::Unrelated
            };
        }
        let lookup = MobileDnsLookupKey {
            client_port: destination_port,
            query_id,
            question,
        };
        if !real_answer && flows.copies_outstanding(&flow, &self.servers, now) {
            // Another box may still produce a real answer: hold this one.
            // A second negative while one is held adds nothing. The lock is
            // kept across the rewrite so a real answer cannot slip in
            // between and leave a stale negative behind to be released.
            if flows.held.contains_key(&lookup) {
                return MobileDnsInbound::Drop;
            }
            let mut held = packet.clone();
            if !self.rewrite_to_origin(&mut held, source, origin, header_len, destination_port) {
                return MobileDnsInbound::Unrelated;
            }
            flows.held.insert(
                lookup,
                MobileHeldAnswer {
                    packet: held,
                    since: now,
                    flow,
                },
            );
            drop(flows);
            self.hold_notify.notify_one();
            return MobileDnsInbound::Drop;
        }
        // The lookup is done: a real answer, or every box said no. The first
        // negative, if one is held, is the one the phone gets in the latter
        // case; this later one is dropped.
        let held = flows.held.remove(&lookup);
        flows.retire(&flow, question, &self.servers, now);
        drop(flows);
        match held {
            Some(held) if !real_answer => {
                *packet = held.packet;
                MobileDnsInbound::Deliver
            }
            _ => {
                if self.rewrite_to_origin(packet, source, origin, header_len, destination_port) {
                    MobileDnsInbound::Deliver
                } else {
                    MobileDnsInbound::Unrelated
                }
            }
        }
    }

    /// Negative answers whose hold has run out with no real answer from any
    /// other box, rewritten for the phone and ready to hand over. The caller
    /// polls this: the forwarder is packet-driven and has no clock of its
    /// own.
    fn release_expired_holds(&self) -> Vec<Vec<u8>> {
        self.release_expired_holds_at(Instant::now())
    }

    fn release_expired_holds_at(&self, now: Instant) -> Vec<Vec<u8>> {
        let Ok(mut flows) = self.flows.lock() else {
            return Vec::new();
        };
        let due = flows
            .held
            .iter()
            .filter(|(_, held)| {
                now.saturating_duration_since(held.since) >= MOBILE_DNS_NEGATIVE_ANSWER_HOLD
                    || !flows.copies_outstanding(&held.flow, &self.servers, now)
            })
            .map(|(lookup, _)| *lookup)
            .collect::<Vec<_>>();
        due.into_iter()
            .filter_map(|lookup| {
                let held = flows.held.remove(&lookup)?;
                flows.retire(&held.flow, lookup.question, &self.servers, now);
                // Older than its flows would have lived: the stub gave up
                // long ago and may have reused the port and id. Dropped.
                (now.saturating_duration_since(held.since) < MOBILE_DNS_UDP_FLOW_TTL)
                    .then_some(held.packet)
            })
            .collect()
    }

    /// How long until a held answer is due, counting both the hold running
    /// out and the box it is waiting on going silent; `None` with nothing
    /// held.
    fn next_hold_due(&self) -> Option<Duration> {
        self.next_hold_due_at(Instant::now())
    }

    fn next_hold_due_at(&self, now: Instant) -> Option<Duration> {
        let flows = self.flows.lock().ok()?;
        if flows.held.is_empty() {
            return None;
        }
        let hold_due = flows
            .held
            .values()
            .map(|held| held.since + MOBILE_DNS_NEGATIVE_ANSWER_HOLD)
            .min()?;
        let silence_due = flows
            .boxes
            .iter()
            .filter_map(|state| state.unanswered_since)
            .map(|since| since + MOBILE_DNS_BOX_SILENT_AFTER)
            .filter(|at| *at > now)
            .min();
        let due = silence_due.map_or(hold_due, |at| at.min(hold_due));
        Some(due.saturating_duration_since(now))
    }

    /// Make the answer look like it came from where the phone sent the query.
    fn rewrite_to_origin(
        &self,
        packet: &mut Vec<u8>,
        source: Ipv4Addr,
        origin: MobileDnsFlowOrigin,
        header_len: usize,
        destination_port: u16,
    ) -> bool {
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

/// A fingerprint of a DNS message's question section, case-folded (a stub
/// may randomize the case of the name; the answer echoes it). 0 when the
/// message has no parsable question.
fn dns_question_fingerprint(message: &[u8]) -> u64 {
    let Some(end) = dns_questions_end(message) else {
        return 0;
    };
    // FNV-1a: cheap, no allocation, and the value is never exposed.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in &message[12.min(end)..end] {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Whether an answer is worth delivering over a possible real one from
/// another box: NOERROR with at least one answer record. NXDOMAIN, SERVFAIL,
/// REFUSED and an empty NOERROR are negative, truncated or not: an empty
/// answer with TC set tells the phone nothing but "ask me again over TCP",
/// and a broken box emits exactly that.
fn dns_answer_has_records(message: &[u8]) -> bool {
    if message.len() < 12 {
        return false;
    }
    let rcode = message[3] & 0x0f;
    let answers = u16::from_be_bytes([message[6], message[7]]);
    rcode == 0 && answers > 0
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
        network_dns_servers: Vec::new(),
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
