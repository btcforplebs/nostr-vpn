// DNS bypass sinkhole for the network DNS override.
//
// Pointing the system resolver at the in-tunnel stub captures every lookup the
// OS makes, but an app can still skip it by talking DoH/DoT/DoQ to a public
// resolver's hard-coded address. While the override is on, those addresses are
// routed into the tunnel and refused here, so the only resolver that works is
// the network's own. Hostname-based DoH (resolvers reached by name, or behind
// shared CDN addresses) is left to the network nameserver's blocklist, which
// sees the lookup for the DoH hostname first.
//
// Only dedicated resolver anycast addresses belong on this list. A shared CDN
// address would break ordinary sites that happen to sit behind it.
// Addresses re-resolved from each provider's DoH hostname, 2026-10-11.
const DNS_SINKHOLE_ADDRESSES: &[&str] = &[
    // Google (dns.google)
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    // Cloudflare (one.one.one.one, security., family.)
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2606:4700:4700::1112",
    "2606:4700:4700::1002",
    "2606:4700:4700::1113",
    "2606:4700:4700::1003",
    // Cloudflare browser-vendor endpoints (mozilla./chrome.cloudflare-dns.com)
    "162.159.61.3",
    "162.159.61.4",
    "172.64.41.3",
    "172.64.41.4",
    "2a06:98c1:52::3",
    "2a06:98c1:52::4",
    "2803:f800:53::3",
    "2803:f800:53::4",
    // Quad9 (dns., dns9., dns10., dns11.quad9.net)
    "9.9.9.9",
    "149.112.112.112",
    "149.112.112.9",
    "9.9.9.10",
    "149.112.112.10",
    "9.9.9.11",
    "149.112.112.11",
    "2620:fe::fe",
    "2620:fe::9",
    "2620:fe::fe:9",
    "2620:fe::10",
    "2620:fe::fe:10",
    "2620:fe::11",
    "2620:fe::fe:11",
    // OpenDNS (dns., doh.opendns.com)
    "208.67.222.222",
    "208.67.220.220",
    "146.112.41.2",
    "2620:119:35::35",
    "2620:119:53::53",
    "2620:119:fc::2",
    // AdGuard (dns., unfiltered., family.adguard-dns.com)
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.140",
    "94.140.14.141",
    "94.140.14.15",
    "94.140.15.16",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
    "2a10:50c0::1:ff",
    "2a10:50c0::2:ff",
    "2a10:50c0::bad1:ff",
    "2a10:50c0::bad2:ff",
    // CleanBrowsing (doh.cleanbrowsing.org)
    "185.228.168.168",
    "185.228.168.10",
    // Mullvad (dns., base.dns.mullvad.net)
    "194.242.2.2",
    "194.242.2.4",
    "2a07:e340::2",
    "2a07:e340::4",
    // Control D (freedns.controld.com)
    "76.76.2.11",
    "2606:1a40::11",
    // AliDNS, DNSPod, TWNIC, LibreDNS
    "223.5.5.5",
    "223.6.6.6",
    "2400:3200::1",
    "2400:3200:baba::1",
    "1.12.12.12",
    "120.53.53.53",
    "101.101.101.101",
    "2001:de4::101",
    "2001:de4::102",
    "116.202.176.26",
    "2a01:4f8:1c0c:8274::1",
];

/// Unique-local address for the tun while IPv6 sinkhole routes are installed.
/// It only ever sources packets the sinkhole refuses, and resets come back to
/// it, so it never needs to be reachable from anywhere.
const MOBILE_SINKHOLE_LOCAL_IPV6: &str = "fd6e:7670:6e00::1/128";

/// RFC 6052 well-known NAT64 prefix, `64:ff9b::/96`. On an IPv6-only carrier
/// with DNS64, an app that looks up `dns.google` gets `64:ff9b::808:808`, and
/// iOS synthesizes the same address for a hard-coded IPv4 literal, so each
/// listed IPv4 resolver is also sinkholed at its synthesized address.
///
/// Only the per-resolver /128s are routed, never the /96: routing the prefix
/// would pull every IPv4-literal connection on a 464XLAT carrier into the
/// tunnel. Network-specific prefixes (RFC 6146 NSPs, RFC 8215 local-use) are
/// not covered; they differ per carrier.
const NAT64_WELL_KNOWN_PREFIX: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

fn nat64_synthesized(address: Ipv4Addr) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[..12].copy_from_slice(&NAT64_WELL_KNOWN_PREFIX);
    octets[12..].copy_from_slice(&address.octets());
    Ipv6Addr::from(octets)
}

/// Every destination the sinkhole refuses: the listed addresses plus the
/// NAT64 synthesis of each listed IPv4 one. Routes and refusals both read
/// this one set, so they cannot drift apart.
fn dns_sinkhole_destinations() -> &'static HashSet<IpAddr> {
    static DESTINATIONS: OnceLock<HashSet<IpAddr>> = OnceLock::new();
    DESTINATIONS.get_or_init(|| {
        let listed = DNS_SINKHOLE_ADDRESSES
            .iter()
            .filter_map(|address| address.parse::<IpAddr>().ok());
        let mut destinations = HashSet::new();
        for address in listed {
            destinations.insert(address);
            if let IpAddr::V4(address) = address {
                destinations.insert(IpAddr::V6(nat64_synthesized(address)));
            }
        }
        destinations
    })
}

/// Host routes that pull every sinkholed resolver into the tunnel.
fn dns_sinkhole_route_targets() -> Vec<String> {
    let mut routes = dns_sinkhole_destinations()
        .iter()
        .map(|address| match address {
            IpAddr::V4(address) => format!("{address}/32"),
            IpAddr::V6(address) => format!("{address}/128"),
        })
        .collect::<Vec<_>>();
    routes.sort();
    routes
}

fn is_dns_sinkhole_address(address: IpAddr) -> bool {
    dns_sinkhole_destinations().contains(&address)
}

#[derive(Debug, PartialEq, Eq)]
enum DnsSinkholeVerdict {
    /// Not addressed to a sinkholed resolver.
    Pass,
    /// Swallow the packet.
    Drop,
    /// Swallow the packet and write this reply back into the tun.
    Reply(Vec<u8>),
}

/// Refuse traffic addressed to a sinkholed resolver. Every protocol and port is
/// refused, not just 53/443/853: a resolver address has no other use worth
/// keeping, and a port list is one more thing to get wrong.
///
/// TCP gets a reset so the client gives up on that resolver at once and falls
/// back to the system resolver, instead of waiting out a connect timeout. Other
/// protocols (`DoQ`, QUIC `DoH`, plain UDP/53) are dropped; their clients retry
/// over TCP or fall back on their own timers.
fn dns_sinkhole_verdict(packet: &[u8]) -> DnsSinkholeVerdict {
    let Some(destination) = packet_destination(packet) else {
        return DnsSinkholeVerdict::Pass;
    };
    if !is_dns_sinkhole_address(destination) {
        return DnsSinkholeVerdict::Pass;
    }
    tcp_reset_for(packet).map_or(DnsSinkholeVerdict::Drop, DnsSinkholeVerdict::Reply)
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let octets = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// RFC 9293 §3.10.7.1 reset for a segment arriving at a closed port, with the
/// addresses and ports swapped. `None` when the packet is not a complete,
/// unfragmented TCP segment, or is itself a reset.
fn tcp_reset_for(packet: &[u8]) -> Option<Vec<u8>> {
    let (header_len, segment) = match packet.first()? >> 4 {
        4 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            if ihl < 20 || packet[9] != 6 || fragment & 0x3fff != 0 || total_len > packet.len() {
                return None;
            }
            (20, packet.get(ihl..total_len)?)
        }
        6 => {
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if packet.len() < 40 || packet[6] != 6 {
                return None;
            }
            (40, packet.get(40..40 + payload_len)?)
        }
        _ => return None,
    };
    let data_offset = usize::from(segment.get(12)? >> 4) * 4;
    if data_offset < 20 || segment.len() < data_offset {
        return None;
    }
    let flags = segment[13];
    if flags & TCP_RST != 0 {
        return None;
    }
    let seq = u32::from_be_bytes(segment[4..8].try_into().ok()?);
    let ack = u32::from_be_bytes(segment[8..12].try_into().ok()?);
    let (reset_seq, reset_ack, reset_flags) = if flags & TCP_ACK != 0 {
        (ack, 0, TCP_RST)
    } else {
        let consumed = u32::try_from(segment.len() - data_offset).ok()?
            + u32::from(flags & TCP_SYN != 0)
            + u32::from(flags & TCP_FIN != 0);
        (0, seq.wrapping_add(consumed), TCP_RST | TCP_ACK)
    };

    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&segment[2..4]);
    tcp[2..4].copy_from_slice(&segment[0..2]);
    tcp[4..8].copy_from_slice(&reset_seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&reset_ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = reset_flags;

    let mut reply = Vec::with_capacity(header_len + tcp.len());
    if header_len == 20 {
        reply.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        reply.extend_from_slice(&packet[16..20]);
        reply.extend_from_slice(&packet[12..16]);
        let checksum = ipv4_header_checksum(&reply);
        reply[10..12].copy_from_slice(&checksum.to_be_bytes());
    } else {
        reply.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        reply.extend_from_slice(&packet[24..40]);
        reply.extend_from_slice(&packet[8..24]);
    }
    reply.extend_from_slice(&tcp);
    nostr_vpn_core::packet_checksums::finalize_transport_checksum(&mut reply);
    Some(reply)
}
