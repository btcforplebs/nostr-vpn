pub mod config;
mod config_defaults;
mod config_magic_dns;
pub mod control;
pub mod data_plane;
pub mod diagnostics;
pub mod fips_control;
pub mod fips_mesh;
pub mod join_requests;
pub mod magic_dns;
mod network_roster;
mod network_routes;
pub mod paths;
pub mod platform_paths;

pub use config::DEFAULT_RELAYS;

/// Underlay UDP MTU the daemon targets for the encrypted FIPS frame.
///
/// Sized to fit the worst-case wire image (ciphertext + FIPS framing) inside
/// a 1500-byte ethernet payload after subtracting the IPv6 (40 B) + UDP (8 B)
/// header pair, with a 20-byte cushion for intermediate L2 overhead (PPPoE,
/// MPLS, tunnel-over-tunnel).
///
/// Anything smaller than this still works — the kernel fragments — but the
/// daemon takes a per-packet syscall hit so we want this as large as is
/// safe across common underlays.
pub const MESH_UNDERLAY_UDP_MTU: u16 = 1432;

/// Tunnel-side MTU: maximum IPv4/IPv6 packet a TUN device hands to the daemon
/// for encryption + transit. Equals `MESH_UNDERLAY_UDP_MTU` minus the 106-byte
/// FIPS overhead (handshake nonce + AEAD framing + inner header; see fips-core
/// `upper::icmp::FIPS_OVERHEAD`) minus a 6-byte cushion for the optional
/// COORDS warmup tag. Single source of truth — every TUN config, every
/// UdpConfig, every Wintun adapter, every linux `ip link set mtu` should
/// derive from this.
pub const MESH_TUNNEL_MTU: u16 = 1320;
