use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(debug_assertions)]
use std::fs::OpenOptions;
#[cfg(debug_assertions)]
use std::io::Write;
#[cfg(test)]
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use fips_endpoint::{
    Config as FipsConfig, ConnectPolicy, FipsEndpoint, FipsEndpointMessage, FipsEndpointPeer,
    FipsEndpointRelayStatus, NostrDiscoveryPolicy, PeerAddress, PeerConfig as FipsPeerConfig,
    PeerIdentity, TransportInstances, UdpConfig,
};
use nostr_sdk::prelude::PublicKey;
use nostr_vpn_core::config::{
    AppConfig, MESH_TUNNEL_IPV4_CIDR, SharedNetworkRoster, WireGuardExitConfig,
    derive_mesh_tunnel_ip, maybe_autoconfigure_node, normalize_nostr_pubkey,
    normalize_runtime_network_id, split_peer_transport_addr,
};
use nostr_vpn_core::fips_control::NetworkRoster;
use nostr_vpn_core::fips_control::{
    FipsControlFragmentBuffer, FipsControlFrame, PeerCapabilities, PeerEndpointHint, SignedRoster,
    decode_fips_control_frame, encode_fips_control_frame, encode_fips_control_messages,
    local_fips_dataplane_features, peer_endpoint_hint_addr,
};
use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime};
use nostr_vpn_core::join_requests::{FIPS_JOIN_REQUEST_RETRY_SECS, MeshJoinRequest};
use nostr_vpn_core::magic_dns::{build_magic_dns_records, build_magic_dns_response_if_handled};
use nostr_vpn_core::signed_rosters::{
    load_signed_rosters, signed_rosters_file_path, upsert_signed_roster,
};
use nostr_vpn_core::wg_upstream::{DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT, WgUpstreamRuntime};
use serde::{Deserialize, Serialize};

use crate::state::{DaemonPeerState, DaemonRuntimeState};
use crate::wg_upstream_nat::{rewrite_ipv4_destination, rewrite_ipv4_source};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task::JoinHandle;


include!("mobile_tunnel/config.rs");
include!("mobile_tunnel/runtime.rs");
include!("mobile_tunnel/endpoint_control.rs");
include!("mobile_tunnel/runtime_state.rs");
include!("mobile_tunnel/endpoint_config.rs");
include!("mobile_tunnel/magic_dns.rs");

#[cfg(test)]
mod tests {
    include!("mobile_tunnel/tests_core.rs");
    include!("mobile_tunnel/tests_runtime.rs");
    include!("mobile_tunnel/tests_config.rs");
}

fn dns_log(dns_log_path: &str, config_path: &Option<std::path::PathBuf>, message: &str) {
    let log_path = if !dns_log_path.is_empty() {
        std::path::PathBuf::from(dns_log_path)
    } else {
        let Some(path) = config_path else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        parent.join("dns_nat_debug.log")
    };
    
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        use std::io::Write;
        let _ = writeln!(file, "[{timestamp}] {message}");
    }
}

