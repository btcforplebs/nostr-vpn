use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const FIPS_PRIVATE_IP_PROTOCOL: &str = "nostr-vpn/ip/1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDataPlane {
    #[default]
    #[serde(rename = "wireguard")]
    WireGuard,
    Fips,
}

impl PrivateDataPlane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::Fips => "fips",
        }
    }
}

impl fmt::Display for PrivateDataPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitDataPlane {
    None,
    #[default]
    #[serde(rename = "wireguard")]
    WireGuard,
}

impl ExitDataPlane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WireGuard => "wireguard",
        }
    }
}

impl fmt::Display for ExitDataPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsDataPlaneCapability {
    pub protocol: String,
    pub endpoint_npub: String,
    pub network_scope: String,
    #[serde(default)]
    pub bridge_ok: bool,
}

impl FipsDataPlaneCapability {
    pub fn new(endpoint_npub: impl Into<String>, network_scope: impl Into<String>) -> Self {
        Self {
            protocol: FIPS_PRIVATE_IP_PROTOCOL.to_string(),
            endpoint_npub: endpoint_npub.into(),
            network_scope: network_scope.into(),
            bridge_ok: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "data_plane", rename_all = "snake_case")]
pub enum DataPlaneCapability {
    #[serde(rename = "wireguard")]
    WireGuard,
    Fips {
        fips: FipsDataPlaneCapability,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRoster {
    pub network_id: String,
    pub member_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    pub private_routes: Vec<String>,
    pub exit_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivatePacket {
    pub source_pubkey: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeerStatus {
    pub pubkey: String,
    pub connected: bool,
    pub data_plane: PrivateDataPlane,
}

#[async_trait]
pub trait PrivateMeshBackend: Send {
    async fn start(&mut self, roster: MeshRoster, routes: RoutePolicy) -> Result<()>;

    async fn send_private_packet(&self, packet: &[u8]) -> Result<()>;

    async fn recv_private_packet(&mut self) -> Result<Option<PrivatePacket>>;

    async fn peer_status(&self) -> Result<Vec<MeshPeerStatus>>;
}

pub fn private_data_plane_routes_to_fips(private_data_plane: PrivateDataPlane) -> bool {
    private_data_plane == PrivateDataPlane::Fips
}

pub fn exit_data_plane_routes_to_wireguard(exit_data_plane: ExitDataPlane) -> bool {
    exit_data_plane == ExitDataPlane::WireGuard
}

#[cfg(test)]
mod tests {
    use super::{
        DataPlaneCapability, ExitDataPlane, FIPS_PRIVATE_IP_PROTOCOL, FipsDataPlaneCapability,
        PrivateDataPlane, exit_data_plane_routes_to_wireguard, private_data_plane_routes_to_fips,
    };

    #[test]
    fn defaults_preserve_wireguard_behavior() {
        assert_eq!(PrivateDataPlane::default(), PrivateDataPlane::WireGuard);
        assert_eq!(ExitDataPlane::default(), ExitDataPlane::WireGuard);
        assert!(!private_data_plane_routes_to_fips(
            PrivateDataPlane::default()
        ));
        assert!(exit_data_plane_routes_to_wireguard(ExitDataPlane::default()));
    }

    #[test]
    fn fips_capability_uses_nostr_vpn_ip_protocol() {
        let capability = FipsDataPlaneCapability::new("npub1example", "network-a");
        assert_eq!(capability.protocol, FIPS_PRIVATE_IP_PROTOCOL);
        assert!(!capability.bridge_ok);

        let encoded = serde_json::to_value(DataPlaneCapability::Fips { fips: capability })
            .expect("capability should serialize");
        assert_eq!(encoded["data_plane"], "fips");
        assert_eq!(encoded["fips"]["network_scope"], "network-a");
    }
}
