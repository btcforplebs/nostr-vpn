use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::*;

use crate::data_plane::DataPlaneCapability;

pub const NOSTR_KIND_NOSTR_VPN_NODE_RECORD: u16 = 30_078;
pub const NODE_RECORD_D_TAG: &str = "nostr-vpn:node";
pub const NODE_RECORD_RELAY_TAG: &str = "nostr-vpn-relay";
pub const NODE_RECORD_NAT_ASSIST_TAG: &str = "nostr-vpn-nat-assist";
pub const NODE_RECORD_EXIT_TAG: &str = "nostr-vpn-exit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRecordMode {
    Private,
    PublicPeer,
    PublicService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeServiceKind {
    Relay,
    NatAssist,
    Exit,
}

impl NodeServiceKind {
    pub fn discovery_tag(&self) -> &'static str {
        match self {
            Self::Relay => NODE_RECORD_RELAY_TAG,
            Self::NatAssist => NODE_RECORD_NAT_ASSIST_TAG,
            Self::Exit => NODE_RECORD_EXIT_TAG,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeService {
    pub kind: NodeServiceKind,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_hint_msats: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub mode: NodeRecordMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<NodeService>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_plane: Option<DataPlaneCapability>,
    pub updated_at: u64,
    pub expires_at: u64,
}

impl NodeRecord {
    pub fn discovery_tags(&self) -> Vec<&'static str> {
        let mut tags = self
            .services
            .iter()
            .map(|service| service.kind.discovery_tag())
            .collect::<Vec<_>>();
        tags.sort_unstable();
        tags.dedup();
        tags
    }

    pub fn has_service(&self, kind: NodeServiceKind) -> bool {
        self.services.iter().any(|service| service.kind == kind)
    }
}

pub async fn publish_node_record(
    secret_key: &str,
    relays: &[String],
    record: &NodeRecord,
) -> Result<()> {
    let keys = Keys::parse(secret_key).context("invalid nostr secret key")?;
    let client = ClientBuilder::new()
        .signer(keys.clone())
        .database(nostr_sdk::database::MemoryDatabase::new())
        .build();

    for relay in relays {
        client
            .add_relay(relay)
            .await
            .with_context(|| format!("failed to add relay {relay}"))?;
    }
    client.connect().await;

    let expiration = Timestamp::from_secs(record.expires_at);
    let mut tags = vec![
        Tag::identifier(NODE_RECORD_D_TAG),
        Tag::expiration(expiration),
    ];
    for discovery_tag in record.discovery_tags() {
        tags.push(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T)),
            vec![discovery_tag.to_string()],
        ));
    }

    let content =
        serde_json::to_string(record).context("failed to serialize node record content")?;
    let event = EventBuilder::new(node_record_kind(), content, tags)
        .to_event(&keys)
        .context("failed to sign node record event")?;

    let result = match client.send_event(event).await {
        Ok(output) if !output.success.is_empty() => Ok(()),
        Ok(_) => Err(anyhow!("node record rejected by all relays")),
        Err(error) => Err(anyhow!(error).context("failed to publish node record")),
    };

    let _ = client.disconnect().await;
    result
}

pub async fn discover_node_records(
    relays: &[String],
    service_tag: &str,
    lookback: Duration,
) -> Result<HashMap<String, NodeRecord>> {
    let client = ClientBuilder::new()
        .database(nostr_sdk::database::MemoryDatabase::new())
        .build();

    for relay in relays {
        client
            .add_relay(relay)
            .await
            .with_context(|| format!("failed to add relay {relay}"))?;
    }
    client.connect().await;

    client
        .subscribe(
            vec![
                Filter::new()
                    .kind(node_record_kind())
                    .custom_tag(
                        SingleLetterTag::lowercase(Alphabet::D),
                        vec![NODE_RECORD_D_TAG.to_string()],
                    )
                    .custom_tag(
                        SingleLetterTag::lowercase(Alphabet::T),
                        vec![service_tag.to_string()],
                    )
                    .since(Timestamp::now() - lookback),
            ],
            None,
        )
        .await
        .context("failed to subscribe to node records")?;

    let mut notifications = client.notifications();
    let mut out = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        let wait_for = std::cmp::min(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            Duration::from_millis(50),
        );
        match tokio::time::timeout(wait_for, notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                if event.kind != node_record_kind() {
                    continue;
                }
                let Ok(record) = serde_json::from_str::<NodeRecord>(&event.content) else {
                    continue;
                };
                if record.expires_at <= Timestamp::now().as_u64() {
                    continue;
                }
                out.insert(event.pubkey.to_hex(), record);
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }

    let _ = client.disconnect().await;
    Ok(out)
}

fn node_record_kind() -> Kind {
    Kind::from(NOSTR_KIND_NOSTR_VPN_NODE_RECORD)
}
