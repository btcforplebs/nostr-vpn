use nostr_vpn_core::node_record::{
    NODE_RECORD_EXIT_TAG, NODE_RECORD_NAT_ASSIST_TAG, NODE_RECORD_RELAY_TAG, NodeRecord,
    NodeRecordMode, NodeService, NodeServiceKind,
};

#[test]
fn node_record_deduplicates_service_discovery_tags() {
    let record = NodeRecord {
        mode: NodeRecordMode::PublicService,
        services: vec![
            NodeService {
                kind: NodeServiceKind::Relay,
                endpoint: "198.51.100.10:45000".to_string(),
                protocol: Some("udp-port-pair".to_string()),
                price_hint_msats: None,
            },
            NodeService {
                kind: NodeServiceKind::Relay,
                endpoint: "198.51.100.11:45000".to_string(),
                protocol: Some("udp-port-pair".to_string()),
                price_hint_msats: Some(100),
            },
            NodeService {
                kind: NodeServiceKind::NatAssist,
                endpoint: "198.51.100.11:3478".to_string(),
                protocol: Some("stun".to_string()),
                price_hint_msats: None,
            },
            NodeService {
                kind: NodeServiceKind::Exit,
                endpoint: "198.51.100.12:45001".to_string(),
                protocol: Some("socks5".to_string()),
                price_hint_msats: Some(1_000),
            },
        ],
        data_plane: None,
        updated_at: 10,
        expires_at: 100,
    };

    assert_eq!(
        record.discovery_tags(),
        vec![
            NODE_RECORD_EXIT_TAG,
            NODE_RECORD_NAT_ASSIST_TAG,
            NODE_RECORD_RELAY_TAG
        ]
    );
    assert!(record.has_service(NodeServiceKind::Relay));
    assert!(record.has_service(NodeServiceKind::NatAssist));
    assert!(record.has_service(NodeServiceKind::Exit));
}
