#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frame_roundtrips_with_magic_prefix() {
        let frame = FipsControlFrame::Ping {
            network_id: "mesh".to_string(),
            sent_at: 42,
        };

        let encoded = encode_fips_control_frame(&frame).expect("encode");
        assert!(encoded.starts_with(FIPS_CONTROL_MAGIC));

        let decoded = decode_fips_control_frame(&encoded)
            .expect("decode")
            .expect("control frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn raw_packet_is_not_control() {
        let packet = [0x45, 0, 0, 20];

        assert!(
            decode_fips_control_frame(&packet)
                .expect("decode")
                .is_none()
        );
    }

    #[test]
    fn capabilities_frame_roundtrips() {
        let frame = FipsControlFrame::Capabilities {
            network_id: "mesh".to_string(),
            capabilities: PeerCapabilities {
                advertised_routes: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
                endpoint_hints: vec![PeerEndpointHint::udp("192.168.50.22:51820")],
                dataplane_features: vec!["future_feature".to_string()],
                signed_at: 99,
            },
        };

        let encoded = encode_fips_control_frame(&frame).expect("encode");
        let decoded = decode_fips_control_frame(&encoded)
            .expect("decode")
            .expect("control frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn old_capabilities_decode_with_empty_endpoint_hints() {
        let caps: PeerCapabilities =
            serde_json::from_str(r#"{"advertised_routes":["0.0.0.0/0"],"signed_at":99}"#)
                .expect("decode old capabilities");

        assert_eq!(caps.advertised_routes, vec!["0.0.0.0/0".to_string()]);
        assert!(caps.endpoint_hints.is_empty());
        assert!(caps.dataplane_features.is_empty());
        assert_eq!(caps.signed_at, 99);
    }

    #[test]
    fn peer_capabilities_match_dataplane_features_case_insensitively() {
        let caps = PeerCapabilities {
            dataplane_features: vec!["FUTURE_FEATURE".to_string()],
            ..PeerCapabilities::default()
        };

        assert!(caps.supports_dataplane_feature("future_feature"));
        assert!(!caps.supports_dataplane_feature("unknown_feature"));
    }

    #[test]
    fn local_dataplane_features_are_empty_without_protocol_extensions() {
        assert!(local_fips_dataplane_features().is_empty());
    }

    #[test]
    fn signed_roster_verifies_independent_of_alias_map_order() {
        let admin = Keys::generate();
        let alice = Keys::generate().public_key().to_hex();
        let bob = Keys::generate().public_key().to_hex();
        let mut aliases = HashMap::new();
        aliases.insert(bob.clone(), "bob".to_string());
        aliases.insert(alice.clone(), "alice".to_string());
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![bob.clone(), alice.clone()],
            admins: vec![admin.public_key().to_hex()],
            aliases,
            signed_at: 123,
            ..Default::default()
        };

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");

        signed.verify().expect("verify signed roster");
        assert_eq!(
            signed.signer_pubkey_hex().unwrap(),
            admin.public_key().to_hex()
        );
        assert_eq!(signed.network_id().unwrap(), "mesh");
        assert_eq!(signed.roster().unwrap().network_name, "Home");
        assert_eq!(signed.content_hash().len(), 64);
        assert_eq!(signed.artifact_hash().len(), 64);
    }

    #[test]
    fn signed_roster_puts_roster_fields_in_tags() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let mut aliases = HashMap::new();
        aliases.insert(member.clone(), "phone".to_string());
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member.clone()],
            admins: vec![admin.public_key().to_hex()],
            aliases,
            signed_at: 123,
            ..Default::default()
        };

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let tags = signed
            .event
            .tags
            .iter()
            .map(Tag::as_slice)
            .collect::<Vec<_>>();

        assert!(signed.event.content.is_empty());
        assert!(tags.contains(&vec!["d".to_string(), "mesh".to_string()].as_slice()));
        assert!(tags.contains(&vec!["member".to_string(), member].as_slice()));
        assert!(
            tags.iter()
                .any(|tag| tag.first().is_some_and(|tag| tag == "alias"))
        );
    }

    #[test]
    fn join_binding_lives_in_control_data_without_changing_the_roster_event() {
        let admin = Keys::generate();
        let device = Keys::generate().public_key().to_hex();
        let roster = SignedRoster::sign(
            "mesh",
            NetworkRoster {
                network_name: "Home".to_string(),
                devices: vec![device.clone()],
                admins: vec![admin.public_key().to_hex()],
                aliases: HashMap::new(),
                signed_at: 123,
                ..Default::default()
            },
            &admin,
        )
        .expect("sign ordinary roster");
        let join = JoinRosterControl::new(roster.clone(), "qr-request-secret")
            .expect("bind roster to join request");

        join.verify_for_request("qr-request-secret")
            .expect("verify join control data");
        assert_eq!(join.signed_roster, roster);
        assert!(!format!("{join:?}").contains("qr-request-secret"));
        assert!(
            join.verify_for_request("wrong-secret")
                .is_err()
        );

        let frame = join_roster_control_frame(join.clone());
        let encoded = encode_fips_control_frame(&frame).expect("encode join control record");
        assert_eq!(
            decode_fips_control_frame(&encoded).expect("decode join control record"),
            Some(frame)
        );
    }

    #[test]
    fn join_roster_ack_roundtrips_as_application_control_data() {
        let frame = join_roster_ack_control_frame("ab".repeat(32));
        let encoded = encode_fips_control_frame(&frame).expect("encode join roster receipt");

        assert_eq!(
            decode_fips_control_frame(&encoded).expect("decode join roster receipt"),
            Some(frame)
        );
    }

    #[test]
    fn signed_roster_rejects_tampered_content() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member],
            admins: vec![admin.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: 123,
            ..Default::default()
        };
        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let mut event = signed.event.clone();
        event.tags.push(roster_tag(&["name", "Office"]).unwrap());
        let signed = SignedRoster { event };

        assert!(signed.verify().is_err());
    }

    #[test]
    fn endpoint_hints_default_to_udp_transport() {
        let hint: PeerEndpointHint =
            serde_json::from_str(r#"{"addr":"192.168.50.22:51820"}"#).expect("decode hint");

        assert_eq!(hint.transport, "udp");
        assert_eq!(hint.addr, "192.168.50.22:51820");
    }

    #[test]
    fn peer_endpoint_hint_addr_accepts_lan_and_dns_udp_hints() {
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22:51820")),
            Some("192.168.50.22:51820".to_string())
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("peer.example.com:51820")),
            Some("peer.example.com:51820".to_string())
        );
    }

    #[test]
    fn peer_endpoint_hint_addr_rejects_unusable_hints() {
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint {
                transport: "tcp".to_string(),
                addr: "192.168.50.22:51820".to_string(),
            }),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("127.0.0.1:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("100.120.94.10:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("198.51.100.10:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("0.0.0.0:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("localhost:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("not an endpoint:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp(format!(
                "{}:51820",
                "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            ))),
            None
        );
    }

    #[test]
    fn large_stateful_control_frame_roundtrips_as_one_record() {
        let roster = NetworkRoster {
            network_name: "Network 1".to_string(),
            devices: (0..12).map(|value| format!("{value:064x}")).collect(),
            admins: vec!["f".repeat(64)],
            aliases: (0..12)
                .map(|value| (format!("{value:064x}"), format!("node-{value}")))
                .collect(),
            signed_at: 123,
            ..Default::default()
        };
        let frame = FipsControlFrame::Roster {
            network_id: "mesh".to_string(),
            roster,
            signed_roster: None,
        };

        let encoded = encode_fips_control_frame(&frame).expect("encode one state-control record");
        assert!(encoded.len() > 1_100);
        assert_eq!(
            decode_fips_control_frame(&encoded).expect("decode state-control record"),
            Some(frame)
        );
    }

    #[test]
    fn unknown_kind_is_dropped_silently() {
        let mut bytes = Vec::from(FIPS_CONTROL_MAGIC);
        bytes.extend_from_slice(br#"{"v":1,"frame":{"kind":"future_kind","x":1}}"#);

        assert!(decode_fips_control_frame(&bytes).expect("decode").is_none());
    }

    #[test]
    fn future_version_is_dropped_silently() {
        let mut bytes = Vec::from(FIPS_CONTROL_MAGIC);
        bytes
            .extend_from_slice(br#"{"v":99,"frame":{"kind":"ping","network_id":"x","sent_at":1}}"#);

        assert!(decode_fips_control_frame(&bytes).expect("decode").is_none());
    }

    fn dns_roster(dns_node: String, dns_override: bool, devices: Vec<String>) -> NetworkRoster {
        NetworkRoster {
            network_name: "Home".to_string(),
            devices,
            admins: Vec::new(),
            aliases: HashMap::new(),
            dns_node,
            dns_backup_nodes: Vec::new(),
            dns_override,
            signed_at: 123,
        }
    }

    fn roster_tag_rows(signed: &SignedRoster) -> Vec<Vec<String>> {
        signed
            .event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect()
    }

    #[test]
    fn signed_roster_round_trips_dns_backups_in_preference_order() {
        let admin = Keys::generate();
        let pihole = Keys::generate().public_key().to_hex();
        let second = Keys::generate().public_key().to_hex();
        let third = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(
            pihole.clone(),
            true,
            vec![pihole.clone(), second.clone(), third.clone()],
        );
        roster.admins = vec![admin.public_key().to_hex()];
        // Deliberately not sorted, so a sort anywhere on the path shows up.
        roster.dns_backup_nodes = vec![third.clone(), second.clone()];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let backup_tags = roster_tag_rows(&signed)
            .into_iter()
            .filter(|tag| tag[0] == "dns-node-backup")
            .map(|tag| tag[1].clone())
            .collect::<Vec<_>>();
        assert_eq!(backup_tags, vec![third.clone(), second.clone()]);

        let decoded = signed.roster().expect("decode roster");
        assert_eq!(decoded.dns_node, pihole);
        assert_eq!(decoded.dns_backup_nodes, vec![third, second]);
    }

    /// A client from before backups existed knows only `dns-node` and keeps
    /// the last one it sees. It must still land on the primary, so the
    /// backups cannot travel as extra `dns-node` tags.
    #[test]
    fn a_client_that_predates_dns_backups_keeps_the_primary() {
        let admin = Keys::generate();
        let pihole = Keys::generate().public_key().to_hex();
        let backup = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(pihole.clone(), true, vec![pihole.clone(), backup.clone()]);
        roster.admins = vec![admin.public_key().to_hex()];
        roster.dns_backup_nodes = vec![backup.clone()];
        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");

        // The pre-backup rule: every `dns-node` tag overwrites the last.
        let mut old_client_dns_node = String::new();
        for tag in roster_tag_rows(&signed) {
            if tag[0] == "dns-node" {
                old_client_dns_node = tag[1].clone();
            }
        }
        assert_eq!(old_client_dns_node, pihole);

        // And the decoder, fed only the tags an old client understands,
        // agrees.
        let old_tags = signed
            .event
            .tags
            .iter()
            .filter(|tag| tag.as_slice().first().map(String::as_str) != Some("dns-node-backup"))
            .cloned()
            .collect::<Vec<_>>();
        let (_, decoded) = signed_roster_from_tags(&old_tags, 123).expect("decode old tags");
        assert_eq!(decoded.dns_node, pihole);
        assert!(decoded.dns_backup_nodes.is_empty());
    }

    #[test]
    fn signed_roster_drops_dns_backups_that_are_not_usable() {
        let admin = Keys::generate();
        let pihole = Keys::generate().public_key().to_hex();
        let backup = Keys::generate().public_key().to_hex();
        let stranger = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(pihole.clone(), true, vec![pihole.clone(), backup.clone()]);
        roster.admins = vec![admin.public_key().to_hex()];
        roster.dns_backup_nodes = vec![
            stranger,
            pihole.clone(),
            backup.clone(),
            backup.clone(),
        ];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let decoded = signed.roster().expect("decode roster");

        assert_eq!(
            decoded.dns_backup_nodes,
            vec![backup],
            "non-members, the primary itself and repeats must all be dropped"
        );
    }

    #[test]
    fn signed_roster_round_trips_the_network_dns_selection() {
        let admin = Keys::generate();
        let pihole = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(pihole.clone(), true, vec![pihole.clone()]);
        roster.admins = vec![admin.public_key().to_hex()];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let tags = signed
            .event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect::<Vec<_>>();
        assert!(tags.contains(&vec!["dns-node".to_string(), pihole.clone()]));
        assert!(tags.contains(&vec!["dns-override".to_string(), "1".to_string()]));

        let decoded = signed.roster().expect("decode roster");
        assert_eq!(decoded.dns_node, pihole);
        assert!(decoded.dns_override);
    }

    #[test]
    fn signed_roster_without_dns_tags_stays_unset() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(String::new(), false, vec![member]);
        roster.admins = vec![admin.public_key().to_hex()];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        assert!(
            !signed
                .event
                .tags
                .iter()
                .any(|tag| matches!(tag.as_slice().first(), Some(kind) if kind.starts_with("dns")))
        );

        let decoded = signed.roster().expect("decode roster");
        assert!(decoded.dns_node.is_empty());
        assert!(!decoded.dns_override);
    }

    /// The nameserver goes, the override stays: members fail closed on it.
    #[test]
    fn signed_roster_drops_a_dns_node_that_left_the_roster() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let stranger = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(stranger, true, vec![member]);
        roster.admins = vec![admin.public_key().to_hex()];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let decoded = signed.roster().expect("decode roster");

        assert!(decoded.dns_node.is_empty());
        assert!(decoded.dns_override);
    }

    #[test]
    fn signed_roster_keeps_the_override_without_a_dns_node() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster(String::new(), true, vec![member]);
        roster.admins = vec![admin.public_key().to_hex()];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let decoded = signed.roster().expect("decode roster");

        assert!(decoded.dns_node.is_empty());
        assert!(decoded.dns_override);
    }

    /// A bad nameserver value must not stop membership changes from publishing.
    #[test]
    fn signed_roster_still_publishes_membership_with_an_unparseable_dns_node() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let mut roster = dns_roster("not-a-pubkey".to_string(), true, vec![member.clone()]);
        roster.admins = vec![admin.public_key().to_hex()];

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let decoded = signed.roster().expect("decode roster");

        assert_eq!(decoded.devices, vec![member]);
        assert!(decoded.dns_node.is_empty());
        assert!(decoded.dns_override);
    }
}
