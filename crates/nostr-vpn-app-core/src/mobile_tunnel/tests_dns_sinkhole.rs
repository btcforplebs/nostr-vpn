    fn tcp_packet_v4(destination: Ipv4Addr, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut packet = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 6, 0, 0, 100, 64, 0, 2];
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet.extend_from_slice(&destination.octets());
        packet.extend_from_slice(&50_000u16.to_be_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ack.to_be_bytes());
        packet.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    fn tcp_packet_v6(destination: std::net::Ipv6Addr, flags: u8, seq: u32) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        packet.extend_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet.extend_from_slice(&destination.octets());
        packet.extend_from_slice(&50_000u16.to_be_bytes());
        packet.extend_from_slice(&853u16.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
        packet
    }

    fn udp_packet_v4(destination: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 36, 0, 1, 0x40, 0, 64, 17, 0, 0, 100, 64, 0, 2];
        packet.extend_from_slice(&destination.octets());
        packet.extend_from_slice(&50_000u16.to_be_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(&[0, 16, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        packet
    }

    /// Ones-complement sum over a buffer whose checksum field is filled in:
    /// a correct checksum folds to 0xffff.
    fn folds_to_ones(bytes: &[u8]) -> bool {
        let mut sum = bytes
            .chunks(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)])))
            .sum::<u32>();
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum == 0xffff
    }

    fn tcp_checksum_valid_v4(reply: &[u8]) -> bool {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&reply[12..20]);
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&reply[20..40]);
        folds_to_ones(&pseudo)
    }

    #[test]
    fn sinkhole_routes_cover_every_listed_address_in_both_families() {
        let routes = dns_sinkhole_route_targets();
        assert_eq!(routes.len(), DNS_SINKHOLE_ADDRESSES.len(), "an address failed to parse");
        assert!(routes.iter().any(|route| route == "8.8.8.8/32"));
        assert!(routes.iter().any(|route| route == "1.1.1.1/32"));
        assert!(routes.iter().any(|route| route == "2606:4700:4700::1111/128"));
        assert!(routes.iter().any(|route| route == "2001:4860:4860::8888/128"));
        assert!(
            routes.iter().all(|route| route.ends_with("/32") || route.ends_with("/128")),
            "sinkhole must only take host routes, never a prefix that could swallow real sites"
        );
    }

    #[test]
    fn sinkhole_passes_traffic_to_other_hosts() {
        let packet = tcp_packet_v4(Ipv4Addr::new(93, 184, 215, 14), TCP_SYN, 1, 0, &[]);
        assert_eq!(dns_sinkhole_verdict(&packet), DnsSinkholeVerdict::Pass);
        let stub = udp_packet_v4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER.parse().unwrap(), 53);
        assert_eq!(dns_sinkhole_verdict(&stub), DnsSinkholeVerdict::Pass);
    }

    #[test]
    fn sinkhole_resets_a_doh_connect_to_a_public_resolver() {
        let packet = tcp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), TCP_SYN, 1000, 0, &[]);
        let DnsSinkholeVerdict::Reply(reply) = dns_sinkhole_verdict(&packet) else {
            panic!("a SYN to a sinkholed resolver must be answered with a reset");
        };
        assert_eq!(reply.len(), 40);
        assert_eq!(&reply[12..16], &[8, 8, 8, 8], "reset comes from the resolver address");
        assert_eq!(&reply[16..20], &[100, 64, 0, 2], "reset goes back to the client");
        assert_eq!(&reply[20..22], &443u16.to_be_bytes());
        assert_eq!(&reply[22..24], &50_000u16.to_be_bytes());
        assert_eq!(reply[33], TCP_RST | TCP_ACK);
        assert_eq!(u32::from_be_bytes(reply[28..32].try_into().unwrap()), 1001, "ack covers the SYN");
        assert!(folds_to_ones(&reply[..20]), "IPv4 header checksum");
        assert!(tcp_checksum_valid_v4(&reply), "TCP checksum");
    }

    #[test]
    fn sinkhole_reset_for_established_segment_uses_peer_ack_as_sequence() {
        let packet = tcp_packet_v4(Ipv4Addr::new(1, 1, 1, 1), TCP_ACK, 5, 777, b"GET");
        let DnsSinkholeVerdict::Reply(reply) = dns_sinkhole_verdict(&packet) else {
            panic!("expected reset");
        };
        assert_eq!(reply[33], TCP_RST);
        assert_eq!(u32::from_be_bytes(reply[24..28].try_into().unwrap()), 777);
    }

    #[test]
    fn sinkhole_never_answers_a_reset_with_a_reset() {
        let packet = tcp_packet_v4(Ipv4Addr::new(1, 1, 1, 1), TCP_RST, 5, 0, &[]);
        assert_eq!(dns_sinkhole_verdict(&packet), DnsSinkholeVerdict::Drop);
    }

    #[test]
    fn sinkhole_drops_udp_to_a_public_resolver_on_any_port() {
        for port in [53, 443, 853, 5353] {
            let packet = udp_packet_v4(Ipv4Addr::new(9, 9, 9, 9), port);
            assert_eq!(dns_sinkhole_verdict(&packet), DnsSinkholeVerdict::Drop, "port {port}");
        }
    }

    #[test]
    fn sinkhole_resets_dot_to_an_ipv6_resolver() {
        let resolver: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let packet = tcp_packet_v6(resolver, TCP_SYN, 9);
        let DnsSinkholeVerdict::Reply(reply) = dns_sinkhole_verdict(&packet) else {
            panic!("expected reset");
        };
        assert_eq!(reply.len(), 60);
        assert_eq!(&reply[8..24], &resolver.octets());
        assert_eq!(reply[53], TCP_RST | TCP_ACK);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&reply[8..40]);
        pseudo.extend_from_slice(&[0, 0, 0, 20, 0, 0, 0, 6]);
        pseudo.extend_from_slice(&reply[40..60]);
        assert!(folds_to_ones(&pseudo), "TCP checksum over the IPv6 pseudo-header");
    }

    #[test]
    fn network_dns_override_routes_public_resolvers_into_the_sinkhole() {
        let (app, _) = mobile_network_dns_app(true);
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        for route in dns_sinkhole_route_targets() {
            assert!(
                config.route_targets.contains(&route),
                "{route} must enter the tunnel while the override is on"
            );
        }
    }

    #[test]
    fn sinkhole_routes_stay_off_without_the_override() {
        let (app, _) = mobile_network_dns_app(false);
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        assert!(
            !config.route_targets.iter().any(|route| route == "8.8.8.8/32"
                || route == "2606:4700:4700::1111/128"),
            "a device without the override must reach public resolvers directly, got {:?}",
            config.route_targets
        );
    }

    /// Runs one outbound batch through the real dispatcher with a WireGuard exit
    /// attached, and returns (packets sent to the exit, packets written back to
    /// the tun).
    fn dispatch_through_exit(dns_sinkhole: bool, packets: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("sinkhole dispatch test runtime");
        runtime.block_on(async {
            let keys = Keys::generate();
            let mobile = MobileTunnelConfig {
                identity_nsec: keys.secret_key().to_bech32().expect("mobile nsec"),
                network_id: "sinkhole-dispatch".to_string(),
                local_address: "100.64.0.2/32".to_string(),
                listen_port: available_udp_port(),
                ..empty_config()
            };
            let endpoint = bind_local_mobile_endpoint("nostr-vpn:sinkhole-dispatch", &mobile).await;
            let mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(Vec::new(), Vec::new()));
            let peer_identities = Arc::new(RwLock::new(MobilePeerIdentityMap::default()));
            let app = Arc::new(RwLock::new(AppConfig::generated()));
            let (wg_tx, mut wg_rx) = tokio_mpsc::channel(8);
            let (inbound_tx, mut inbound_rx) = tokio_mpsc::channel(8);
            let mut secure_dns: Option<MobileSecureDnsDispatch> = None;

            assert!(
                dispatch_mobile_outbound_packets(
                    &endpoint,
                    &mesh,
                    &peer_identities,
                    Some(&wg_tx),
                    None,
                    None,
                    &inbound_tx,
                    &app,
                    &mut secure_dns,
                    None,
                    None,
                    dns_sinkhole,
                    packets,
                )
                .await
            );
            drop(wg_tx);
            drop(inbound_tx);
            let mut to_exit = Vec::new();
            while let Some(batch) = wg_rx.recv().await {
                to_exit.extend(batch);
            }
            let mut to_tun = Vec::new();
            while let Some(batch) = inbound_rx.recv().await {
                to_tun.extend(batch);
            }
            endpoint.shutdown().await.expect("shutdown mobile endpoint");
            (to_exit, to_tun)
        })
    }

    #[test]
    fn dispatcher_refuses_public_resolvers_before_exit_routing_when_sinkhole_is_on() {
        let doh = tcp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), TCP_SYN, 1000, 0, &[]);
        let doq = udp_packet_v4(Ipv4Addr::new(9, 9, 9, 9), 853);
        let web = tcp_packet_v4(Ipv4Addr::new(93, 184, 215, 14), TCP_SYN, 1, 0, &[]);

        let (to_exit, to_tun) = dispatch_through_exit(true, vec![doh.clone(), doq, web.clone()]);

        assert_eq!(to_exit, vec![web], "only non-resolver traffic may reach the exit");
        assert_eq!(to_tun.len(), 1, "the DoH connect is answered with a reset");
        assert_eq!(&to_tun[0][12..16], &[8, 8, 8, 8]);
        assert_eq!(to_tun[0][33], TCP_RST | TCP_ACK);
    }

    #[test]
    fn dispatcher_leaves_public_resolvers_alone_when_sinkhole_is_off() {
        let doh = tcp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), TCP_SYN, 1000, 0, &[]);
        let (to_exit, to_tun) = dispatch_through_exit(false, vec![doh.clone()]);
        assert_eq!(to_exit, vec![doh]);
        assert!(to_tun.is_empty());
    }
