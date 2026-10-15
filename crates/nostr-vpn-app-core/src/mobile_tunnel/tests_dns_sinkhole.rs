    fn tcp_packet_v4(destination: Ipv4Addr, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut packet = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 6, 0, 0, 100, 64, 0, 2];
        packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
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

    fn udp_checksum_valid_v4(packet: &[u8]) -> bool {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.extend_from_slice(&[0, 17, packet[24], packet[25]]);
        pseudo.extend_from_slice(&packet[20..]);
        folds_to_ones(&pseudo)
    }

    #[test]
    fn sinkhole_routes_cover_every_listed_address_in_both_families() {
        let routes = dns_sinkhole_route_targets();
        let listed_ipv4 = DNS_SINKHOLE_ADDRESSES
            .iter()
            .filter(|address| address.parse::<Ipv4Addr>().is_ok())
            .count();
        assert_eq!(
            routes.len(),
            DNS_SINKHOLE_ADDRESSES.len() + listed_ipv4,
            "an address failed to parse, or an IPv4 resolver lost its NAT64 route"
        );
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
        assert_eq!(
            config.local_address_ipv6, MOBILE_SINKHOLE_LOCAL_IPV6,
            "IPv6 resolver routes need an IPv6 address on the tun"
        );
        // Not raised to IPv6's 1280: the 1150 tun MTU is derived from the
        // 1280 underlay budget, and a bigger inner packet overruns it on
        // cellular. Whether Android still carries the IPv6 address at 1150
        // is for the device to show.
        assert_eq!(config.mtu, nostr_vpn_core::MESH_TUNNEL_MTU);
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
        assert!(config.local_address_ipv6.is_empty());
        assert_eq!(config.mtu, nostr_vpn_core::MESH_TUNNEL_MTU, "no IPv6 on the tun, no MTU change");
    }

    /// Runs one outbound batch through the real dispatcher with a `WireGuard` exit
    /// attached, and returns (packets sent to the exit, packets written back to
    /// the tun).
    fn dispatch_through_exit(dns_sinkhole: bool, packets: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        dispatch_through_exit_with_nat(dns_sinkhole, None, packets)
    }

    fn dispatch_through_exit_with_nat(
        dns_sinkhole: bool,
        exit_dns_nat: Option<&MobileExitDnsNat>,
        packets: Vec<Vec<u8>>,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
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
                    exit_dns_nat,
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

    fn nat64(address: Ipv4Addr) -> std::net::Ipv6Addr {
        format!("64:ff9b::{address}").parse().expect("synthesized address")
    }

    /// Tron's probe: on an IPv6-only carrier with DNS64, `dns.google` resolves
    /// to `64:ff9b::808:808`, which used to walk past every /32 and /128.
    #[test]
    fn sinkhole_refuses_nat64_synthesized_resolver_addresses() {
        let routes = dns_sinkhole_route_targets();
        assert!(routes.iter().any(|route| route == "64:ff9b::808:808/128"));
        assert!(routes.iter().any(|route| route == "64:ff9b::101:101/128"));
        assert!(
            !routes.iter().any(|route| route.starts_with("64:ff9b::/")),
            "routing the whole prefix would capture every IPv4-literal flow on 464XLAT"
        );

        let doh = tcp_packet_v6(nat64(Ipv4Addr::new(8, 8, 8, 8)), TCP_SYN, 9);
        let DnsSinkholeVerdict::Reply(reply) = dns_sinkhole_verdict(&doh) else {
            panic!("a SYN to a synthesized resolver address must be reset");
        };
        assert_eq!(&reply[8..24], &nat64(Ipv4Addr::new(8, 8, 8, 8)).octets());

        let web = tcp_packet_v6(nat64(Ipv4Addr::new(93, 184, 215, 14)), TCP_SYN, 9);
        assert_eq!(
            dns_sinkhole_verdict(&web),
            DnsSinkholeVerdict::Pass,
            "a synthesized address for an ordinary site must pass"
        );
    }

    fn nameserver_nat(nameserver: Ipv4Addr) -> MobileExitDnsNat {
        let local_dns = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();
        MobileExitDnsNat::new(local_dns, vec![nameserver]).expect("nameserver NAT")
    }

    /// Hard-coded `8.8.8.8:53` lands in the nameserver's log and keeps working,
    /// instead of costing the app a full timeout per lookup.
    #[test]
    fn plain_dns_to_a_public_resolver_is_redirected_to_the_nameserver() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let google = Ipv4Addr::new(8, 8, 8, 8);
        let mut query = udp_packet_v4(google, 53);

        assert_eq!(
            nat.redirect_public_resolver_query(&mut query),
            Some(Vec::new()),
            "one box, so no further copies"
        );
        assert_eq!(&query[16..20], &nameserver.octets());
        assert_ne!(nat.unanswered_since(), 0, "a forwarded query is awaiting its answer");

        let mut answer = query.clone();
        answer[12..16].copy_from_slice(&nameserver.octets());
        answer[16..20].copy_from_slice(&[100, 64, 0, 2]);
        answer[20..22].copy_from_slice(&53u16.to_be_bytes());
        answer[22..24].copy_from_slice(&50_000u16.to_be_bytes());
        assert!(nat.rewrite_response(&mut answer));
        assert_eq!(&answer[12..16], &google.octets(), "the answer comes back from 8.8.8.8");
        assert_eq!(nat.unanswered_since(), 0, "an answer clears the alarm");
    }

    #[test]
    fn only_plain_dns_to_a_listed_resolver_is_redirected() {
        let nat = nameserver_nat(Ipv4Addr::new(10, 44, 0, 53));
        let mut dot = udp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), 853);
        let mut doh = tcp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), TCP_SYN, 1, 0, &[]);
        let mut unlisted = udp_packet_v4(Ipv4Addr::new(77, 88, 8, 8), 53);

        assert_eq!(nat.redirect_public_resolver_query(&mut dot), None);
        assert_eq!(nat.redirect_public_resolver_query(&mut doh), None);
        assert_eq!(nat.redirect_public_resolver_query(&mut unlisted), None);
        assert_eq!(nat.unanswered_since(), 0);
    }

    #[test]
    fn dispatcher_redirects_plain_dns_and_still_refuses_encrypted_dns() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let plain = udp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let doh = tcp_packet_v4(Ipv4Addr::new(8, 8, 8, 8), TCP_SYN, 1000, 0, &[]);

        let (to_exit, to_tun) =
            dispatch_through_exit_with_nat(true, Some(&nat), vec![plain, doh]);

        assert_eq!(to_exit.len(), 1, "the plain query is forwarded, not dropped");
        assert_eq!(&to_exit[0][16..20], &nameserver.octets());
        assert_eq!(to_tun.len(), 1, "the DoH connect is still reset");
        assert_eq!(to_tun[0][33], TCP_RST | TCP_ACK);
    }

    /// The nameserver leaving the roster used to clear the override, and the
    /// phone went back to carrier DNS with the VPN still connected.
    #[test]
    fn override_with_no_nameserver_keeps_owning_dns_and_forwards_nowhere() {
        let (mut app, pihole) = mobile_network_dns_app(true);
        app.networks[0].devices.retain(|device| device != &pihole);
        app.ensure_defaults();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert!(config.network_dns_unavailable);
        assert!(config.network_dns_servers.is_empty(), "there is no nameserver to forward to");
        assert_eq!(config.dns_match_domains, vec![String::new()], "all domains stay in the tunnel");
        assert_eq!(config.dns_servers, vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER.to_string()]);
        for route in dns_sinkhole_route_targets() {
            assert!(config.route_targets.contains(&route), "{route} must stay sinkholed");
        }
        assert_eq!(
            mobile_dns_upstream(&config).expect("dns upstream"),
            MobileDnsUpstream::Nowhere,
            "no NAT and no DoH fallback with no nameserver"
        );
    }

    /// Same with an exit selected: exit DNS would resolve around the override.
    #[test]
    fn override_with_no_nameserver_forwards_nowhere_even_through_an_exit() {
        let (mut app, pihole) = mobile_network_dns_app(true);
        app.networks[0].devices.retain(|device| device != &pihole);
        app.ensure_defaults();
        let mut config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        config.route_targets.push("0.0.0.0/0".to_string());

        assert_eq!(mobile_dns_upstream(&config).expect("dns upstream"), MobileDnsUpstream::Nowhere);
    }

    #[test]
    fn override_with_a_nameserver_nats_to_it() {
        let (app, pihole) = mobile_network_dns_app(true);
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        assert!(!config.network_dns_unavailable);
        assert_eq!(
            mobile_dns_upstream(&config).expect("dns upstream"),
            MobileDnsUpstream::Nat(vec![expected_mobile_nameserver(&app, &pihole)])
        );
    }

    #[test]
    fn override_off_is_not_unavailable() {
        let (app, _) = mobile_network_dns_app(false);
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        assert!(!config.network_dns_unavailable);
        assert_eq!(mobile_dns_upstream(&config).expect("dns upstream"), MobileDnsUpstream::SecureDns);
    }

    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    fn dns_udp_v4(destination: Ipv4Addr, client_port: u16, query_id: u16) -> Vec<u8> {
        build_ipv4_udp_packet(CLIENT_V4, destination, client_port, 53, &dns_query_with_id(query_id))
            .expect("query packet")
    }

    fn dns_answer_v4(server: Ipv4Addr, client_port: u16, query_id: u16) -> Vec<u8> {
        build_ipv4_udp_packet(server, CLIENT_V4, 53, client_port, &dns_query_with_id(query_id))
            .expect("answer packet")
    }

    fn dns_query_with_id(query_id: u16) -> Vec<u8> {
        let mut message = query_id.to_be_bytes().to_vec();
        message.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        message
    }

    fn dns_tcp_v4(destination: Ipv4Addr, source: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut packet = tcp_packet_v4(destination, flags, 1, 0, &[]);
        packet[12..16].copy_from_slice(&source.octets());
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&dport.to_be_bytes());
        packet
    }

    /// The entry count, after checking the running counters admission reads
    /// against a full recount of the table.
    fn flow_count(nat: &MobileExitDnsNat) -> usize {
        let table = nat.flows.lock().unwrap();
        let mut per_port = HashMap::new();
        for flow in table.entries.keys() {
            *per_port.entry(flow.client_port).or_insert(0_usize) += 1;
        }
        let redirected = table.entries.values().filter(|entry| entry.origin.is_redirect()).count();
        assert_eq!(table.per_port, per_port, "per-port counts drifted from the table");
        assert_eq!(table.redirected, redirected, "redirect count drifted from the table");
        table.entries.len()
    }

    fn stub_query(client_port: u16, query_id: u16) -> Vec<u8> {
        dns_udp_v4(parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap(), client_port, query_id)
    }

    /// Box off answers nothing, and any app can spray UDP/53 at 8.8.8.8: the
    /// table must stay bounded for as long as the tunnel is up.
    #[test]
    fn unanswered_redirects_never_grow_the_flow_table_past_its_cap() {
        let nat = nameserver_nat(Ipv4Addr::new(10, 44, 0, 53));
        let now = Instant::now();
        for index in 0..10_000_u32 {
            let port = 20_000 + u16::try_from(index % 40_000).unwrap();
            let mut query = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), port, u16::try_from(index % 65_536).unwrap());
            nat.redirect_public_resolver_query_at(&mut query, now);
        }
        assert_eq!(flow_count(&nat), MOBILE_DNS_REDIRECT_CAPACITY);
        for index in 0..10_000_u16 {
            let mut query = stub_query(30_000 + index, index);
            nat.rewrite_query(&mut query);
        }
        assert_eq!(flow_count(&nat), MOBILE_DNS_FLOW_CAPACITY);
    }

    /// Tron's 15: one socket issuing 2048 queries used to evict another
    /// app's pending lookup, whose answer then matched nothing while the
    /// status line stayed green.
    #[test]
    fn one_socket_cannot_take_more_than_its_share() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let now = Instant::now();
        let mut victim = dns_udp_v4(Ipv4Addr::new(1, 1, 1, 1), 41_000, 0xbeef);
        nat.redirect_public_resolver_query_at(&mut victim, now).unwrap();
        let admitted = (0..2048_u16)
            .filter(|query_id| {
                let mut spray = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 50_000, *query_id);
                nat.redirect_public_resolver_query_at(&mut spray, now).is_some()
            })
            .count();
        assert_eq!(admitted, MOBILE_DNS_FLOWS_PER_PORT);

        let mut answer = dns_answer_v4(nameserver, 41_000, 0xbeef);
        assert!(
            nat.rewrite_response_at(&mut answer, now + Duration::from_secs(2)),
            "the other app's lookup survives the spray"
        );
        assert_eq!(&answer[12..16], &[1, 1, 1, 1]);
    }

    /// Tron's 17: one flow per port on low port numbers used to make a real
    /// app with several lookups in flight the preferred eviction victim. Now
    /// nothing live is evicted, and the stub keeps room for the system
    /// resolver whatever the redirect path is doing.
    #[test]
    fn a_many_port_spray_never_evicts_live_lookups_or_starves_the_stub() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let now = Instant::now();
        for query_id in 0..4_u16 {
            let mut lookup = dns_udp_v4(Ipv4Addr::new(1, 1, 1, 1), 45_000, query_id);
            nat.redirect_public_resolver_query_at(&mut lookup, now).unwrap();
        }
        for port in 1025..1025 + 4096_u16 {
            let mut spray = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), port, 7);
            nat.redirect_public_resolver_query_at(&mut spray, now);
        }
        for query_id in 0..4_u16 {
            let mut answer = dns_answer_v4(nameserver, 45_000, query_id);
            assert!(
                nat.rewrite_response_at(&mut answer, now + Duration::from_secs(2)),
                "lookup {query_id} was evicted"
            );
        }
        let mut system = stub_query(46_000, 0x5150);
        assert!(nat.rewrite_query(&mut system).is_some(), "the stub still has room");
    }

    /// Even a spray through the stub, which looks exactly like the system
    /// resolver, fills the table and then gets refused; it never pushes out a
    /// lookup that is already waiting for its answer.
    #[test]
    fn a_full_table_refuses_newcomers_instead_of_evicting() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let mut waiting = stub_query(45_000, 0x0bad);
        assert!(nat.rewrite_query(&mut waiting).is_some());
        let admitted = (0..4096_u16)
            .filter(|index| {
                let mut spray = stub_query(1025 + index, 7);
                nat.rewrite_query(&mut spray).is_some()
            })
            .count();
        assert_eq!(admitted, MOBILE_DNS_FLOW_CAPACITY - 1);
        let mut answer = dns_answer_v4(nameserver, 45_000, 0x0bad);
        assert!(nat.rewrite_response(&mut answer), "the waiting lookup was evicted");
    }

    /// Tron's 20: 32 sockets through the stub, 32 flows each, used to fill
    /// the table and lock every new lookup out. Flows past a port's floor now
    /// share only half the table, so a newcomer still gets its A and AAAA.
    #[test]
    fn a_stub_spray_from_32_sockets_leaves_room_for_a_newcomer() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        for port in 1025..1025 + 32_u16 {
            for query_id in 0..32_u16 {
                let mut spray = stub_query(port, query_id);
                nat.rewrite_query(&mut spray);
            }
        }
        assert!(flow_count(&nat) < MOBILE_DNS_FLOW_CAPACITY);
        let mut a = stub_query(46_000, 1);
        let mut aaaa = stub_query(46_000, 2);
        assert!(nat.rewrite_query(&mut a).is_some(), "the newcomer's first lookup");
        assert!(nat.rewrite_query(&mut aaaa).is_some(), "the newcomer's second lookup");
        let mut answer = dns_answer_v4(nameserver, 46_000, 1);
        assert!(nat.rewrite_response(&mut answer));
    }

    /// What is left of 20: a sprayer can still fill the table, but only by
    /// holding a floor's worth on hundreds of sockets, not 32.
    #[test]
    fn filling_the_table_through_the_stub_takes_hundreds_of_sockets() {
        let nat = nameserver_nat(Ipv4Addr::new(10, 44, 0, 53));
        let mut sockets = 0;
        for port in 1025..1025 + 4096_u16 {
            if flow_count(&nat) >= MOBILE_DNS_FLOW_CAPACITY {
                break;
            }
            sockets += 1;
            for query_id in 0..32_u16 {
                let mut spray = stub_query(port, query_id);
                nat.rewrite_query(&mut spray);
            }
        }
        assert_eq!(flow_count(&nat), MOBILE_DNS_FLOW_CAPACITY);
        assert!(sockets >= 256, "the table filled after only {sockets} sockets");
    }

    /// A key reused after expiry by a query to a different origin moves the
    /// redirect count with it.
    #[test]
    fn counts_follow_a_reused_key_across_origins() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let start = Instant::now();
        let mut redirected = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 50_000, 7);
        nat.redirect_public_resolver_query_at(&mut redirected, start).unwrap();
        assert_eq!(nat.flows.lock().unwrap().redirected, 1);
        // One nameserver, so the stub query lands on the same key.
        let later = start + MOBILE_DNS_UDP_FLOW_TTL + Duration::from_secs(1);
        let stub = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();
        // A sweep would just drop the dead flow; reach the reuse path instead.
        nat.flows.lock().unwrap().last_sweep = later;
        let mut query = stub_query(50_000, 7);
        nat.translate_query(&mut query, stub, later).unwrap();
        assert_eq!(flow_count(&nat), 1);
        assert_eq!(nat.flows.lock().unwrap().redirected, 0);
    }

    #[test]
    fn unanswered_udp_flows_expire() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let start = Instant::now();
        let mut query = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 50_000, 7);
        nat.redirect_public_resolver_query_at(&mut query, start).unwrap();

        let later = start + MOBILE_DNS_UDP_FLOW_TTL + Duration::from_secs(1);
        let mut late_answer = dns_answer_v4(nameserver, 50_000, 7);
        assert!(!nat.rewrite_response_at(&mut late_answer, later), "a dead flow is not revived");

        let mut other = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 50_001, 8);
        nat.redirect_public_resolver_query_at(&mut other, start).unwrap();
        let mut trigger = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 50_002, 9);
        nat.redirect_public_resolver_query_at(&mut trigger, later).unwrap();
        assert_eq!(flow_count(&nat), 1, "the sweep drops expired flows on its own");
    }

    /// Tron's probe: 8.8.8.8 then 1.1.1.1 from one port used to overwrite each
    /// other, and the single answer came back as 1.1.1.1.
    #[test]
    fn answers_go_back_to_the_resolver_each_query_was_sent_to() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let google = Ipv4Addr::new(8, 8, 8, 8);
        let cloudflare = Ipv4Addr::new(1, 1, 1, 1);
        let mut first = dns_udp_v4(google, 55_000, 0x1111);
        let mut second = dns_udp_v4(cloudflare, 55_000, 0x2222);
        nat.redirect_public_resolver_query(&mut first).unwrap();
        nat.redirect_public_resolver_query(&mut second).unwrap();

        let mut answer_first = dns_answer_v4(nameserver, 55_000, 0x1111);
        let mut answer_second = dns_answer_v4(nameserver, 55_000, 0x2222);
        assert!(nat.rewrite_response(&mut answer_first));
        assert!(nat.rewrite_response(&mut answer_second));
        assert_eq!(&answer_first[12..16], &google.octets());
        assert_eq!(&answer_second[12..16], &cloudflare.octets());

        let mut duplicate = dns_answer_v4(nameserver, 55_000, 0x1111);
        assert!(!nat.rewrite_response(&mut duplicate), "a UDP answer consumes its flow");
    }

    #[test]
    fn a_colliding_query_is_refused_rather_than_cross_wired() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let mut first = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 55_000, 0x1111);
        let mut clash = dns_udp_v4(Ipv4Addr::new(1, 1, 1, 1), 55_000, 0x1111);
        nat.redirect_public_resolver_query(&mut first).unwrap();
        assert_eq!(nat.redirect_public_resolver_query(&mut clash), None);

        let mut answer = dns_answer_v4(nameserver, 55_000, 0x1111);
        assert!(nat.rewrite_response(&mut answer));
        assert_eq!(&answer[12..16], &[8, 8, 8, 8], "the first query still owns its answer");
    }

    #[test]
    fn tcp_flows_close_on_reset_and_after_fin() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver);
        let google = Ipv4Addr::new(8, 8, 8, 8);
        let start = Instant::now();

        let mut syn = dns_tcp_v4(google, CLIENT_V4, 40_000, 53, TCP_SYN);
        nat.redirect_public_resolver_query_at(&mut syn, start).unwrap();
        let mut reset = dns_tcp_v4(CLIENT_V4, nameserver, 53, 40_000, TCP_RST);
        assert!(nat.rewrite_response_at(&mut reset, start));
        assert_eq!(flow_count(&nat), 0, "a reset ends the stream");
        let mut stale = dns_tcp_v4(CLIENT_V4, nameserver, 53, 40_000, TCP_ACK);
        assert!(!nat.rewrite_response_at(&mut stale, start), "a stale duplicate matches nothing");

        let mut syn = dns_tcp_v4(google, CLIENT_V4, 40_001, 53, TCP_SYN);
        nat.redirect_public_resolver_query_at(&mut syn, start).unwrap();
        let mut fin = dns_tcp_v4(CLIENT_V4, nameserver, 53, 40_001, TCP_FIN | TCP_ACK);
        assert!(nat.rewrite_response_at(&mut fin, start));
        let mut last_ack = dns_tcp_v4(google, CLIENT_V4, 40_001, 53, TCP_ACK);
        let after_grace = start + MOBILE_DNS_TCP_FLOW_CLOSING + Duration::from_secs(1);
        let mut late = dns_tcp_v4(CLIENT_V4, nameserver, 53, 40_001, TCP_ACK);
        assert!(nat.redirect_public_resolver_query_at(&mut last_ack, start).is_some());
        assert!(!nat.rewrite_response_at(&mut late, after_grace), "FIN leaves only a short grace");
    }

    #[test]
    fn a_second_tcp_stream_on_the_same_port_is_refused() {
        let nat = nameserver_nat(Ipv4Addr::new(10, 44, 0, 53));
        let mut first = dns_tcp_v4(Ipv4Addr::new(8, 8, 8, 8), CLIENT_V4, 40_000, 53, TCP_SYN);
        let mut second = dns_tcp_v4(Ipv4Addr::new(1, 1, 1, 1), CLIENT_V4, 40_000, 53, TCP_SYN);
        assert!(nat.redirect_public_resolver_query(&mut first).is_some());
        assert_eq!(nat.redirect_public_resolver_query(&mut second), None);
    }

    fn dns_udp_v6(destination: std::net::Ipv6Addr, client_port: u16, query_id: u16) -> Vec<u8> {
        build_ipv6_udp_packet(
            "fd00::2".parse().unwrap(),
            destination,
            client_port,
            53,
            &dns_query_with_id(query_id),
        )
        .expect("ipv6 query")
    }

    fn udp_checksum_valid_v6(packet: &[u8]) -> bool {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[8..40]);
        pseudo.extend_from_slice(&[0, 0, packet[4], packet[5], 0, 0, 0, 17]);
        pseudo.extend_from_slice(&packet[40..]);
        folds_to_ones(&pseudo)
    }

    /// Tron's probe: UDP/53 to `2001:4860:4860::8888` was dropped, so on an
    /// IPv6 carrier a hard-coded resolver cost a timeout and never reached
    /// the nameserver.
    #[test]
    fn plain_dns_to_an_ipv6_resolver_is_redirected_and_answered_over_ipv6() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver).with_ipv4_source(Some(CLIENT_V4));
        for resolver in [
            "2001:4860:4860::8888".parse::<std::net::Ipv6Addr>().unwrap(),
            nat64(Ipv4Addr::new(8, 8, 8, 8)),
        ] {
            let mut query = dns_udp_v6(resolver, 51_000, 0x4242);
            assert_eq!(
            nat.redirect_public_resolver_query(&mut query),
            Some(Vec::new()),
            "one box, so no further copies"
        );
            assert_eq!(query[0] >> 4, 4, "carried to the nameserver over IPv4");
            assert_eq!(&query[12..16], &CLIENT_V4.octets());
            assert_eq!(&query[16..20], &nameserver.octets());
            assert_eq!(&query[28..30], &0x4242_u16.to_be_bytes());

            let mut answer = dns_answer_v4(nameserver, 51_000, 0x4242);
            assert!(nat.rewrite_response(&mut answer));
            assert_eq!(answer[0] >> 4, 6, "the answer goes back as IPv6");
            assert_eq!(&answer[8..24], &resolver.octets(), "from the resolver it asked");
            assert_eq!(&answer[24..40], &"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
            assert_eq!(&answer[40..42], &53u16.to_be_bytes());
            assert_eq!(&answer[42..44], &51_000u16.to_be_bytes());
            assert!(udp_checksum_valid_v6(&answer));
        }
    }

    fn dns_query_with_edns(query_id: u16, udp_size: u16) -> Vec<u8> {
        let mut message = query_id.to_be_bytes().to_vec();
        message.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        message.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        message.extend_from_slice(&[0, 16, 0, 1]);
        message.extend_from_slice(&[0, 0, 41]);
        message.extend_from_slice(&udp_size.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
        message
    }

    /// Tron's 16: an answer that fits the tun as IPv4 is 20 bytes too big
    /// once rebuilt as IPv6. The query asks for no more than fits, and an
    /// answer that is too big anyway comes back truncated with TC set.
    #[test]
    fn ipv6_redirected_answers_never_outgrow_the_tun_mtu() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let mtu = 1150_u16;
        let nat = nameserver_nat(nameserver)
            .with_ipv4_source(Some(CLIENT_V4))
            .with_mtu(mtu);
        let google = "2001:4860:4860::8888".parse::<std::net::Ipv6Addr>().unwrap();
        let client: std::net::Ipv6Addr = "fd00::2".parse().unwrap();

        let mut query =
            build_ipv6_udp_packet(client, google, 52_000, 53, &dns_query_with_edns(0x5151, 4096))
                .unwrap();
        nat.redirect_public_resolver_query(&mut query).unwrap();
        let edns_size = &query[query.len() - 8..query.len() - 6];
        assert_eq!(edns_size, &(mtu - 48).to_be_bytes(), "EDNS size clamped to what fits as IPv6");
        assert!(udp_checksum_valid_v4(&query), "checksum covers the clamped size");

        // Exactly the tun MTU as IPv4: 1150 - 28 bytes of DNS.
        let mut big = dns_query_with_edns(0x5151, 4096);
        big[2] = 0x81;
        big.resize(usize::from(mtu) - 28, 0);
        let mut answer = build_ipv4_udp_packet(nameserver, CLIENT_V4, 53, 52_000, &big).unwrap();
        assert_eq!(answer.len(), usize::from(mtu));
        assert!(nat.rewrite_response(&mut answer));
        assert!(answer.len() <= usize::from(mtu), "rebuilt answer is {} bytes", answer.len());
        assert_ne!(answer[48 + 2] & 0x02, 0, "TC tells the client the answer was cut");
        assert_eq!(&answer[48 + 4..48 + 6], &[0, 1], "the question is kept");
        assert_eq!(&answer[48 + 6..48 + 12], &[0; 6], "no partial records");
        assert!(udp_checksum_valid_v6(&answer));

        let mut small = build_ipv6_udp_packet(client, google, 52_001, 53, &dns_query_with_id(9)).unwrap();
        nat.redirect_public_resolver_query(&mut small).unwrap();
        let mut ordinary = dns_answer_v4(nameserver, 52_001, 9);
        assert!(nat.rewrite_response(&mut ordinary));
        assert_eq!(ordinary[48 + 2] & 0x02, 0, "an answer that fits is untouched");
    }

    #[test]
    fn ipv6_redirect_needs_a_tunnel_ipv4_and_a_listed_resolver() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let google = "2001:4860:4860::8888".parse::<std::net::Ipv6Addr>().unwrap();
        let mut query = dns_udp_v6(google, 51_000, 1);
        assert_eq!(nameserver_nat(nameserver).redirect_public_resolver_query(&mut query), None);

        let nat = nameserver_nat(nameserver).with_ipv4_source(Some(CLIENT_V4));
        let mut unlisted = dns_udp_v6("2a02:6b8::feed:0ff".parse().unwrap(), 51_000, 1);
        assert_eq!(nat.redirect_public_resolver_query(&mut unlisted), None);
        let mut dot = dns_udp_v6(google, 51_000, 1);
        dot[42..44].copy_from_slice(&853u16.to_be_bytes());
        assert_eq!(nat.redirect_public_resolver_query(&mut dot), None);
    }

    #[test]
    fn dispatcher_redirects_ipv6_plain_dns_to_the_nameserver() {
        let nameserver = Ipv4Addr::new(10, 44, 0, 53);
        let nat = nameserver_nat(nameserver).with_ipv4_source(Some(CLIENT_V4));
        let google = "2001:4860:4860::8888".parse::<std::net::Ipv6Addr>().unwrap();
        let plain = dns_udp_v6(google, 51_000, 9);

        let (to_exit, to_tun) = dispatch_through_exit_with_nat(true, Some(&nat), vec![plain]);

        assert_eq!(to_exit.len(), 1, "the IPv6 query is forwarded, not dropped");
        assert_eq!(&to_exit[0][16..20], &nameserver.octets());
        assert!(to_tun.is_empty());
    }
