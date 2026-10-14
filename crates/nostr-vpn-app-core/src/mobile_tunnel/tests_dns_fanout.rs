    /// A DNS box on the far side of the tunnel: answers every query after
    /// `latency`, or never (asleep, off, unplugged).
    struct FakeDnsBox {
        address: Ipv4Addr,
        latency: Option<Duration>,
    }

    impl FakeDnsBox {
        fn healthy(address: Ipv4Addr, latency: Duration) -> Self {
            Self {
                address,
                latency: Some(latency),
            }
        }

        fn silent(address: Ipv4Addr) -> Self {
            Self {
                address,
                latency: None,
            }
        }
    }

    fn fan_out_nat(servers: &[Ipv4Addr]) -> MobileExitDnsNat {
        let local_dns = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();
        MobileExitDnsNat::new(local_dns, servers.to_vec()).expect("nameserver NAT")
    }

    fn packet_destination(packet: &[u8]) -> Ipv4Addr {
        Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap())
    }

    /// One lookup from the phone's stub through `nat` to `boxes`, the way the
    /// tunnel does it: the query is translated, every copy is delivered to
    /// the box it is addressed to, and each box's answer comes back through
    /// the NAT. The time until the phone holds an answer, and the box it came
    /// from; `None` when nothing usable arrives before `deadline`.
    fn lookup_through(
        nat: &MobileExitDnsNat,
        boxes: &[FakeDnsBox],
        client_port: u16,
        query_id: u16,
        deadline: Duration,
    ) -> Option<(Duration, Ipv4Addr)> {
        let local_dns = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();
        let start = Instant::now();
        let mut query = stub_query(client_port, query_id);
        let copies = nat.rewrite_query(&mut query)?;
        let (tx, rx) = std::sync::mpsc::channel();
        for packet in std::iter::once(query).chain(copies) {
            let destination = packet_destination(&packet);
            let dns_box = boxes
                .iter()
                .find(|dns_box| dns_box.address == destination)
                .expect("a copy went to an unlisted box");
            let Some(latency) = dns_box.latency else {
                continue;
            };
            let tx = tx.clone();
            let answer = dns_answer_v4(destination, client_port, query_id);
            std::thread::spawn(move || {
                std::thread::sleep(latency);
                let _ = tx.send(answer);
            });
        }
        drop(tx);
        while let Ok(mut answer) = rx.recv_timeout(deadline.saturating_sub(start.elapsed())) {
            let from = Ipv4Addr::from(<[u8; 4]>::try_from(&answer[12..16]).unwrap());
            if nat.deliver_response(&mut answer) && packet_destination(&answer) == CLIENT_V4 {
                assert_eq!(
                    &answer[12..16],
                    &local_dns.octets(),
                    "the phone sees the answer come from its stub"
                );
                return Some((start.elapsed(), from));
            }
        }
        None
    }

    const MAC: Ipv4Addr = Ipv4Addr::new(10, 44, 0, 10);
    const PI: Ipv4Addr = Ipv4Addr::new(10, 44, 0, 53);
    const BOX_LATENCY: Duration = Duration::from_millis(20);
    const LOOKUP_BUDGET: Duration = Duration::from_millis(500);

    /// Logen's Mac is asleep and the Pi is up. With the lookup copied to both,
    /// the phone gets the Pi's answer at the Pi's speed.
    ///
    /// The positive control is what phones did before this change: the
    /// config handed the forwarder only the first listed box. Through the
    /// same harness that lookup never comes back, so the bound is real.
    #[test]
    fn a_silent_box_and_a_healthy_box_answer_within_the_budget() {
        let boxes = [FakeDnsBox::silent(MAC), FakeDnsBox::healthy(PI, BOX_LATENCY)];

        let first_box_only = fan_out_nat(&[MAC]);
        assert_eq!(
            lookup_through(&first_box_only, &boxes, 50_000, 0x0101, LOOKUP_BUDGET),
            None,
            "positive control: the old first-box-only forwarder never answers"
        );
        assert_ne!(
            first_box_only.unanswered_since(),
            0,
            "and status would report the box as not answering"
        );

        let every_box = fan_out_nat(&[MAC, PI]);
        let (elapsed, from) = lookup_through(&every_box, &boxes, 50_000, 0x0102, LOOKUP_BUDGET)
            .expect("the Pi's answer reaches the phone");
        assert_eq!(from, PI);
        assert!(
            elapsed < LOOKUP_BUDGET,
            "answered in {elapsed:?}, budget {LOOKUP_BUDGET:?}"
        );
        assert_eq!(
            every_box.unanswered_since(),
            0,
            "one box answering is enough to keep status green"
        );
    }

    /// The order the admin listed the boxes in does not matter: neither is
    /// primary. The same lookup with the Mac listed second still comes back.
    #[test]
    fn box_order_does_not_decide_who_answers() {
        let boxes = [FakeDnsBox::healthy(PI, BOX_LATENCY), FakeDnsBox::silent(MAC)];
        let nat = fan_out_nat(&[PI, MAC]);
        let (_, from) = lookup_through(&nat, &boxes, 50_001, 0x0201, LOOKUP_BUDGET)
            .expect("answered");
        assert_eq!(from, PI);

        let nat = fan_out_nat(&[MAC, PI]);
        let (_, from) = lookup_through(&nat, &boxes, 50_002, 0x0202, LOOKUP_BUDGET)
            .expect("answered");
        assert_eq!(from, PI);
    }

    /// "Not answering" only when every box is silent.
    #[test]
    fn every_box_silent_is_the_only_way_to_stay_unanswered() {
        let boxes = [FakeDnsBox::silent(MAC), FakeDnsBox::silent(PI)];
        let nat = fan_out_nat(&[MAC, PI]);
        assert_eq!(
            lookup_through(&nat, &boxes, 50_003, 0x0301, Duration::from_millis(100)),
            None
        );
        assert_ne!(nat.unanswered_since(), 0);
    }

    /// Both boxes answer. The first answer is handed to the phone; the
    /// slower box's copy matches nothing and is dropped rather than handed to
    /// the phone's socket as a second datagram from a strange address.
    #[test]
    fn a_late_duplicate_answer_is_dropped() {
        let nat = fan_out_nat(&[MAC, PI]);
        let mut query = stub_query(50_004, 0x0401);
        let copies = nat.rewrite_query(&mut query).expect("stub query");
        assert_eq!(packet_destination(&query), MAC);
        assert_eq!(copies.len(), 1);
        assert_eq!(packet_destination(&copies[0]), PI);
        assert_eq!(flow_count(&nat), 2, "one flow per box");

        let mut first = dns_answer_v4(PI, 50_004, 0x0401);
        assert!(nat.deliver_response(&mut first), "the first answer is delivered");
        assert_eq!(flow_count(&nat), 0, "the answer consumed its siblings too");

        let mut late = dns_answer_v4(MAC, 50_004, 0x0401);
        let untouched = late.clone();
        assert!(!nat.deliver_response(&mut late), "the late copy is dropped");
        assert_eq!(late, untouched, "and not rewritten");

        // Only stray answers are dropped: other traffic from a box passes.
        let mut ssh = build_ipv4_udp_packet(MAC, CLIENT_V4, 22, 50_004, b"not dns").unwrap();
        assert!(nat.deliver_response(&mut ssh));
        let mut unrelated_dns = build_ipv4_udp_packet(Ipv4Addr::new(10, 44, 0, 99), CLIENT_V4, 53, 50_004, b"x").unwrap();
        assert!(nat.deliver_response(&mut unrelated_dns), "an unlisted host is not ours to drop");
    }

    /// TCP cannot be copied, so a new stream goes to the box that answered
    /// most recently: the one known to be awake.
    #[test]
    fn a_new_tcp_stream_goes_to_the_box_that_answered_last() {
        let nat = fan_out_nat(&[MAC, PI]);
        let local_dns = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();

        let mut syn = dns_tcp_v4(local_dns, CLIENT_V4, 40_000, 53, TCP_SYN);
        assert_eq!(nat.rewrite_query(&mut syn), Some(Vec::new()), "TCP is never copied");
        assert_eq!(packet_destination(&syn), MAC, "nothing answered yet: the first box");

        let mut query = stub_query(50_005, 0x0501);
        nat.rewrite_query(&mut query).unwrap();
        let mut answer = dns_answer_v4(PI, 50_005, 0x0501);
        assert!(nat.rewrite_response(&mut answer));

        let mut syn = dns_tcp_v4(local_dns, CLIENT_V4, 40_001, 53, TCP_SYN);
        nat.rewrite_query(&mut syn).unwrap();
        assert_eq!(packet_destination(&syn), PI, "the Pi answered last");
        let mut data = dns_tcp_v4(local_dns, CLIENT_V4, 40_001, 53, TCP_ACK);
        nat.rewrite_query(&mut data).unwrap();
        assert_eq!(packet_destination(&data), PI, "the stream stays on its box");
    }

    /// A port's guaranteed room counts lookups, not copies: an A and an AAAA
    /// through two boxes still fit when the table is under pressure.
    #[test]
    fn per_port_room_counts_lookups_not_copies() {
        let nat = fan_out_nat(&[MAC, PI]);
        let now = Instant::now();
        // Fill the shared half of the table from many ports.
        for port in 0..u16::try_from(MOBILE_DNS_FLOW_CAPACITY).unwrap() {
            let mut spray = dns_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 20_000 + port, port);
            nat.redirect_public_resolver_query_at(&mut spray, now);
        }
        let mut a = stub_query(60_000, 1);
        let mut aaaa = stub_query(60_000, 2);
        assert!(nat.rewrite_query(&mut a).is_some(), "the newcomer's A lookup");
        assert!(nat.rewrite_query(&mut aaaa).is_some(), "the newcomer's AAAA lookup");
        let mut third = stub_query(60_000, 3);
        assert!(nat.rewrite_query(&mut third).is_none(), "past the floor it shares the rest");
    }
