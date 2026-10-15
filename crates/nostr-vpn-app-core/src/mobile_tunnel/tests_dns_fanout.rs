    const LOOKUP_NAME: &str = "example.com";

    /// What a box says back.
    #[derive(Clone, Copy)]
    enum DnsReply {
        /// NOERROR with one A record.
        Real,
        /// NOERROR, no records.
        Empty,
        NxDomain,
        ServFail,
        Refused,
    }

    /// A query for `name` (type A) with a question section, unlike the
    /// header-only `dns_query_with_id`, so answers can carry an rcode and
    /// records and the forwarder can tell questions apart.
    fn dns_question_message(query_id: u16, name: &str) -> Vec<u8> {
        let mut message = query_id.to_be_bytes().to_vec();
        message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            message.push(u8::try_from(label.len()).unwrap());
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&[0, 1, 0, 1]);
        message
    }

    fn dns_reply_message(query_id: u16, name: &str, reply: DnsReply) -> Vec<u8> {
        let mut message = dns_question_message(query_id, name);
        message[2] = 0x81;
        message[3] = 0x80
            | match reply {
                DnsReply::Real | DnsReply::Empty => 0,
                DnsReply::NxDomain => 3,
                DnsReply::ServFail => 2,
                DnsReply::Refused => 5,
            };
        if matches!(reply, DnsReply::Real) {
            message[7] = 1;
            // Pointer to the question name, type A, class IN, TTL 60, 93.184.216.34.
            message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        }
        message
    }

    fn stub_lookup(client_port: u16, query_id: u16, name: &str) -> Vec<u8> {
        let stub = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();
        build_ipv4_udp_packet(CLIENT_V4, stub, client_port, 53, &dns_question_message(query_id, name))
            .unwrap()
    }

    fn box_reply(server: Ipv4Addr, client_port: u16, query_id: u16, name: &str, reply: DnsReply) -> Vec<u8> {
        build_ipv4_udp_packet(server, CLIENT_V4, 53, client_port, &dns_reply_message(query_id, name, reply))
            .unwrap()
    }

    fn rcode_of(packet: &[u8]) -> u8 {
        packet[28 + 3] & 0x0f
    }

    fn packet_source(packet: &[u8]) -> Ipv4Addr {
        Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap())
    }

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
        let mut query = stub_lookup(client_port, query_id, LOOKUP_NAME);
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
            let answer = box_reply(destination, client_port, query_id, LOOKUP_NAME, DnsReply::Real);
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
        let mut query = stub_lookup(50_004, 0x0401, LOOKUP_NAME);
        let copies = nat.rewrite_query(&mut query).expect("stub query");
        assert_eq!(packet_destination(&query), MAC);
        assert_eq!(copies.len(), 1);
        assert_eq!(packet_destination(&copies[0]), PI);
        assert_eq!(flow_count(&nat), 2, "one flow per box");

        let mut first = box_reply(PI, 50_004, 0x0401, LOOKUP_NAME, DnsReply::Real);
        assert!(nat.deliver_response(&mut first), "the first answer is delivered");
        assert_eq!(flow_count(&nat), 0, "the answer consumed its siblings too");

        let mut late = box_reply(MAC, 50_004, 0x0401, LOOKUP_NAME, DnsReply::Real);
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

        let mut query = stub_lookup(50_005, 0x0501, LOOKUP_NAME);
        nat.rewrite_query(&mut query).unwrap();
        let mut answer = box_reply(PI, 50_005, 0x0501, LOOKUP_NAME, DnsReply::Real);
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

    /// Logen's pick A: a fast "no such site" (or failure, or empty answer)
    /// from one box is held while another box's copy is still out, and a
    /// real answer that arrives inside the hold is what the phone gets.
    /// Before this, the first datagram won whatever it said, so a box that
    /// is up but broken beat the good box every time.
    #[test]
    fn a_fast_negative_answer_waits_for_a_real_one_from_another_box() {
        for negative in [DnsReply::NxDomain, DnsReply::ServFail, DnsReply::Refused, DnsReply::Empty] {
            let nat = fan_out_nat(&[MAC, PI]);
            let now = Instant::now();
            let mut query = stub_lookup(50_100, 0x1001, LOOKUP_NAME);
            nat.rewrite_query(&mut query).unwrap();

            let mut fast = box_reply(MAC, 50_100, 0x1001, LOOKUP_NAME, negative);
            assert!(
                !nat.rewrite_response_at(&mut fast, now),
                "the negative answer is held, not delivered"
            );
            assert_eq!(nat.unanswered_since(), 0, "a negative answer still proves the box is up");

            let mut real = box_reply(PI, 50_100, 0x1001, LOOKUP_NAME, DnsReply::Real);
            assert!(
                nat.rewrite_response_at(&mut real, now + Duration::from_millis(300)),
                "the real answer inside the hold is delivered"
            );
            assert_eq!(rcode_of(&real), 0);
            assert_eq!(packet_source(&real), parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap());
        }
    }

    /// Once the real answer went out, the held negative one is forgotten.
    #[test]
    fn a_real_answer_discards_the_held_negative_one() {
        let nat = fan_out_nat(&[MAC, PI]);
        let now = Instant::now();
        let mut query = stub_lookup(50_104, 0x1005, LOOKUP_NAME);
        nat.rewrite_query(&mut query).unwrap();
        let mut fast = box_reply(MAC, 50_104, 0x1005, LOOKUP_NAME, DnsReply::NxDomain);
        assert_eq!(nat.inbound_at(&mut fast, now), MobileDnsInbound::Drop);
        assert!(
            nat.release_expired_holds_at(now + Duration::from_millis(300)).is_empty(),
            "nothing is released inside the hold"
        );
        let mut real = box_reply(PI, 50_104, 0x1005, LOOKUP_NAME, DnsReply::Real);
        assert_eq!(
            nat.inbound_at(&mut real, now + Duration::from_millis(300)),
            MobileDnsInbound::Deliver
        );
        assert!(nat.release_expired_holds_at(now + MOBILE_DNS_NEGATIVE_ANSWER_HOLD).is_empty());
        assert_eq!(flow_count(&nat), 0);
    }

    /// With the other box silent, the negative answer is released once the
    /// hold runs out, and the silent box's late answer is then dropped.
    #[test]
    fn a_held_negative_answer_is_released_after_the_hold() {
        let nat = fan_out_nat(&[MAC, PI]);
        let now = Instant::now();
        let mut query = stub_lookup(50_101, 0x1002, LOOKUP_NAME);
        nat.rewrite_query(&mut query).unwrap();
        let mut fast = box_reply(MAC, 50_101, 0x1002, LOOKUP_NAME, DnsReply::NxDomain);
        assert_eq!(nat.inbound_at(&mut fast, now), MobileDnsInbound::Drop);

        let just_before = now + MOBILE_DNS_NEGATIVE_ANSWER_HOLD.checked_sub(Duration::from_millis(1)).unwrap();
        assert!(nat.release_expired_holds_at(just_before).is_empty());
        let released = nat.release_expired_holds_at(now + MOBILE_DNS_NEGATIVE_ANSWER_HOLD);
        assert_eq!(released.len(), 1, "the negative answer goes to the phone after the hold");
        assert_eq!(rcode_of(&released[0]), 3);
        assert_eq!(
            packet_source(&released[0]),
            parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap(),
            "rewritten so the phone sees it from its stub"
        );
        assert_eq!(flow_count(&nat), 0, "the silent box's copy is retired");
        assert!(nat.release_expired_holds_at(now + Duration::from_secs(10)).is_empty(), "released once");

        let mut late = box_reply(PI, 50_101, 0x1002, LOOKUP_NAME, DnsReply::Real);
        assert_eq!(
            nat.inbound_at(&mut late, now + Duration::from_secs(3)),
            MobileDnsInbound::Drop,
            "an answer to a question the phone already has an answer for is dropped"
        );
    }

    /// When every box says no there is nothing to wait for.
    #[test]
    fn every_box_saying_no_is_delivered_at_once() {
        let nat = fan_out_nat(&[MAC, PI]);
        let now = Instant::now();
        let mut query = stub_lookup(50_102, 0x1003, LOOKUP_NAME);
        nat.rewrite_query(&mut query).unwrap();
        let mut first = box_reply(MAC, 50_102, 0x1003, LOOKUP_NAME, DnsReply::NxDomain);
        assert_eq!(nat.inbound_at(&mut first, now), MobileDnsInbound::Drop);
        let mut second = box_reply(PI, 50_102, 0x1003, LOOKUP_NAME, DnsReply::ServFail);
        assert_eq!(
            nat.inbound_at(&mut second, now + Duration::from_millis(50)),
            MobileDnsInbound::Deliver,
            "the last box to answer completes the lookup"
        );
        assert_eq!(rcode_of(&second), 3, "the phone gets the first negative answer, not the later one");
        assert!(nat.release_expired_holds_at(now + MOBILE_DNS_NEGATIVE_ANSWER_HOLD).is_empty());
        assert_eq!(flow_count(&nat), 0);
    }

    /// The phone's resolver retransmits a lost first packet after about a
    /// second. The hold has to outlast that retransmit plus a mesh round
    /// trip, or the real answer to the retransmit arrives to find the
    /// negative one already delivered.
    #[test]
    fn a_real_answer_to_the_resolvers_retransmit_still_wins() {
        let retransmit_after = Duration::from_secs(1);
        let mesh_round_trip = Duration::from_millis(300);
        let nat = fan_out_nat(&[MAC, PI]);
        let now = Instant::now();
        let mut query = stub_lookup(50_103, 0x1004, LOOKUP_NAME);
        nat.rewrite_query(&mut query).unwrap();
        let mut fast = box_reply(MAC, 50_103, 0x1004, LOOKUP_NAME, DnsReply::NxDomain);
        assert_eq!(nat.inbound_at(&mut fast, now), MobileDnsInbound::Drop);

        // The first copy to the Pi was lost; the phone asks again.
        let mut retransmit = stub_lookup(50_103, 0x1004, LOOKUP_NAME);
        assert!(nat.rewrite_query(&mut retransmit).is_some());
        assert!(
            nat.release_expired_holds_at(now + retransmit_after).is_empty(),
            "the hold must not expire as the retransmit goes out"
        );
        let answered_at = now + retransmit_after + mesh_round_trip;
        assert!(nat.release_expired_holds_at(answered_at).is_empty());
        let mut real = box_reply(PI, 50_103, 0x1004, LOOKUP_NAME, DnsReply::Real);
        assert_eq!(nat.inbound_at(&mut real, answered_at), MobileDnsInbound::Deliver);
        assert_eq!(rcode_of(&real), 0);
    }

    /// Tron's sequence: port 1234 / txid 0x5555 asks name 1, box A answers,
    /// the phone reuses the same port and txid for name 2, and box B's late
    /// answer to name 1 arrives. It must not be delivered as the answer to
    /// name 2.
    #[test]
    fn a_stale_answer_never_lands_on_a_new_question() {
        let nat = fan_out_nat(&[MAC, PI]);
        let now = Instant::now();
        let mut first = stub_lookup(1234, 0x5555, "one.example");
        nat.rewrite_query(&mut first).unwrap();
        let mut answer = box_reply(MAC, 1234, 0x5555, "one.example", DnsReply::Real);
        assert!(nat.rewrite_response_at(&mut answer, now));

        let mut second = stub_lookup(1234, 0x5555, "two.example");
        nat.rewrite_query(&mut second).unwrap();
        let mut stale = box_reply(PI, 1234, 0x5555, "one.example", DnsReply::NxDomain);
        let untouched = stale.clone();
        assert!(
            !nat.rewrite_response_at(&mut stale, now + Duration::from_millis(10)),
            "box B's answer to the first question is not the answer to the second"
        );
        assert_eq!(stale, untouched);

        // A port-53 datagram that matches a live flow's port and id but not
        // its question is not the forwarder's answer either way.
        let mut never_asked = box_reply(PI, 1234, 0x5555, "three.example", DnsReply::Real);
        let untouched = never_asked.clone();
        assert!(!nat.rewrite_response_at(&mut never_asked, now + Duration::from_millis(20)));
        assert_eq!(never_asked, untouched);

        let mut real = box_reply(PI, 1234, 0x5555, "two.example", DnsReply::Real);
        assert!(nat.rewrite_response_at(&mut real, now + Duration::from_millis(30)));
        assert_eq!(rcode_of(&real), 0);
        assert_eq!(flow_count(&nat), 0);
    }

    /// A lookup the phone sends straight to a box's mesh address records no
    /// flow. Its answer is not the forwarder's to drop.
    #[test]
    fn a_direct_query_to_a_box_keeps_its_answer() {
        let nat = fan_out_nat(&[MAC, PI]);
        // Something else is in flight through the stub from the same port.
        let mut other = stub_lookup(40_000, 0x7777, LOOKUP_NAME);
        nat.rewrite_query(&mut other).unwrap();

        let mut direct = box_reply(MAC, 40_000, 0x7778, "direct.example", DnsReply::Real);
        let untouched = direct.clone();
        assert!(nat.deliver_response(&mut direct), "a direct query's answer reaches the phone");
        assert_eq!(direct, untouched, "and is not rewritten");
    }
