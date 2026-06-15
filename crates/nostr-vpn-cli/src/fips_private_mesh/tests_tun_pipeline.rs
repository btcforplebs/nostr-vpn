    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_ipv6_tcp_packet(flags: u8, tcp_payload_len: usize) -> Vec<u8> {
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[40 + 12] = 5 << 4;
        packet[40 + 13] = flags;
        packet
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_ipv6_udp_packet(payload_len: usize) -> Vec<u8> {
        let udp_len = 8 + payload_len;
        let mut packet = vec![0u8; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = 17;
        packet
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_ipv4_icmp_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 1;
        packet[20] = 8;
        packet
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_pipeline_packet(bytes: Vec<u8>) -> TunPipelinePacket {
        TunPipelinePacket::new(bytes)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tun_to_mesh_classifier_reserves_liveness_and_tcp_control_packets() {
        assert_eq!(
            tun_pipeline_packet_lane(&test_ipv4_icmp_packet()),
            TunPipelineLane::Priority
        );

        let mut icmpv6 = vec![0u8; 48];
        icmpv6[0] = 0x60;
        icmpv6[4..6].copy_from_slice(&8u16.to_be_bytes());
        icmpv6[6] = 58;
        assert_eq!(tun_pipeline_packet_lane(&icmpv6), TunPipelineLane::Priority);

        assert_eq!(
            tun_pipeline_packet_lane(&test_ipv6_tcp_packet(0x10, 0)),
            TunPipelineLane::Priority
        );
        assert_eq!(
            tun_pipeline_packet_lane(&test_ipv6_tcp_packet(0x02, 0)),
            TunPipelineLane::Priority
        );
        assert_eq!(
            tun_pipeline_packet_lane(&test_ipv6_tcp_packet(0x18, 64)),
            TunPipelineLane::Priority
        );
        assert_eq!(
            tun_pipeline_packet_lane(&test_ipv6_tcp_packet(0x18, 512)),
            TunPipelineLane::Bulk
        );
        assert_eq!(
            tun_pipeline_packet_lane(&test_ipv6_udp_packet(8)),
            TunPipelineLane::Bulk
        );
        assert_eq!(tun_pipeline_packet_lane(&[0xaa; 32]), TunPipelineLane::Bulk);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn full_tun_to_mesh_queue_drops_bulk_without_waiting() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(1);

        let first = vec![test_pipeline_packet(test_ipv6_tcp_packet(0x18, 512))];
        let second = vec![test_pipeline_packet(test_ipv6_tcp_packet(0x18, 512))];

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, first),
            TunQueueSubmit::Enqueued
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, second),
            TunQueueSubmit::DroppedBulk
        );

        let queued = rx.bulk.try_recv().expect("first batch should stay queued");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].bytes, test_ipv6_tcp_packet(0x18, 512));
        assert!(
            rx.bulk.try_recv().is_err(),
            "full-queue bulk drop must not smuggle a pending batch into the queue"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tun_to_mesh_queue_counts_bulk_capacity_by_packets() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(3);

        let first = vec![
            test_pipeline_packet(test_ipv6_tcp_packet(0x18, 512)),
            test_pipeline_packet(test_ipv6_tcp_packet(0x18, 513)),
        ];
        let second = vec![
            test_pipeline_packet(test_ipv6_tcp_packet(0x18, 514)),
            test_pipeline_packet(test_ipv6_tcp_packet(0x18, 515)),
        ];

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, first),
            TunQueueSubmit::Enqueued
        );
        assert_eq!(
            tx.bulk_queued_packets
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, second),
            TunQueueSubmit::DroppedBulk
        );
        assert_eq!(
            tx.bulk_queued_packets
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        let queued = rx.bulk.try_recv().expect("first batch should stay queued");
        assert_eq!(queued.len(), 2);
        assert!(rx.bulk.try_recv().is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tun_to_mesh_queue_splits_large_lane_batches_before_enqueue() {
        let priority_count = FIPS_MESH_PRIORITY_SEND_BURST + 2;
        let (tx, mut rx) = TunPipelineQueueTx::channel(1);
        let priority = (0..priority_count)
            .map(|sequence| {
                let mut packet = test_ipv6_tcp_packet(0x10, 0);
                packet.push(u8::try_from(sequence).expect("sequence fits in test packet marker"));
                test_pipeline_packet(packet)
            })
            .collect();

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, priority),
            TunQueueSubmit::Enqueued
        );
        let first_priority = rx.priority.try_recv().expect("first priority chunk");
        assert_eq!(first_priority.len(), FIPS_MESH_PRIORITY_SEND_BURST);
        assert_eq!(
            first_priority
                .last()
                .and_then(|packet| packet.bytes.last())
                .copied(),
            Some((FIPS_MESH_PRIORITY_SEND_BURST - 1) as u8)
        );
        let second_priority = rx.priority.try_recv().expect("remaining priority chunk");
        assert_eq!(second_priority.len(), 2);
        assert_eq!(
            second_priority[0].bytes.last().copied(),
            Some(FIPS_MESH_PRIORITY_SEND_BURST as u8)
        );

        let bulk_count = FIPS_MESH_BULK_SEND_BURST + 2;
        let (tx, mut rx) = TunPipelineQueueTx::channel(bulk_count);
        let bulk = (0..bulk_count)
            .map(|sequence| {
                let mut packet = test_ipv6_tcp_packet(0x18, 512 + sequence);
                packet.push(u8::try_from(sequence).expect("sequence fits in test packet marker"));
                test_pipeline_packet(packet)
            })
            .collect();

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, bulk),
            TunQueueSubmit::Enqueued
        );
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), bulk_count);
        let first_bulk = rx.bulk.try_recv().expect("first bulk chunk");
        assert_eq!(first_bulk.len(), FIPS_MESH_BULK_SEND_BURST);
        assert_eq!(
            first_bulk
                .last()
                .and_then(|packet| packet.bytes.last())
                .copied(),
            Some((FIPS_MESH_BULK_SEND_BURST - 1) as u8)
        );
        let second_bulk = rx.bulk.try_recv().expect("remaining bulk chunk");
        assert_eq!(second_bulk.len(), 2);
        assert_eq!(
            second_bulk[0].bytes.last().copied(),
            Some(FIPS_MESH_BULK_SEND_BURST as u8)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tun_to_mesh_release_bulk_packet_slots_subtracts_exact_count() {
        let counter = AtomicUsize::new(5);

        release_tun_bulk_packet_slots(&counter, 0);
        assert_eq!(counter.load(Ordering::Relaxed), 5);

        release_tun_bulk_packet_slots(&counter, 3);
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_releases_bulk_packet_slots_on_recv() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(2);

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![
                    test_pipeline_packet(test_ipv6_tcp_packet(0x18, 512)),
                    test_pipeline_packet(test_ipv6_tcp_packet(0x18, 513)),
                ],
            ),
            TunQueueSubmit::Enqueued
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![test_pipeline_packet(test_ipv6_tcp_packet(0x18, 514)),],
            ),
            TunQueueSubmit::DroppedBulk
        );

        let queued = rx.recv().await.expect("queued bulk batch");
        assert_eq!(queued.len(), 2);
        assert_eq!(
            tx.bulk_queued_packets
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![test_pipeline_packet(test_ipv6_tcp_packet(0x18, 515)),],
            ),
            TunQueueSubmit::Enqueued
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_coalesces_ready_bulk_batches_on_recv() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        rx.set_bulk_coalesce_delay_for_tests(Duration::ZERO);
        let first = test_ipv6_tcp_packet(0x18, 512);
        let second = test_ipv6_tcp_packet(0x18, 513);
        let third = test_ipv6_tcp_packet(0x18, 514);

        for packet in [&first, &second, &third] {
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(
                    &tx,
                    vec![test_pipeline_packet(packet.clone())],
                ),
                TunQueueSubmit::Enqueued
            );
        }
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), 3);

        let queued = rx.recv().await.expect("coalesced bulk batch");
        assert_eq!(queued.len(), 3);
        assert_eq!(queued[0].bytes, first);
        assert_eq!(queued[1].bytes, second);
        assert_eq!(queued[2].bytes, third);
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_caps_ready_bulk_batches_on_recv() {
        let packet_count = FIPS_MESH_BULK_SEND_BURST + 2;
        let (tx, mut rx) = TunPipelineQueueTx::channel(packet_count);
        rx.set_bulk_coalesce_delay_for_tests(Duration::ZERO);

        for sequence in 0..packet_count {
            let mut packet = test_ipv6_tcp_packet(0x18, 512 + sequence);
            packet.push(u8::try_from(sequence).expect("sequence fits in test packet marker"));
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(packet)],),
                TunQueueSubmit::Enqueued
            );
        }
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), packet_count);

        let first = rx.recv().await.expect("first bulk batch");
        assert_eq!(first.len(), FIPS_MESH_BULK_SEND_BURST);
        assert_eq!(
            first.last().and_then(|packet| packet.bytes.last()).copied(),
            Some((FIPS_MESH_BULK_SEND_BURST - 1) as u8)
        );
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), 2);

        let second = rx.recv().await.expect("remaining bulk batch");
        assert_eq!(second.len(), 2);
        assert_eq!(
            second[0].bytes.last().copied(),
            Some(FIPS_MESH_BULK_SEND_BURST as u8)
        );
        assert_eq!(
            second[1].bytes.last().copied(),
            Some((FIPS_MESH_BULK_SEND_BURST + 1) as u8)
        );
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_coalesces_delayed_bulk_batch_within_window() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        rx.set_bulk_coalesce_delay_for_tests(Duration::from_millis(100));
        let first = test_ipv6_tcp_packet(0x18, 512);
        let second = test_ipv6_tcp_packet(0x18, 513);

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(first.clone())],),
            TunQueueSubmit::Enqueued
        );

        let delayed_tx = tx.clone();
        let delayed = second.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(
                    &delayed_tx,
                    vec![test_pipeline_packet(delayed)],
                ),
                TunQueueSubmit::Enqueued
            );
        });

        let queued = rx.recv().await.expect("coalesced delayed bulk batch");
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0].bytes, first);
        assert_eq!(queued[1].bytes, second);
        assert_eq!(tx.bulk_queued_packets.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_preempts_bulk_coalesce_when_priority_arrives() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        rx.set_bulk_coalesce_delay_for_tests(Duration::from_millis(250));
        let bulk = test_ipv6_tcp_packet(0x18, 512);
        let priority = test_ipv4_icmp_packet();

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(bulk.clone())],),
            TunQueueSubmit::Enqueued
        );

        let delayed_tx = tx.clone();
        let delayed_priority = priority.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(
                    &delayed_tx,
                    vec![test_pipeline_packet(delayed_priority)],
                ),
                TunQueueSubmit::Enqueued
            );
        });

        let started = std::time::Instant::now();
        let queued_priority = rx.recv().await.expect("priority batch should return");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "priority arrival should cut the bulk coalesce window short"
        );
        assert_eq!(queued_priority.len(), 1);
        assert_eq!(queued_priority[0].bytes, priority);

        let queued_bulk = rx.recv().await.expect("deferred bulk batch");
        assert_eq!(queued_bulk.len(), 1);
        assert_eq!(queued_bulk[0].bytes, bulk);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_keeps_deferred_bulk_behind_later_priority() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        rx.set_bulk_coalesce_delay_for_tests(Duration::from_millis(250));
        let bulk = test_ipv6_tcp_packet(0x18, 512);
        let first_priority = test_ipv4_icmp_packet();
        let second_priority = test_ipv6_tcp_packet(0x10, 0);

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(bulk.clone())],),
            TunQueueSubmit::Enqueued
        );

        let delayed_tx = tx.clone();
        let delayed_priority = first_priority.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(
                    &delayed_tx,
                    vec![test_pipeline_packet(delayed_priority)],
                ),
                TunQueueSubmit::Enqueued
            );
        });

        let queued_first_priority = rx.recv().await.expect("first priority batch");
        assert_eq!(queued_first_priority.len(), 1);
        assert_eq!(queued_first_priority[0].bytes, first_priority);

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![test_pipeline_packet(second_priority.clone())],
            ),
            TunQueueSubmit::Enqueued
        );

        let queued_second_priority = rx.recv().await.expect("second priority batch");
        assert_eq!(queued_second_priority.len(), 1);
        assert_eq!(queued_second_priority[0].bytes, second_priority);

        let queued_bulk = rx.recv().await.expect("deferred bulk batch");
        assert_eq!(queued_bulk.len(), 1);
        assert_eq!(queued_bulk[0].bytes, bulk);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_coalesces_ready_priority_batches_on_recv() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        let first = test_ipv4_icmp_packet();
        let second = test_ipv6_tcp_packet(0x10, 0);

        for packet in [&first, &second] {
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(
                    &tx,
                    vec![test_pipeline_packet(packet.clone())],
                ),
                TunQueueSubmit::Enqueued
            );
        }

        let queued = rx.recv().await.expect("coalesced priority batch");
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0].bytes, first);
        assert_eq!(queued[1].bytes, second);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_caps_ready_priority_batches_on_recv() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        let packet_count = FIPS_MESH_PRIORITY_SEND_BURST + 2;

        for sequence in 0..packet_count {
            let mut packet = test_ipv6_tcp_packet(0x10, 0);
            packet.push(u8::try_from(sequence).expect("sequence fits in test packet marker"));
            assert_eq!(
                submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(packet)],),
                TunQueueSubmit::Enqueued
            );
        }

        let first = rx.recv().await.expect("first priority batch");
        assert_eq!(first.len(), FIPS_MESH_PRIORITY_SEND_BURST);
        assert_eq!(
            first
                .last()
                .and_then(|packet| packet.bytes.last())
                .copied(),
            Some((FIPS_MESH_PRIORITY_SEND_BURST - 1) as u8)
        );

        let second = rx.recv().await.expect("remaining priority batch");
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].bytes.last().copied(), Some(FIPS_MESH_PRIORITY_SEND_BURST as u8));
        assert_eq!(
            second[1].bytes.last().copied(),
            Some((FIPS_MESH_PRIORITY_SEND_BURST + 1) as u8)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn tun_to_mesh_queue_keeps_priority_biased_over_ready_bulk() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(8);
        let bulk = test_ipv6_tcp_packet(0x18, 512);
        let priority = test_ipv4_icmp_packet();

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(bulk.clone())],),
            TunQueueSubmit::Enqueued
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![test_pipeline_packet(priority.clone())],
            ),
            TunQueueSubmit::Enqueued
        );

        let queued_priority = rx.recv().await.expect("priority batch first");
        assert_eq!(queued_priority.len(), 1);
        assert_eq!(queued_priority[0].bytes, priority);

        let queued_bulk = rx.recv().await.expect("bulk batch second");
        assert_eq!(queued_bulk.len(), 1);
        assert_eq!(queued_bulk[0].bytes, bulk);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn full_tun_to_mesh_queue_preserves_priority_progress() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(1);
        let bulk_first = test_ipv6_tcp_packet(0x18, 512);
        let bulk_dropped = test_ipv6_tcp_packet(0x18, 512);
        let priority = test_ipv4_icmp_packet();

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![test_pipeline_packet(bulk_first.clone())],
            ),
            TunQueueSubmit::Enqueued
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(&tx, vec![test_pipeline_packet(bulk_dropped)],),
            TunQueueSubmit::DroppedBulk
        );
        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![test_pipeline_packet(priority.clone())]
            ),
            TunQueueSubmit::Enqueued
        );

        let queued_priority = rx
            .priority
            .try_recv()
            .expect("priority packet should bypass full bulk queue");
        assert_eq!(queued_priority.len(), 1);
        assert_eq!(queued_priority[0].bytes, priority);

        let queued_bulk = rx.bulk.try_recv().expect("first bulk should stay queued");
        assert_eq!(queued_bulk.len(), 1);
        assert_eq!(queued_bulk[0].bytes, bulk_first);
        assert!(rx.bulk.try_recv().is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tun_to_mesh_queue_splits_mixed_batch_into_priority_and_bulk_lanes() {
        let (tx, mut rx) = TunPipelineQueueTx::channel(2);
        let bulk = test_ipv6_tcp_packet(0x18, 512);
        let ack = test_ipv6_tcp_packet(0x10, 0);
        let ping = test_ipv4_icmp_packet();

        assert_eq!(
            submit_tun_packet_batch_to_mesh_queue(
                &tx,
                vec![
                    test_pipeline_packet(bulk.clone()),
                    test_pipeline_packet(ack.clone()),
                    test_pipeline_packet(ping.clone()),
                ],
            ),
            TunQueueSubmit::Enqueued
        );

        let queued_priority = rx.priority.try_recv().expect("priority batch");
        assert_eq!(queued_priority.len(), 2);
        assert_eq!(queued_priority[0].bytes, ack);
        assert_eq!(queued_priority[1].bytes, ping);

        let queued_bulk = rx.bulk.try_recv().expect("bulk batch");
        assert_eq!(queued_bulk.len(), 1);
        assert_eq!(queued_bulk[0].bytes, bulk);
    }
