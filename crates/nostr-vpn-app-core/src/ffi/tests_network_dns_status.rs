    /// A runtime whose active network sends DNS to `pihole`, aliased "pihole".
    fn network_dns_status_runtime(vpn_active: bool) -> (NativeAppRuntime, String) {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let pihole = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = vpn_active;
        runtime.vpn_active = vpn_active;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].devices = vec![pihole.to_string()];
        runtime
            .config
            .set_peer_alias(pihole, "pihole")
            .expect("alias the nameserver");
        let network_id = runtime.config.networks[0].id.clone();
        runtime
            .config
            .set_network_dns(&network_id, pihole, true)
            .expect("select nameserver");
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: vpn_active,
            vpn_active,
            peers: vec![DaemonPeerState {
                participant_pubkey: pihole.to_string(),
                endpoint: "fips".to_string(),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });
        (runtime, pihole.to_string())
    }

    #[test]
    fn network_dns_status_names_the_nameserver() {
        let (runtime, _) = network_dns_status_runtime(true);
        let state = runtime.state();
        assert_eq!(state.network_dns_status_text, "DNS via pihole.nvpn");
        assert!(!state.network_dns_blocked);
    }

    #[test]
    fn network_dns_status_alerts_when_the_nameserver_stops_answering() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.network_dns_unanswered_since =
                unix_timestamp().saturating_sub(NETWORK_DNS_UNANSWERED_ALERT_SECS);
        }
        let state = runtime.state();
        assert!(state.network_dns_blocked);
        assert!(state.network_dns_status_text.contains("isn't answering"), "{}", state.network_dns_status_text);
    }

    #[test]
    fn network_dns_status_ignores_a_query_still_inside_its_timeout() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.network_dns_unanswered_since = unix_timestamp();
        }
        assert!(!runtime.state().network_dns_blocked);
    }

    /// The override outlives its nameserver, and the user is told lookups fail.
    #[test]
    fn network_dns_status_alerts_when_the_nameserver_leaves() {
        let (mut runtime, pihole) = network_dns_status_runtime(true);
        runtime.config.networks[0].devices.retain(|device| device != &pihole);
        let state = runtime.state();
        assert!(state.network_dns_blocked);
        assert_eq!(state.network_dns_status_text, "DNS: No network nameserver. Lookups are blocked.");
    }

    #[test]
    fn network_dns_status_warns_when_the_nameserver_is_unreachable() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.peers[0].reachable = false;
        }
        let state = runtime.state();
        assert!(state.network_dns_blocked);
        assert_eq!(
            state.network_dns_status_text,
            "DNS via pihole.nvpn is unreachable. Lookups will fail."
        );
    }

    #[test]
    fn network_dns_status_warns_when_the_nameserver_is_missing_from_the_mesh() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.peers.clear();
        }
        assert!(runtime.state().network_dns_blocked);
    }

    #[test]
    fn network_dns_status_names_the_nameserver_while_disconnected() {
        let (runtime, _) = network_dns_status_runtime(false);
        let state = runtime.state();
        assert_eq!(state.network_dns_status_text, "DNS via pihole.nvpn when connected");
        assert!(!state.network_dns_blocked);
    }

    #[test]
    fn only_the_nameserver_row_is_marked_as_the_dns_server() {
        let (runtime, pihole) = network_dns_status_runtime(true);
        let state = runtime.state();
        let participants = &state.networks[0].participants;
        assert!(participants.len() >= 2);
        for participant in participants {
            assert_eq!(
                participant.serves_network_dns,
                participant.pubkey_hex == pihole,
                "{}",
                participant.pubkey_hex
            );
        }
    }

    #[test]
    fn dns_server_row_follows_the_configured_nameserver_with_the_override_off() {
        let (mut runtime, pihole) = network_dns_status_runtime(true);
        let network_id = runtime.config.networks[0].id.clone();
        runtime
            .config
            .set_network_dns(&network_id, &pihole, false)
            .expect("turn the override off");
        let state = runtime.state();
        assert!(
            state.networks[0]
                .participants
                .iter()
                .any(|participant| participant.serves_network_dns)
        );
    }

    #[test]
    fn network_dns_status_says_network_default_with_the_override_off() {
        let (mut runtime, pihole) = network_dns_status_runtime(true);
        let network_id = runtime.config.networks[0].id.clone();
        runtime
            .config
            .set_network_dns(&network_id, &pihole, false)
            .expect("turn the override off");
        let state = runtime.state();
        assert_eq!(state.network_dns_status_text, "DNS: network default");
        assert!(!state.network_dns_blocked);
    }
