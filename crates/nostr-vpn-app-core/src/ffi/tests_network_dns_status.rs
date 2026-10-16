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

    /// A second box, aliased "mac", listed after the Pi and reachable.
    fn with_second_box(runtime: &mut NativeAppRuntime) -> String {
        let mac = "3a1f7c2e9d4b6a8f0c5e1d2b3a4f5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";
        runtime.config.networks[0].devices.push(mac.to_string());
        runtime
            .config
            .set_peer_alias(mac, "mac")
            .expect("alias the second box");
        let network_id = runtime.config.networks[0].id.clone();
        runtime
            .config
            .set_network_dns_backups(&network_id, &[mac.to_string()])
            .expect("list the second box");
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.peers.push(DaemonPeerState {
                participant_pubkey: mac.to_string(),
                endpoint: "fips".to_string(),
                reachable: true,
                ..DaemonPeerState::default()
            });
        }
        mac.to_string()
    }

    #[test]
    fn network_dns_status_names_every_box() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        with_second_box(&mut runtime);
        let state = runtime.state();
        assert_eq!(state.network_dns_status_text, "DNS via pihole.nvpn, mac.nvpn");
        assert!(!state.network_dns_blocked);
    }

    /// The iOS and Android apps draw their DNS badges from these two keys of the
    /// state JSON (ios/Sources/Models.swift, android/.../core/Models.kt).
    #[test]
    fn state_json_marks_the_dns_box_and_its_backup_for_the_apps() {
        let (mut runtime, pihole) = network_dns_status_runtime(true);
        let mac = with_second_box(&mut runtime);
        let json = serde_json::to_value(runtime.state()).expect("state as JSON");
        let participants = json["networks"][0]["participants"]
            .as_array()
            .expect("participants");
        let row = |hex: &str| {
            participants
                .iter()
                .find(|participant| participant["pubkeyHex"] == hex)
                .unwrap_or_else(|| panic!("no row for {hex}"))
        };
        assert_eq!(row(&pihole)["servesNetworkDns"], true);
        assert_eq!(row(&pihole)["servesNetworkDnsBackup"], false);
        assert_eq!(row(&mac)["servesNetworkDns"], false);
        assert_eq!(row(&mac)["servesNetworkDnsBackup"], true);
    }

    /// Lookups go to every box, so one box out of reach changes nothing.
    #[test]
    fn network_dns_status_stays_green_while_one_box_is_unreachable() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        with_second_box(&mut runtime);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.peers[0].reachable = false;
        }
        let state = runtime.state();
        assert!(!state.network_dns_blocked, "{}", state.network_dns_status_text);
        assert_eq!(state.network_dns_status_text, "DNS via pihole.nvpn, mac.nvpn");
    }

    #[test]
    fn network_dns_status_warns_only_when_every_box_is_unreachable() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        with_second_box(&mut runtime);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            for peer in &mut daemon_state.peers {
                peer.reachable = false;
            }
        }
        let state = runtime.state();
        assert!(state.network_dns_blocked);
        assert_eq!(
            state.network_dns_status_text,
            "DNS via pihole.nvpn, mac.nvpn are all unreachable. Lookups will fail."
        );
    }

    /// The forwarder clears the alarm on any box's answer, so this fires
    /// only when none of them answered.
    #[test]
    fn network_dns_status_alerts_when_no_box_answers() {
        let (mut runtime, _) = network_dns_status_runtime(true);
        with_second_box(&mut runtime);
        if let Some(daemon_state) = runtime.daemon_state.as_mut() {
            daemon_state.network_dns_unanswered_since =
                unix_timestamp().saturating_sub(NETWORK_DNS_UNANSWERED_ALERT_SECS);
        }
        let state = runtime.state();
        assert!(state.network_dns_blocked);
        assert_eq!(
            state.network_dns_status_text,
            "DNS via pihole.nvpn, mac.nvpn aren't answering. Lookups are blocked."
        );
    }

    /// A runtime with a second member "mac" that saves to a temp dir, so the
    /// DNS button actions can run end to end without touching real config.
    fn dns_buttons_runtime(name: &str) -> (NativeAppRuntime, PathBuf, String, String) {
        let (mut runtime, pihole) = network_dns_status_runtime(true);
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-{name}-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        runtime.config_path = dir.join("config.toml");
        runtime.mobile_runtime = true;
        let mac = "3a1f7c2e9d4b6a8f0c5e1d2b3a4f5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";
        runtime.config.networks[0].devices.push(mac.to_string());
        (runtime, dir, pihole, mac.to_string())
    }

    fn dns_role_of(runtime: &NativeAppRuntime, pubkey: &str) -> (bool, bool) {
        let state = runtime.state();
        let participant = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == pubkey)
            .cloned()
            .expect("device row");
        (participant.serves_network_dns, participant.serves_network_dns_backup)
    }

    fn press_dns_button(runtime: &mut NativeAppRuntime, pubkey: &str, role: NativeNetworkDnsRole) {
        let network_id = runtime.config.networks[0].id.clone();
        runtime.dispatch(NativeAppAction::SetNetworkDnsRole {
            network_id,
            npub: npub_for_pubkey_hex(pubkey),
            role,
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
    }

    /// Make backup, promote, remove: the rows follow each step, the old
    /// primary is kept as a backup instead of dropping out, and removing the
    /// primary hands the job to the backup with the override still on.
    #[test]
    fn dns_buttons_move_devices_between_primary_backup_and_none() {
        let (mut runtime, dir, pihole, mac) = dns_buttons_runtime("dns-buttons");

        press_dns_button(&mut runtime, &mac, NativeNetworkDnsRole::Backup);
        assert_eq!(dns_role_of(&runtime, &mac), (false, true));
        assert_eq!(dns_role_of(&runtime, &pihole), (true, false));

        press_dns_button(&mut runtime, &mac, NativeNetworkDnsRole::Primary);
        assert_eq!(dns_role_of(&runtime, &mac), (true, false));
        assert_eq!(dns_role_of(&runtime, &pihole), (false, true));
        assert!(runtime.config.networks[0].dns_override);

        press_dns_button(&mut runtime, &mac, NativeNetworkDnsRole::None);
        assert_eq!(dns_role_of(&runtime, &mac), (false, false));
        assert_eq!(dns_role_of(&runtime, &pihole), (true, false));
        assert!(runtime.config.networks[0].dns_override);

        press_dns_button(&mut runtime, &pihole, NativeNetworkDnsRole::None);
        assert_eq!(dns_role_of(&runtime, &pihole), (false, false));

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.networks[0].dns_node.is_empty());
        assert!(saved.networks[0].dns_backup_nodes.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dns_button_refuses_a_non_admin_and_changes_nothing() {
        let (mut runtime, dir, pihole, mac) = dns_buttons_runtime("dns-buttons-admin");
        runtime.config.networks[0].admins = vec![mac.clone()];
        let network_id = runtime.config.networks[0].id.clone();

        runtime.dispatch(NativeAppAction::SetNetworkDnsRole {
            network_id,
            npub: npub_for_pubkey_hex(&mac),
            role: NativeNetworkDnsRole::Primary,
        });
        assert!(runtime.last_error.contains("only a network admin"), "{}", runtime.last_error);
        assert_eq!(runtime.config.networks[0].dns_node, pihole);
        assert!(runtime.config.networks[0].dns_backup_nodes.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The second-box add: one action puts the new device in the roster and
    /// in the backups, and the roster it is handed already says so, so it is
    /// never a plain member in between.
    #[test]
    fn add_as_dns_backup_admits_and_backs_up_in_one_roster() {
        let (mut runtime, dir, pihole, _) = dns_buttons_runtime("add-dns-backup");
        let network_id = runtime.config.networks[0].id.clone();
        let joiner = Keys::generate();
        let joiner_hex = joiner.public_key().to_hex();

        runtime.dispatch(NativeAppAction::AddParticipantAsDnsBackup {
            network_id,
            npub: joiner.public_key().to_bech32().expect("joiner npub"),
            alias: Some("pi".to_string()),
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(dns_role_of(&runtime, &joiner_hex), (false, true));
        assert_eq!(dns_role_of(&runtime, &pihole), (true, false));
        assert_eq!(runtime.queued_join_rosters.len(), 1);
        let handed = runtime.queued_join_rosters[0]
            .signed_roster
            .roster()
            .expect("join roster");
        assert!(handed.devices.contains(&joiner_hex));
        assert_eq!(handed.dns_node, pihole);
        assert_eq!(handed.dns_backup_nodes, vec![joiner_hex.clone()]);
        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(saved.networks[0].dns_backup_nodes, vec![joiner_hex.clone()]);
        assert_eq!(saved.peer_alias(&joiner_hex).as_deref(), Some("pi"));
        let _ = fs::remove_dir_all(&dir);
    }

    fn roster_of(runtime: &NativeAppRuntime) -> (Vec<String>, Vec<String>, String, Vec<String>) {
        let network = &runtime.config.networks[0];
        (
            network.devices.clone(),
            network.admins.clone(),
            network.dns_node.clone(),
            network.dns_backup_nodes.clone(),
        )
    }


    /// Refusals change nothing: no DNS box to back up, the DNS box itself,
    /// or a device that is not an admin asking.
    #[test]
    fn add_as_dns_backup_refuses_and_leaves_the_roster_alone() {
        let (mut runtime, dir, pihole, mac) = dns_buttons_runtime("add-dns-backup-refused");
        let network_id = runtime.config.networks[0].id.clone();
        let add = |runtime: &mut NativeAppRuntime, npub: String| {
            runtime.dispatch(NativeAppAction::AddParticipantAsDnsBackup {
                network_id: network_id.clone(),
                npub,
                alias: None,
            });
            runtime.last_error.clone()
        };
        let before = roster_of(&runtime);

        let error = add(&mut runtime, npub_for_pubkey_hex(&pihole));
        assert!(error.contains("already the network's DNS box"), "{error}");
        assert_eq!(roster_of(&runtime), before);

        let stranger = Keys::generate().public_key().to_bech32().expect("npub");
        runtime.config.networks[0].dns_node = String::new();
        let before = roster_of(&runtime);
        let error = add(&mut runtime, stranger.clone());
        assert!(error.contains("no DNS box yet"), "{error}");
        assert_eq!(roster_of(&runtime), before);
        assert!(runtime.queued_join_rosters.is_empty());

        runtime.config.networks[0].dns_node = pihole.clone();
        runtime.config.networks[0].admins = vec![mac.clone()];
        let before = roster_of(&runtime);
        let error = add(&mut runtime, stranger);
        assert!(error.contains("only a network admin"), "{error}");
        assert_eq!(roster_of(&runtime), before);
        assert!(runtime.queued_join_rosters.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
