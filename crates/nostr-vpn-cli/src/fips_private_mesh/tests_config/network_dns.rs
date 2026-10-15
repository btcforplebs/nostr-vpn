    /// Builds an app where `pihole` is a roster member serving network DNS.
    fn network_dns_app(dns_override: bool) -> (AppConfig, String, String) {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let pihole = Keys::generate().public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.nostr.public_key = own_pubkey.clone();
        app.networks[0].enabled = true;
        app.networks[0].network_id = "network-dns".to_string();
        app.networks[0].admins = vec![own_pubkey.clone()];
        app.networks[0].devices = vec![own_pubkey.clone(), pihole.clone()];
        let network_entry_id = app.networks[0].id.clone();
        app.set_network_dns(&network_entry_id, &pihole, dns_override)
            .expect("select network nameserver");
        (app, own_pubkey, pihole)
    }

    fn network_dns_config(app: &AppConfig, own_pubkey: &str) -> FipsPrivateTunnelConfig {
        FipsPrivateTunnelConfig::from_app(
            app,
            "network-dns",
            "utun-test",
            Some(own_pubkey),
            None,
            &[],
        )
        .expect("network dns tunnel config")
    }

    fn expected_nameserver(app: &AppConfig, pihole: &str) -> std::net::IpAddr {
        let tunnel_ip = derive_mesh_tunnel_ip(
            &app.effective_network_id(),
            pihole,
        )
        .expect("derive nameserver tunnel ip");
        tunnel_ip
            .split('/')
            .next()
            .expect("address")
            .parse()
            .expect("parse nameserver")
    }

    #[test]
    fn network_dns_override_owns_system_dns_on_a_direct_connection() {
        let (app, own_pubkey, pihole) = network_dns_app(true);
        assert!(app.internet_source.is_direct());

        let config = network_dns_config(&app, &own_pubkey);

        assert!(
            config.secure_dns_required(),
            "the override must own system DNS even with no exit node"
        );
        assert_eq!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec![expected_nameserver(&app, &pihole)]
            }
        );
    }

    #[test]
    fn network_dns_override_hands_the_stub_the_primary_then_the_backups() {
        let (mut app, own_pubkey, pihole) = network_dns_app(true);
        let backup = Keys::generate().public_key().to_hex();
        app.networks[0].devices.push(backup.clone());
        let network_entry_id = app.networks[0].id.clone();
        app.set_network_dns_backups(&network_entry_id, std::slice::from_ref(&backup))
            .expect("name a backup nameserver");

        let config = network_dns_config(&app, &own_pubkey);

        assert_eq!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec![
                    expected_nameserver(&app, &pihole),
                    expected_nameserver(&app, &backup),
                ]
            }
        );
    }

    #[test]
    fn network_dns_selection_without_override_changes_nothing() {
        let (app, own_pubkey, _pihole) = network_dns_app(false);

        let config = network_dns_config(&app, &own_pubkey);

        assert!(!config.secure_dns_required());
        assert!(matches!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::Doh { .. }
        ));
    }

    #[test]
    fn network_dns_override_outranks_this_device_exit_dns_preference() {
        let (mut app, own_pubkey, pihole) = network_dns_app(true);
        app.set_internet_source(InternetSource::PaidAutomatic);
        app.exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::Encrypted;

        let config = network_dns_config(&app, &own_pubkey);

        assert_eq!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec![expected_nameserver(&app, &pihole)]
            },
            "admin network policy must beat the device's own exit DNS setting"
        );
    }

    #[test]
    fn network_dns_override_does_not_fail_closed_waiting_on_wireguard() {
        let (mut app, own_pubkey, pihole) = network_dns_app(true);
        app.exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::ThroughExit;
        app.wireguard_exit.enabled = true;

        let config = network_dns_config(&app, &own_pubkey);

        assert_eq!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec![expected_nameserver(&app, &pihole)]
            },
            "the mesh nameserver is reachable without the WireGuard upstream"
        );
    }

    /// The nameserver device runs the resolver on port 53 itself, so pointing
    /// our own stub at it would collide and take the tunnel down.
    #[test]
    fn the_nameserver_device_does_not_install_the_override_on_itself() {
        let (mut app, own_pubkey, _pihole) = network_dns_app(true);
        let network_entry_id = app.networks[0].id.clone();
        app.set_network_dns(&network_entry_id, &own_pubkey, true)
            .expect("point the network at this device");

        let config = network_dns_config(&app, &own_pubkey);

        assert!(!config.secure_dns_required());
    }

    /// A DNS-only policy change must never bounce the FIPS endpoint.
    #[test]
    fn toggling_the_network_dns_override_does_not_restart_the_endpoint() {
        let (mut app, own_pubkey, _pihole) = network_dns_app(false);
        let before = network_dns_config(&app, &own_pubkey);

        let network_entry_id = app.networks[0].id.clone();
        let pihole = app.networks[0].dns_node.clone();
        app.set_network_dns(&network_entry_id, &pihole, true)
            .expect("enable the override");
        let after = network_dns_config(&app, &own_pubkey);

        assert!(after.secure_dns_required());
        assert!(!fips_tunnel_requires_endpoint_restart(&before, &after));
    }

    /// An override with no usable nameserver must not hand the device back to
    /// local DNS: it owns system DNS and fails every lookup closed.
    #[test]
    fn network_dns_override_without_a_nameserver_fails_closed() {
        let (mut app, own_pubkey, pihole) = network_dns_app(true);
        // The nameserver left the roster; the override stays on.
        app.networks[0].devices.retain(|device| device != &pihole);
        assert_eq!(
            app.network_dns_route(),
            nostr_vpn_core::config::NetworkDnsRoute::Unavailable
        );

        let config = network_dns_config(&app, &own_pubkey);

        assert!(config.secure_dns_required());
        assert_eq!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::FailClosed
        );
        assert!(crate::global_system_dns_required(&app));
    }

    /// Pausing the VPN releases the override with the rest of the dataplane.
    #[test]
    fn a_paused_dataplane_does_not_keep_the_network_dns_override() {
        let (app, own_pubkey, _pihole) = network_dns_app(true);
        let mut config = network_dns_config(&app, &own_pubkey);

        config.disable_client_dataplane();

        assert!(!config.secure_dns_required());
    }
