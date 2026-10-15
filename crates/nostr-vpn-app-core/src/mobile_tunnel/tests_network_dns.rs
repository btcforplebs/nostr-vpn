    /// Mobile-side mirror of the daemon's network DNS override behaviour. A
    /// phone that is a full roster member has to honour the admin's DNS
    /// policy, not just publish it.
    ///
    /// Builds an app where `pihole` is a roster member serving network DNS.
    fn mobile_network_dns_app(dns_override: bool) -> (AppConfig, String) {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own_pubkey = app.own_nostr_pubkey_hex().expect("own pubkey");
        let pihole = Keys::generate().public_key().to_hex();
        app.networks[0].enabled = true;
        app.networks[0].network_id = "network-dns".to_string();
        app.networks[0].admins = vec![own_pubkey.clone()];
        app.networks[0].devices = vec![own_pubkey, pihole.clone()];
        let network_entry_id = app.networks[0].id.clone();
        app.set_network_dns(&network_entry_id, &pihole, dns_override)
            .expect("select network nameserver");
        (app, pihole)
    }

    fn expected_mobile_nameserver(app: &AppConfig, pihole: &str) -> Ipv4Addr {
        derive_mesh_tunnel_ip(&app.effective_network_id(), pihole)
            .expect("derive nameserver tunnel ip")
            .split('/')
            .next()
            .expect("address")
            .parse()
            .expect("parse nameserver")
    }

    #[test]
    fn network_dns_override_owns_mobile_dns_with_no_exit_node() {
        let (app, pihole) = mobile_network_dns_app(true);
        assert!(app.internet_source.is_direct());

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let nameserver = expected_mobile_nameserver(&app, &pihole);

        assert!(
            !config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0" || route == "::/0"),
            "the override alone must not select an exit"
        );
        assert_eq!(config.network_dns_servers, vec![nameserver.to_string()]);
        assert_eq!(
            mobile_exit_dns_resolver_config(&config).expect("resolver config"),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec![IpAddr::V4(nameserver)]
            },
            "the override must own DNS even on a direct connection"
        );
        assert_eq!(
            active_mobile_exit_dns_servers(&config).expect("exit dns servers"),
            vec![nameserver],
            "in-tunnel queries have to be NATed to the network's nameserver"
        );
        assert_eq!(
            config.dns_match_domains,
            vec![""],
            "every domain, not just the MagicDNS suffix, must use the in-tunnel resolver"
        );
        assert_eq!(
            config.dns_servers,
            vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER]
        );
        // Configuring the NAT is only half of it: the rewritten destination
        // still has to be inside the tunnel's route set, or the query is
        // handed to the OS and leaves the device unencrypted (or not at all).
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == &format!("{nameserver}/32")),
            "the nameserver's mesh /32 must be routed into the tunnel, got {:?}",
            config.route_targets
        );
    }

    #[test]
    fn network_dns_override_installs_the_in_tunnel_resolver() {
        let (mut app, _) = mobile_network_dns_app(true);
        // Without MagicDNS or an exit node there is otherwise no reason to run
        // the local responder — but the override is enforced by NATing DNS
        // that enters the tunnel, so the OS still has to be handed one.
        app.magic_dns_suffix.clear();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert!(
            !config.magic_dns_server.is_empty(),
            "the override needs an in-tunnel DNS responder to NAT from"
        );
        assert_eq!(config.dns_servers, vec![config.magic_dns_server.clone()]);
        assert_eq!(config.dns_match_domains, vec![""]);
    }

    #[test]
    fn network_dns_override_outranks_the_exit_dns_preference_with_an_exit() {
        let (mut app, pihole) = mobile_network_dns_app(true);
        let exit = Keys::generate().public_key().to_hex();
        app.networks[0].devices.push(exit.clone());
        app.exit_node = exit;

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let nameserver = expected_mobile_nameserver(&app, &pihole);

        assert!(config.route_targets.iter().any(|route| route == "0.0.0.0/0"));
        assert_eq!(config.dns_match_domains, vec![""]);
        assert_eq!(
            mobile_exit_dns_resolver_config(&config).expect("resolver config"),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec![IpAddr::V4(nameserver)]
            },
            "admin network policy is checked before this device's exit DNS"
        );
    }

    #[test]
    fn network_dns_override_off_leaves_mobile_dns_alone() {
        let (app, _) = mobile_network_dns_app(false);

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert!(config.network_dns_servers.is_empty());
        assert_eq!(
            mobile_exit_dns_resolver_config(&config).expect("resolver config"),
            ExitDnsConfig::default()
                .resolver_config(None)
                .expect("default resolver config"),
            "selecting a nameserver without turning the override on must not \
             redirect this device's DNS"
        );
        assert_eq!(
            config.dns_match_domains,
            vec!["nvpn"],
            "a direct connection keeps ordinary DNS on the underlay"
        );
    }

    #[test]
    fn network_dns_override_off_with_magic_dns_off_installs_no_resolver() {
        let (mut app, _) = mobile_network_dns_app(false);
        app.magic_dns_suffix.clear();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert!(config.magic_dns_server.is_empty());
        assert!(config.dns_servers.is_empty());
        assert!(config.dns_match_domains.is_empty());
    }

    #[test]
    fn network_dns_override_excludes_the_nameserver_device_itself() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own_pubkey = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "network-dns".to_string();
        app.networks[0].admins = vec![own_pubkey.clone()];
        app.networks[0].devices = vec![own_pubkey.clone()];
        let network_entry_id = app.networks[0].id.clone();
        app.set_network_dns(&network_entry_id, &own_pubkey, true)
            .expect("select self as nameserver");

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert!(
            config.network_dns_servers.is_empty(),
            "a device serving network DNS must not NAT its own queries to itself"
        );
        assert_eq!(config.dns_match_domains, vec!["nvpn"]);
    }

    /// Two boxes, neither primary: the phone is handed both, routes both
    /// into the tunnel, and the forwarder is built with both.
    #[test]
    fn network_dns_override_hands_the_phone_every_box() {
        let (mut app, pihole) = mobile_network_dns_app(true);
        let mac = Keys::generate().public_key().to_hex();
        app.networks[0].devices.push(mac.clone());
        let network_entry_id = app.networks[0].id.clone();
        app.set_network_dns_backups(&network_entry_id, std::slice::from_ref(&mac))
            .expect("list a second box");

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let first = expected_mobile_nameserver(&app, &pihole);
        let second = expected_mobile_nameserver(&app, &mac);

        assert_eq!(
            config.network_dns_servers,
            vec![first.to_string(), second.to_string()]
        );
        for nameserver in [first, second] {
            assert!(
                config.route_targets.contains(&format!("{nameserver}/32")),
                "{nameserver} must be routed into the tunnel, got {:?}",
                config.route_targets
            );
        }
        assert_eq!(
            active_mobile_exit_dns_servers(&config).expect("exit dns servers"),
            vec![first, second],
            "every lookup is NATed to every box"
        );
        assert_eq!(
            mobile_dns_upstream(&config).expect("dns upstream"),
            MobileDnsUpstream::Nat(vec![first, second])
        );
    }

    /// The list field is new; a config written before it still loads with
    /// the override off rather than failing to parse.
    #[test]
    fn mobile_config_without_the_box_list_still_loads() {
        let (app, _) = mobile_network_dns_app(false);
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mut json: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&config).expect("encode"),
        )
        .expect("decode");
        json.as_object_mut()
            .expect("object")
            .remove("networkDnsServers")
            .expect("the field is serialized");
        let loaded: MobileTunnelConfig =
            serde_json::from_value(json).expect("a config without the list still loads");
        assert!(loaded.network_dns_servers.is_empty());
    }
