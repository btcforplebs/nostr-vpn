    /// Mobile-side mirror of `fips_private_mesh/tests_config/network_dns.rs`.
    /// The daemon enforced the network DNS override long before mobile did, so
    /// these assert the same behaviour through `MobileTunnelConfig`: a phone
    /// that is a full roster member has to honour the admin's DNS policy, not
    /// just publish it.
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

        assert_eq!(config.network_dns, nameserver.to_string());
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
        // Configuring the NAT is only half of it: the rewritten destination
        // still has to be inside the tunnel's route set, or the query is
        // handed to the OS and leaves the device unencrypted (or not at all).
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == &format!("{nameserver}/32")
                    || route == MESH_TUNNEL_IPV4_CIDR),
            "the nameserver's mesh address must be routed into the tunnel, got {:?}",
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
    }

    #[test]
    fn network_dns_override_off_leaves_mobile_dns_alone() {
        let (app, _) = mobile_network_dns_app(false);

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert!(config.network_dns.is_empty());
        assert_eq!(
            mobile_exit_dns_resolver_config(&config).expect("resolver config"),
            ExitDnsConfig::default()
                .resolver_config(None)
                .expect("default resolver config"),
            "selecting a nameserver without turning the override on must not \
             redirect this device's DNS"
        );
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
            config.network_dns.is_empty(),
            "a device serving network DNS must not NAT its own queries to itself"
        );
    }
