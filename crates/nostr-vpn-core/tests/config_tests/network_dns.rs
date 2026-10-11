use super::*;
#[test]
fn set_network_dns_requires_the_device_to_be_a_member() {
    let mut config = AppConfig::generated();
    let network_id = config.networks[0].id.clone();
    let member = Keys::generate().public_key().to_hex();
    let stranger = Keys::generate().public_key().to_bech32().expect("npub");
    config.networks[0].devices = vec![member.clone()];

    let error = config
        .set_network_dns(&network_id, &stranger, true)
        .expect_err("a non-member cannot serve network DNS");
    assert!(error.to_string().contains("must be a member"));

    config
        .set_network_dns(&network_id, &member, true)
        .expect("a member can serve network DNS");
    assert_eq!(config.networks[0].dns_node, member);
    assert!(config.networks[0].dns_override);
}

#[test]
fn set_network_dns_clears_the_selection_and_the_override() {
    let mut config = AppConfig::generated();
    let network_id = config.networks[0].id.clone();
    let member = Keys::generate().public_key().to_hex();
    config.networks[0].devices = vec![member.clone()];
    config
        .set_network_dns(&network_id, &member, true)
        .expect("select nameserver");

    config
        .set_network_dns(&network_id, "", true)
        .expect("clear nameserver");

    assert!(config.networks[0].dns_node.is_empty());
    assert!(
        !config.networks[0].dns_override,
        "override must not stay on without a nameserver"
    );
}

/// Removing the box must not quietly hand every member back to local DNS.
#[test]
fn removing_the_dns_device_clears_the_selection_and_fails_closed() {
    let own = Keys::generate();
    let pihole = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own.public_key().to_hex();
    let network_id = config.networks[0].id.clone();
    config.networks[0].admins = vec![own.public_key().to_hex()];
    config.networks[0].devices = vec![own.public_key().to_hex(), pihole.clone()];
    config
        .set_network_dns(&network_id, &pihole, true)
        .expect("select nameserver");

    config
        .remove_device_from_network(&network_id, &pihole)
        .expect("remove the nameserver device");
    activate_first_network(&mut config);

    assert!(config.networks[0].dns_node.is_empty());
    assert!(config.networks[0].dns_override);
    assert_eq!(config.network_dns_route(), NetworkDnsRoute::Unavailable);
}

fn network_dns_fixture(dns_override: bool) -> (AppConfig, String, String) {
    let own = Keys::generate();
    let pihole = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own.public_key().to_hex();
    let network_id = config.networks[0].id.clone();
    config.networks[0].admins = vec![own.public_key().to_hex()];
    config.networks[0].devices = vec![own.public_key().to_hex(), pihole.clone()];
    config
        .set_network_dns(&network_id, &pihole, dns_override)
        .expect("select nameserver");
    assert!(
        config.active_network_opt().is_some(),
        "fixture must have an active network or the assertions below pass vacuously"
    );
    (config, own.public_key().to_hex(), pihole)
}

#[test]
fn network_dns_nameserver_resolves_to_the_selected_device_mesh_address() {
    let (config, _own, pihole) = network_dns_fixture(true);

    let expected = derive_mesh_tunnel_ip(&config.effective_network_id(), &pihole)
        .expect("derive nameserver tunnel ip");
    let nameserver = config
        .network_dns_nameserver_ipv4()
        .expect("override is active");

    assert_eq!(format!("{nameserver}/32"), expected);
}

#[test]
fn network_dns_nameserver_is_unset_while_the_override_is_off() {
    let (config, _own, _pihole) = network_dns_fixture(false);

    assert!(config.network_dns_nameserver_ipv4().is_none());
}

/// The nameserver device must never point its own stub at itself: the stub
/// binds port 53 on Linux/Windows and would collide with the resolver it is
/// meant to reach, taking the tunnel down with it.
#[test]
fn network_dns_nameserver_is_unset_on_the_nameserver_device_itself() {
    let (mut config, own, _pihole) = network_dns_fixture(true);
    let network_id = config.networks[0].id.clone();

    config
        .set_network_dns(&network_id, &own, true)
        .expect("point the network at this device");

    assert!(
        config.network_dns_nameserver_ipv4().is_none(),
        "the nameserver device must not install the override on itself"
    );
}

#[test]
fn ensure_defaults_drops_a_network_dns_node_that_left_the_roster() {
    let (mut config, own, _pihole) = network_dns_fixture(true);
    config.networks[0].devices = vec![own];

    config.ensure_defaults();

    assert!(config.networks[0].dns_node.is_empty());
    assert!(config.networks[0].dns_override);
    assert!(config.network_dns_nameserver_ipv4().is_none());
    assert_eq!(config.network_dns_route(), NetworkDnsRoute::Unavailable);
}

#[test]
fn network_dns_route_names_each_state() {
    let (config, _own, pihole) = network_dns_fixture(true);
    let expected = derive_mesh_tunnel_ip(&config.effective_network_id(), &pihole)
        .expect("derive nameserver tunnel ip");
    let NetworkDnsRoute::Nameserver(nameserver) = config.network_dns_route() else {
        panic!("a member nameserver must be forwarded to");
    };
    assert_eq!(format!("{nameserver}/32"), expected);

    let (config, _own, _pihole) = network_dns_fixture(false);
    assert_eq!(config.network_dns_route(), NetworkDnsRoute::Off);

    let (mut config, own, _pihole) = network_dns_fixture(true);
    let network_id = config.networks[0].id.clone();
    config
        .set_network_dns(&network_id, &own, true)
        .expect("point the network at this device");
    assert_eq!(config.network_dns_route(), NetworkDnsRoute::ServesNetwork);
}

/// A device can drop the nameserver locally without the admin's roster
/// changing: a tombstone in `removed_devices`, or a roster that no longer
/// lists it. Both must fail closed, not fall back to local DNS.
#[test]
fn network_dns_route_is_unavailable_for_a_nameserver_that_is_not_a_member() {
    let (mut config, own, _pihole) = network_dns_fixture(true);
    config.networks[0].devices = vec![own];

    assert!(config.networks[0].dns_override);
    assert_eq!(config.network_dns_route(), NetworkDnsRoute::Unavailable);
}

/// Guards every "re-sign the roster from local config" site. The previous
/// attempt at this feature published the setting but rebuilt the roster with
/// the field blank, so it never reached anyone.
#[test]
fn shared_network_roster_carries_the_network_dns_selection() {
    let (config, _own, pihole) = network_dns_fixture(true);

    let shared = config
        .shared_network_roster(&config.networks[0].id)
        .expect("build shared roster");

    assert_eq!(shared.dns_node, pihole);
    assert!(shared.dns_override);
}

/// `devices`/`admins` persist as npubs, so the nameserver must too: a hex value
/// on disk would be an inconsistent format for the same kind of identifier.
#[test]
fn saved_config_serializes_the_network_dns_node_as_an_npub() {
    let (config, _own, pihole) = network_dns_fixture(true);
    let pihole_npub = nostr_vpn_core::config::npub_for_pubkey_hex(&pihole);

    let path = unique_temp_config_path("network-dns-node-npub");
    config.save(&path).expect("save config");
    let raw = fs::read_to_string(&path).expect("read saved config");

    assert!(raw.contains(&format!("dns_node = \"{pihole_npub}\"")));
    assert!(!raw.contains(&pihole), "hex form must not reach disk");

    let reloaded = AppConfig::load(&path).expect("reload config");
    let _ = fs::remove_file(&path);

    assert_eq!(
        reloaded.network_dns_nameserver_ipv4(),
        config.network_dns_nameserver_ipv4(),
        "the override must survive a save/load round trip"
    );
    assert!(reloaded.network_dns_nameserver_ipv4().is_some());
}

/// A device's own roster does not list itself, so a naive membership check
/// reports "not a member" for this very device and wipes the selection. That
/// only showed up on the nameserver device, where it left `nvpn status`
/// claiming no network DNS was configured at all.
#[test]
fn the_nameserver_device_keeps_the_selection_even_though_its_roster_omits_itself() {
    let own = Keys::generate();
    let admin = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let admin_hex = admin.public_key().to_hex();

    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![admin_hex.clone()];
    // Exactly how a member stores its roster: peers only, never itself.
    config.networks[0].devices = vec![admin_hex.clone()];
    config.networks[0].dns_node = own_hex.clone();
    config.networks[0].dns_override = true;

    config.ensure_defaults();

    assert_eq!(
        config.networks[0].dns_node, own_hex,
        "this device serves network DNS and must keep saying so"
    );
    assert!(config.networks[0].dns_override);
    assert!(
        config.network_dns_nameserver_ipv4().is_none(),
        "it still must not point its own resolver stub at itself"
    );
}

/// Enforced in core rather than at each caller, so the CLI and every app shell
/// get the same answer.
#[test]
fn set_network_dns_rejects_a_non_admin() {
    let own = Keys::generate();
    let admin = Keys::generate().public_key().to_hex();
    let pihole = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own.public_key().to_hex();
    let network_id = config.networks[0].id.clone();
    config.networks[0].admins = vec![admin];
    config.networks[0].devices = vec![pihole.clone()];

    let error = config
        .set_network_dns(&network_id, &pihole, true)
        .expect_err("a non-admin must not set the network nameserver");

    assert!(error.to_string().contains("only a network admin"));
    assert!(config.networks[0].dns_node.is_empty());
}
