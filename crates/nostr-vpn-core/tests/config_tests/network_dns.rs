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

/// The first address this device forwards to, primary first.
fn first_nameserver(config: &AppConfig) -> Option<std::net::Ipv4Addr> {
    match config.network_dns_route() {
        NetworkDnsRoute::Nameservers(nameservers) => nameservers.first().copied(),
        _ => None,
    }
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
    let nameserver = first_nameserver(&config).expect("override is active");

    assert_eq!(format!("{nameserver}/32"), expected);
}

#[test]
fn network_dns_nameserver_is_unset_while_the_override_is_off() {
    let (config, _own, _pihole) = network_dns_fixture(false);

    assert!(first_nameserver(&config).is_none());
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
        first_nameserver(&config).is_none(),
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
    assert!(first_nameserver(&config).is_none());
    assert_eq!(config.network_dns_route(), NetworkDnsRoute::Unavailable);
}

#[test]
fn network_dns_route_names_each_state() {
    let (config, _own, pihole) = network_dns_fixture(true);
    let expected = derive_mesh_tunnel_ip(&config.effective_network_id(), &pihole)
        .expect("derive nameserver tunnel ip");
    let NetworkDnsRoute::Nameservers(nameservers) = config.network_dns_route() else {
        panic!("a member nameserver must be forwarded to");
    };
    let nameservers = nameservers
        .iter()
        .map(|nameserver| format!("{nameserver}/32"))
        .collect::<Vec<_>>();
    assert_eq!(nameservers, vec![expected]);

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
        first_nameserver(&reloaded),
        first_nameserver(&config),
        "the override must survive a save/load round trip"
    );
    assert!(first_nameserver(&reloaded).is_some());
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
        first_nameserver(&config).is_none(),
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

/// The fixture plus a second member that the admin names as a backup.
fn network_dns_backup_fixture() -> (AppConfig, String, String, String) {
    let (mut config, own, pihole) = network_dns_fixture(true);
    let backup = Keys::generate().public_key().to_hex();
    config.networks[0].devices.push(backup.clone());
    let network_id = config.networks[0].id.clone();
    config
        .set_network_dns_backups(&network_id, std::slice::from_ref(&backup))
        .expect("name a backup nameserver");
    (config, own, pihole, backup)
}

fn mesh_ipv4(config: &AppConfig, node: &str) -> std::net::Ipv4Addr {
    let tunnel_ip =
        derive_mesh_tunnel_ip(&config.effective_network_id(), node).expect("derive tunnel ip");
    tunnel_ip
        .split('/')
        .next()
        .expect("address")
        .parse()
        .expect("parse address")
}

#[test]
fn a_member_resolves_through_the_primary_then_the_backups() {
    let (config, _own, pihole, backup) = network_dns_backup_fixture();

    assert_eq!(
        config.network_dns_route(),
        NetworkDnsRoute::Nameservers(vec![
            mesh_ipv4(&config, &pihole),
            mesh_ipv4(&config, &backup)
        ])
    );
}

/// A backup box runs its own Pi-hole, so like the primary it must install no
/// stub and forward nowhere. Forwarding to the primary would make the backup
/// stop resolving exactly when the primary sleeps.
#[test]
fn a_backup_dns_box_gets_no_nameservers_of_its_own() {
    let (mut config, own, pihole, _backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();
    config
        .set_network_dns_backups(&network_id, std::slice::from_ref(&own))
        .expect("make this device the backup");
    assert_eq!(config.networks[0].dns_node, pihole);

    assert_eq!(config.network_dns_route(), NetworkDnsRoute::ServesNetwork);
    assert!(first_nameserver(&config).is_none());
}

#[test]
fn losing_the_primary_leaves_the_backup_serving() {
    let (mut config, _own, pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();

    config
        .remove_device_from_network(&network_id, &pihole)
        .expect("remove the primary");
    activate_first_network(&mut config);

    assert!(config.networks[0].dns_node.is_empty());
    assert_eq!(
        config.network_dns_route(),
        NetworkDnsRoute::Nameservers(vec![mesh_ipv4(&config, &backup)])
    );
}

#[test]
fn removing_a_backup_device_drops_it_from_the_backups() {
    let (mut config, _own, _pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();

    config
        .remove_device_from_network(&network_id, &backup)
        .expect("remove the backup");

    assert!(config.networks[0].dns_backup_nodes.is_empty());
}

#[test]
fn set_network_dns_backups_rejects_strangers_and_the_primary() {
    let (mut config, _own, pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();
    let stranger = Keys::generate().public_key().to_bech32().expect("npub");

    let error = config
        .set_network_dns_backups(&network_id, &[stranger])
        .expect_err("a non-member cannot be a backup");
    assert!(error.to_string().contains("must be a member"));

    let error = config
        .set_network_dns_backups(&network_id, std::slice::from_ref(&pihole))
        .expect_err("the primary cannot be its own backup");
    assert!(error.to_string().contains("primary"));

    assert_eq!(
        config.networks[0].dns_backup_nodes,
        vec![backup],
        "a rejected call must leave the stored backups alone"
    );
}

#[test]
fn promoting_a_backup_to_primary_removes_it_from_the_backups() {
    let (mut config, _own, _pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();

    config
        .set_network_dns(&network_id, &backup, true)
        .expect("promote the backup");

    assert_eq!(config.networks[0].dns_node, backup);
    assert!(config.networks[0].dns_backup_nodes.is_empty());
}

#[test]
fn dns_backups_survive_a_save_and_load() {
    let (config, _own, _pihole, backup) = network_dns_backup_fixture();
    let path = std::env::temp_dir().join(format!(
        "nvpn-dns-backups-{}.toml",
        Keys::generate().public_key().to_hex()
    ));

    config.save(&path).expect("save config");
    let reloaded = AppConfig::load(&path).expect("reload config");
    let _ = fs::remove_file(&path);

    assert_eq!(reloaded.networks[0].dns_backup_nodes, vec![backup]);
    assert_eq!(reloaded.network_dns_route(), config.network_dns_route());
}

#[test]
fn making_a_backup_the_dns_box_keeps_the_old_primary_as_a_backup() {
    let (mut config, _, pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();

    config
        .set_network_dns_role(&network_id, &backup, NetworkDnsRole::Primary)
        .expect("promote the backup");

    assert_eq!(config.networks[0].dns_node, backup);
    assert_eq!(config.networks[0].dns_backup_nodes, vec![pihole]);
    assert!(config.networks[0].dns_override);
}

#[test]
fn removing_dns_from_the_primary_hands_it_to_the_first_backup() {
    let (mut config, _, pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();

    config
        .set_network_dns_role(&network_id, &pihole, NetworkDnsRole::None)
        .expect("remove DNS from the primary");

    assert_eq!(config.networks[0].dns_node, backup);
    assert!(config.networks[0].dns_backup_nodes.is_empty());
    assert!(
        config.networks[0].dns_override,
        "the override outlives the box"
    );
}

#[test]
fn removing_dns_from_the_last_box_clears_the_selection() {
    let (mut config, _, pihole) = network_dns_fixture(true);
    let network_id = config.networks[0].id.clone();

    config
        .set_network_dns_role(&network_id, &pihole, NetworkDnsRole::None)
        .expect("remove the only box");

    assert!(config.networks[0].dns_node.is_empty());
    assert!(config.networks[0].dns_backup_nodes.is_empty());
    assert!(!config.networks[0].dns_override);
}

#[test]
fn the_only_dns_box_cannot_become_a_backup() {
    let (mut config, _, pihole) = network_dns_fixture(true);
    let network_id = config.networks[0].id.clone();

    let error = config
        .set_network_dns_role(&network_id, &pihole, NetworkDnsRole::Backup)
        .expect_err("a backup needs a primary to back up");
    assert!(error.to_string().contains("no primary"), "{error}");
    assert_eq!(config.networks[0].dns_node, pihole);
    assert!(config.networks[0].dns_backup_nodes.is_empty());
    assert!(config.networks[0].dns_override);
}

#[test]
fn a_new_backup_goes_after_the_existing_ones() {
    let (mut config, _, pihole, backup) = network_dns_backup_fixture();
    let third = Keys::generate().public_key().to_hex();
    config.networks[0].devices.push(third.clone());
    let network_id = config.networks[0].id.clone();

    config
        .set_network_dns_role(&network_id, &third, NetworkDnsRole::Backup)
        .expect("add a second backup");
    assert_eq!(config.networks[0].dns_node, pihole);
    assert_eq!(
        config.networks[0].dns_backup_nodes,
        vec![backup.clone(), third.clone()]
    );

    config
        .set_network_dns_role(&network_id, &backup, NetworkDnsRole::None)
        .expect("remove the first backup");
    assert_eq!(config.networks[0].dns_backup_nodes, vec![third]);
}

#[test]
fn a_refused_dns_role_change_leaves_the_config_untouched() {
    let (mut config, _, pihole, backup) = network_dns_backup_fixture();
    let network_id = config.networks[0].id.clone();
    let stranger = Keys::generate().public_key().to_hex();

    config
        .set_network_dns_role(&network_id, &stranger, NetworkDnsRole::Primary)
        .expect_err("a stranger cannot serve DNS");
    assert_eq!(config.networks[0].dns_node, pihole);
    assert_eq!(config.networks[0].dns_backup_nodes, vec![backup.clone()]);

    // The primary moves first and the backup list second. When the second
    // step is refused, the first must not stick.
    config.networks[0].dns_backup_nodes.push(stranger);
    config
        .set_network_dns_role(&network_id, &backup, NetworkDnsRole::Primary)
        .expect_err("a stale stranger in the backups refuses the new list");
    assert_eq!(config.networks[0].dns_node, pihole);
    config.networks[0].dns_backup_nodes.pop();

    config.networks[0].admins.clear();
    let error = config
        .set_network_dns_role(&network_id, &backup, NetworkDnsRole::Primary)
        .expect_err("only an admin can change DNS");
    assert!(
        error.to_string().contains("only a network admin"),
        "{error}"
    );
    assert_eq!(config.networks[0].dns_node, pihole);
    assert_eq!(config.networks[0].dns_backup_nodes, vec![backup]);
}
