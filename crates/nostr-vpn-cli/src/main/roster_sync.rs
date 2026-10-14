fn wireguard_exit_status_json(app: &AppConfig) -> serde_json::Value {
    json!({
        "enabled": app.wireguard_exit.enabled,
        "configured": app.wireguard_exit.configured(),
        "interface": &app.wireguard_exit.interface,
        "address": &app.wireguard_exit.address,
        "endpoint": &app.wireguard_exit.endpoint,
        "allowed_ips": &app.wireguard_exit.allowed_ips,
        "dns": &app.wireguard_exit.dns,
        "mtu": app.wireguard_exit.mtu,
        "persistent_keepalive_secs": app.wireguard_exit.persistent_keepalive_secs,
    })
}

/// Network DNS override state for `nvpn status`.
///
/// `enforced` is the truth that matters when resolution breaks: the override
/// fails closed, so an operator needs to see at a glance that it is on and
/// whether the nameserver is usable and reachable.
fn network_dns_status_json(
    app: &AppConfig,
    daemon_peers: Option<&[DaemonPeerState]>,
) -> serde_json::Value {
    use nostr_vpn_core::config::NetworkDnsRoute;

    let Some(network) = app.active_network_opt() else {
        return json!({ "node": null, "override": false, "enforced": false });
    };
    let route = app.network_dns_route();
    if network.dns_node.is_empty()
        && network.dns_backup_nodes.is_empty()
        && route == NetworkDnsRoute::Off
    {
        return json!({ "node": null, "override": false, "enforced": false });
    }

    let dns_node = (!network.dns_node.is_empty()).then(|| network.dns_node.clone());
    let nameservers = match &route {
        NetworkDnsRoute::Nameservers(nameservers) => nameservers.clone(),
        _ => Vec::new(),
    };
    let nameserver = nameservers.first().copied();
    let reachable = match (&dns_node, nameserver) {
        (Some(dns_node), Some(_)) => daemon_peers.map(|peers| {
            peers
                .iter()
                .any(|peer| &peer.participant_pubkey == dns_node && peer.reachable)
        }),
        _ => None,
    };
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let role = match route {
        NetworkDnsRoute::ServesNetwork if own_pubkey.as_deref() == dns_node.as_deref() => {
            "nameserver"
        }
        NetworkDnsRoute::ServesNetwork => "backup",
        _ => "client",
    };

    json!({
        "node": dns_node,
        "node_name": dns_node.as_deref().and_then(|node| app.peer_alias(node)),
        "backups": network.dns_backup_nodes,
        "nameserver_ip": nameserver.map(|ip| ip.to_string()),
        "nameserver_ips": nameservers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "override": network.dns_override,
        "role": role,
        "enforced": matches!(route, NetworkDnsRoute::Nameservers(_) | NetworkDnsRoute::Unavailable),
        "unavailable": route == NetworkDnsRoute::Unavailable,
        "reachable": reachable,
    })
}

fn network_dns_status_text(app: &AppConfig, daemon_peers: Option<&[DaemonPeerState]>) -> String {
    let status = network_dns_status_json(app, daemon_peers);
    if status["unavailable"].as_bool().unwrap_or(false) {
        return "override=on NO USABLE NAMESERVER, DNS fails closed".to_string();
    }
    if status["role"] == "backup" {
        return "this device is a backup network DNS server".to_string();
    }
    let Some(node) = status["node"].as_str() else {
        return "none".to_string();
    };
    let name = status["node_name"].as_str().unwrap_or(node);

    if status["role"] == "nameserver" {
        return format!("{name} (this device serves network DNS)");
    }
    if !status["enforced"].as_bool().unwrap_or(false) {
        return format!("{name} (selected, override off)");
    }

    let nameserver = status["nameserver_ip"].as_str().unwrap_or("unknown");
    let backups = status["nameserver_ips"]
        .as_array()
        .map_or(0, |ips| ips.len().saturating_sub(1));
    let backups = match backups {
        0 => String::new(),
        1 => " +1 backup".to_string(),
        count => format!(" +{count} backups"),
    };
    match status["reachable"].as_bool() {
        Some(false) if backups.is_empty() => {
            format!("{name} ({nameserver}) override=on UNREACHABLE, DNS fails closed")
        }
        Some(false) => format!("{name} ({nameserver}) override=on UNREACHABLE{backups}"),
        Some(true) => format!("{name} ({nameserver}) override=on reachable{backups}"),
        None => format!("{name} ({nameserver}) override=on{backups}"),
    }
}

fn apply_cached_active_network_roster(app: &mut AppConfig, path: &Path) -> Result<bool> {
    let Some(network) = app.active_network_opt() else {
        return Ok(false);
    };
    let network_id = network.network_id.clone();
    let Some(signed_roster) = load_signed_rosters(&signed_rosters_file_path(path))?
        .latest_for(&network_id)
        .cloned()
    else {
        return Ok(false);
    };
    app.apply_verified_admin_signed_shared_roster(&signed_roster)
}

fn runtime_local_tunnel_ip(app: &AppConfig, network_id: &str) -> String {
    if let Ok(own_pubkey) = app.own_nostr_pubkey_hex()
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &own_pubkey)
    {
        return tunnel_ip;
    }
    app.node.tunnel_ip.clone()
}

fn runtime_peer_tunnel_ips(app: &AppConfig, network_id: &str) -> Vec<String> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut ips = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant) != own_pubkey.as_ref())
        .filter_map(|participant| derive_mesh_tunnel_ip(network_id, &participant))
        .collect::<Vec<_>>();
    ips.sort();
    ips.dedup();
    ips
}

fn configured_fips_peer_announcements(app: &AppConfig, network_id: &str) -> Vec<PeerAnnouncement> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut peers = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant) != own_pubkey.as_ref())
        .filter_map(|participant| {
            let tunnel_ip = derive_mesh_tunnel_ip(network_id, &participant)?;
            let node_id = app
                .magic_dns_name_for_participant(&participant)
                .or_else(|| app.peer_alias(&participant))
                .unwrap_or_else(|| participant.clone());
            Some(PeerAnnouncement {
                node_id,
                public_key: participant,
                endpoint: "fips".to_string(),
                local_endpoint: None,
                public_endpoint: None,
                tunnel_ip,
                advertised_routes: Vec::new(),
                timestamp: 0,
            })
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    peers
}

pub(crate) fn shared_roster_publish_allowed(
    app: &AppConfig,
    network_id: &str,
    own_pubkey: &str,
    signed_by: &str,
) -> bool {
    let Ok(own_pubkey) = normalize_nostr_pubkey(own_pubkey) else {
        return false;
    };
    if !app.is_network_admin(network_id, &own_pubkey) {
        return false;
    }

    let signed_by = normalize_nostr_pubkey(signed_by).unwrap_or_default();
    signed_by.is_empty() || signed_by == own_pubkey
}

fn network_roster_from_shared(shared: &SharedNetworkRoster) -> NetworkRoster {
    NetworkRoster {
        dns_node: shared.dns_node.clone(),
        dns_backup_nodes: shared.dns_backup_nodes.clone(),
        dns_override: shared.dns_override,
        network_name: shared.name.clone(),
        devices: shared.devices.clone(),
        admins: shared.admins.clone(),
        aliases: shared.aliases.clone(),
        signed_at: if shared.updated_at > 0 {
            shared.updated_at
        } else {
            unix_timestamp()
        },
    }
}

fn signed_roster_matches_shared(
    signed_roster: &SignedRoster,
    shared: &SharedNetworkRoster,
) -> bool {
    let Ok(signed_network_id) = signed_roster.network_id() else {
        return false;
    };
    if normalize_runtime_network_id(&signed_network_id)
        != normalize_runtime_network_id(&shared.network_id)
    {
        return false;
    }

    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    let shared_signed_by = normalize_nostr_pubkey(&shared.signed_by).unwrap_or_default();
    if shared_signed_by.is_empty() || shared_signed_by != signed_by {
        return false;
    }

    let Ok(roster) = signed_roster.roster() else {
        return false;
    };
    roster == network_roster_from_shared(shared)
}

fn active_signed_roster_for_sync(
    app: &AppConfig,
    config_path: &Path,
    allow_forwarded: bool,
) -> Result<Option<SignedRoster>> {
    let Some(network) = app.active_network_opt() else {
        return Ok(None);
    };
    let shared = app.shared_network_roster(&network.id)?;
    let store_path = signed_rosters_file_path(config_path);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut store = load_signed_rosters(&store_path)?;
    if let Some(stored) = store
        .latest_for(&shared.network_id)
        .filter(|stored| signed_roster_matches_shared(stored, &shared))
        .filter(|stored| {
            allow_forwarded
                || own_pubkey.as_deref().is_some_and(|own_pubkey| {
                    stored.signer_pubkey_hex().ok().as_deref() == Some(own_pubkey)
                })
        })
        .cloned()
    {
        if store.record_removals(&stored, &network.removed_devices)? {
            nostr_vpn_core::signed_rosters::write_signed_rosters(&store_path, &store)?;
        }
        return Ok(Some(stored));
    }

    let Some(own_pubkey) = own_pubkey else {
        return Ok(None);
    };
    if !shared_roster_publish_allowed(app, &network.id, &own_pubkey, &shared.signed_by) {
        return Ok(None);
    }

    let signed_roster = SignedRoster::sign(
        &shared.network_id,
        network_roster_from_shared(&shared),
        &app.nostr_keys()?,
    )?;
    store.upsert(signed_roster.clone())?;
    store.record_removals(&signed_roster, &network.removed_devices)?;
    nostr_vpn_core::signed_rosters::write_signed_rosters(&store_path, &store)?;
    Ok(Some(signed_roster))
}

fn signed_roster_is_current_for_app(
    app: &AppConfig,
    network_id: &str,
    signed_roster: &SignedRoster,
) -> bool {
    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    app.networks.iter().any(|network| {
        normalize_runtime_network_id(&network.network_id)
            == normalize_runtime_network_id(network_id)
            && network.shared_roster_updated_at == signed_roster.signed_at()
            && normalize_nostr_pubkey(&network.shared_roster_signed_by)
                .is_ok_and(|value| value == signed_by)
    })
}
const FIPS_ROSTER_RESEND_SECS: u64 = 60;
#[derive(Default)]
struct FipsRosterSyncState {
    sent_by_peer: HashMap<String, FipsRosterSentState>,
    source: Option<(String, u64, String)>,
    roster: Option<SignedRoster>,
    removal_rosters: HashMap<String, SignedRoster>,
}
struct FipsRosterSentState {
    hash: String,
    sent_at: u64,
}
fn sync_fips_roster_with_connected_peers(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    state: &mut FipsRosterSyncState,
) -> Result<usize> {
    let source = app.active_network_opt().map(|network| {
        (
            normalize_runtime_network_id(&network.network_id),
            network.shared_roster_updated_at,
            network.shared_roster_signed_by.clone(),
        )
    });
    if state.source != source {
        state.roster = active_signed_roster_for_sync(app, config_path, true)?;
        let mut store = load_signed_rosters(&signed_rosters_file_path(config_path))?;
        state.removal_rosters = source
            .as_ref()
            .and_then(|(network_id, _, _)| store.removals.remove(network_id))
            .unwrap_or_default();
        state.source = state.roster.as_ref().map(|_| source).unwrap_or_default();
    }
    let Some(signed_roster) = state.roster.clone() else {
        return Ok(0);
    };
    let now = unix_timestamp();
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let roster_peers = app
        .active_network_signal_pubkeys_hex()
        .into_iter()
        .collect::<HashSet<_>>();
    let connected = runtime
        .peer_statuses()
        .into_iter()
        .filter(|status| status.connected)
        .filter(|status| own_pubkey.as_deref() != Some(status.pubkey.as_str()))
        .map(|status| status.pubkey)
        .collect::<HashSet<_>>();

    let awaiting_approval = nostr_vpn_core::join_delivery::load_join_rosters(config_path)
        .into_iter()
        .map(|(_, queued)| queued.recipient_npub)
        .collect();
    let (connected, _) = split_ready_fips_roster_recipients(
        connected
            .into_iter()
            .filter(|peer| roster_peers.contains(peer) || state.removal_rosters.contains_key(peer))
            .collect(),
        &awaiting_approval,
    );

    state
        .sent_by_peer
        .retain(|peer, _| connected.contains(peer));

    let mut sent = 0usize;
    for peer in connected {
        // Former members use ordinary roster delivery, but only receive the
        // first signed roster that excluded them, never later revisions.
        let roster = state.removal_rosters.get(&peer).unwrap_or(&signed_roster);
        let roster_hash = roster.content_hash();
        if state.sent_by_peer.get(&peer).is_some_and(|sent| {
            sent.hash == roster_hash && now.saturating_sub(sent.sent_at) < FIPS_ROSTER_RESEND_SECS
        }) {
            continue;
        }
        runtime.enqueue_roster(&peer, roster.clone())?;
        state.sent_by_peer.insert(
            peer,
            FipsRosterSentState {
                hash: roster_hash,
                sent_at: now,
            },
        );
        sent += 1;
    }
    Ok(sent)
}

/// `nvpn status --json` is what a DNS box's own healthcheck reads, so the
/// role names are a contract, not just display text.
#[cfg(test)]
mod network_dns_status_tests {
    use super::*;
    use nostr_sdk::prelude::{Keys, ToBech32};

    fn app_with_roles() -> (AppConfig, String, String, String) {
        let keys = Keys::generate();
        let own = keys.public_key().to_hex();
        let primary = Keys::generate().public_key().to_hex();
        let backup = Keys::generate().public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.nostr.public_key = own.clone();
        app.networks[0].enabled = true;
        app.networks[0].network_id = "network-dns".to_string();
        app.networks[0].admins = vec![own.clone()];
        app.networks[0].devices = vec![own.clone(), primary.clone(), backup.clone()];
        (app, own, primary, backup)
    }

    fn select(app: &mut AppConfig, primary: &str, backups: &[String]) {
        let network_id = app.networks[0].id.clone();
        app.set_network_dns(&network_id, primary, true)
            .expect("select primary");
        app.set_network_dns_backups(&network_id, backups)
            .expect("select backups");
    }

    #[test]
    fn status_names_the_primary_the_backup_and_a_client() {
        let (mut app, own, primary, backup) = app_with_roles();

        select(&mut app, &own, std::slice::from_ref(&backup));
        assert_eq!(network_dns_status_json(&app, None)["role"], "nameserver");

        select(&mut app, &primary, std::slice::from_ref(&own));
        let status = network_dns_status_json(&app, None);
        assert_eq!(status["role"], "backup");
        assert_eq!(status["enforced"], false);

        select(&mut app, &primary, std::slice::from_ref(&backup));
        let status = network_dns_status_json(&app, None);
        assert_eq!(status["role"], "client");
        assert_eq!(status["backups"], serde_json::json!([backup]));
        assert_eq!(
            status["nameserver_ips"].as_array().map(Vec::len),
            Some(2),
            "a client must be handed the primary and the backup"
        );
    }
}
