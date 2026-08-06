//! Applying a network's DNS policy to macOS's *primary* resolver.
//!
//! The rest of secure DNS installs `/etc/resolver` files pointing at the local
//! stub. That works for scoped lookups like MagicDNS, but macOS treats those
//! files as *supplemental*: a file carrying `domain .` is loaded as a
//! domain-less resolver far down the list, never as resolver #1, and ordinary
//! application lookups keep using the network service's own DNS. Observed on a
//! live machine with the override active and reachable:
//!
//! ```text
//! resolver #1   nameserver[0] : 192.168.4.1     <- every app used this
//! resolver #9   nameserver[0] : 127.0.0.1       <- `domain .`, never consulted
//!               port          : 1053
//! ```
//!
//! So the network DNS override silently failed *open* on macOS: the daemon
//! reported `override=on reachable` while queries went to the local router.
//! That inverts the guarantee the override exists to make, which is why this
//! path sets the service's DNS directly instead.
//!
//! `networksetup` only accepts addresses, never ports — which is fine here and
//! is the reason this is scoped to the network-DNS case specifically. The
//! network's nameserver is a real resolver listening on 53, so no stub needs to
//! sit in front of it.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Saved DNS for one network service, captured before we change it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ServiceDnsSnapshot {
    pub(crate) service: String,
    /// Empty means the service had no explicit servers (DHCP-provided), which
    /// `networksetup` expresses as the literal argument `Empty`.
    pub(crate) servers: Vec<String>,
}

/// What the daemon must undo. Persisted next to the config so an unclean exit
/// can still be repaired: leaving a machine pointed at a mesh address that is
/// no longer reachable breaks *all* name resolution, which is a far worse
/// failure than the one this module fixes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PrimaryDnsRestoreState {
    pub(crate) services: Vec<ServiceDnsSnapshot>,
}

pub(crate) fn restore_state_file_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("macos-primary-dns-restore.json")
}

/// Services `networksetup -listallnetworkservices` reports as usable.
///
/// The first line is a human-readable preamble, and disabled services are
/// prefixed with `*`. Both are skipped: setting DNS on a disabled service
/// fails, and failing the whole apply because Thunderbolt Bridge is off would
/// be absurd.
pub(crate) fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(ToString::to_string)
        .collect()
}

/// Current servers for a service.
///
/// `networksetup -getdnsservers` prints one address per line, or a sentence
/// when nothing is configured. Anything that isn't an address is treated as
/// "none configured" rather than parsed, because the sentence is localized and
/// matching on its text would break on non-English systems.
pub(crate) fn parse_dns_servers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| line.parse::<std::net::IpAddr>().is_ok())
        .map(ToString::to_string)
        .collect()
}

/// Arguments for `networksetup -setdnsservers <service> ...`.
///
/// Restoring a service that had no explicit servers requires the literal
/// `Empty`; passing no arguments at all is a usage error.
pub(crate) fn set_dns_args(service: &str, servers: &[String]) -> Vec<String> {
    let mut args = vec!["-setdnsservers".to_string(), service.to_string()];
    if servers.is_empty() {
        args.push("Empty".to_string());
    } else {
        args.extend(servers.iter().cloned());
    }
    args
}

#[cfg(target_os = "macos")]
fn networksetup(args: &[String]) -> Result<String> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .context("failed to run networksetup")?;
    if !output.status.success() {
        let details = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "networksetup {} failed: {}",
            args.join(" "),
            details.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(not(target_os = "macos"))]
fn networksetup(_args: &[String]) -> Result<String> {
    Err(anyhow::anyhow!("networksetup is macOS-only"))
}

/// Point every enabled service at `nameservers`, returning what to undo.
///
/// The snapshot is captured and persisted *before* the first change, so a crash
/// between two services still leaves a complete record of the originals.
pub(crate) fn apply(
    nameservers: &[String],
    config_path: &Path,
) -> Result<PrimaryDnsRestoreState> {
    let services = parse_network_services(&networksetup(&["-listallnetworkservices".to_string()])?);
    let mut state = PrimaryDnsRestoreState::default();
    for service in &services {
        let current = parse_dns_servers(&networksetup(&[
            "-getdnsservers".to_string(),
            service.clone(),
        ])?);
        // Already ours from an earlier run: recording it would overwrite the
        // real originals with the override's own addresses and strand the
        // machine after restore.
        if current == nameservers {
            continue;
        }
        state.services.push(ServiceDnsSnapshot {
            service: service.clone(),
            servers: current,
        });
    }

    if state.services.is_empty() {
        return Ok(state);
    }
    write_restore_state(&restore_state_file_path(config_path), &state)?;

    for snapshot in &state.services {
        networksetup(&set_dns_args(&snapshot.service, nameservers))?;
    }
    Ok(state)
}

/// Put back what `apply` captured. Best-effort by design: a service that has
/// since been removed must not stop the remaining ones from being restored.
pub(crate) fn restore(state: &PrimaryDnsRestoreState, config_path: &Path) {
    for snapshot in &state.services {
        let _ = networksetup(&set_dns_args(&snapshot.service, &snapshot.servers));
    }
    let _ = std::fs::remove_file(restore_state_file_path(config_path));
}

/// Restore DNS stranded by a daemon that exited without running `restore`.
/// Called during startup repair, before anything else touches system DNS.
pub(crate) fn restore_stale(config_path: &Path) {
    let path = restore_state_file_path(config_path);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(state) = serde_json::from_str::<PrimaryDnsRestoreState>(&contents) else {
        // Unreadable state is still evidence something was changed, but we have
        // no originals to put back; drop the file rather than retrying forever.
        let _ = std::fs::remove_file(&path);
        return;
    };
    restore(&state, config_path);
}

fn write_restore_state(path: &Path, state: &PrimaryDnsRestoreState) -> Result<()> {
    let encoded = serde_json::to_string_pretty(state)
        .context("failed to encode macOS primary DNS restore state")?;
    std::fs::write(path, encoded)
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_services_skip_the_preamble_and_disabled_entries() {
        let output = "An asterisk (*) denotes that a network service is disabled.\n\
                      Wi-Fi\n\
                      *Thunderbolt Bridge\n\
                      Ethernet\n";

        assert_eq!(
            parse_network_services(output),
            vec!["Wi-Fi".to_string(), "Ethernet".to_string()]
        );
    }

    #[test]
    fn dns_servers_parse_addresses_and_ignore_the_empty_sentence() {
        assert_eq!(
            parse_dns_servers("192.168.4.1\nfd2d:b864:a993::1\n"),
            vec!["192.168.4.1".to_string(), "fd2d:b864:a993::1".to_string()]
        );
        // Localized on non-English systems, so it is rejected by shape rather
        // than by matching its wording.
        assert!(parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
    }

    #[test]
    fn restoring_a_service_without_servers_passes_empty() {
        assert_eq!(
            set_dns_args("Wi-Fi", &[]),
            vec![
                "-setdnsservers".to_string(),
                "Wi-Fi".to_string(),
                "Empty".to_string()
            ]
        );
        assert_eq!(
            set_dns_args("Wi-Fi", &["10.44.82.211".to_string()]),
            vec![
                "-setdnsservers".to_string(),
                "Wi-Fi".to_string(),
                "10.44.82.211".to_string()
            ]
        );
    }

    #[test]
    fn restore_state_round_trips_through_the_file_format() {
        let state = PrimaryDnsRestoreState {
            services: vec![
                ServiceDnsSnapshot {
                    service: "Wi-Fi".to_string(),
                    servers: vec!["192.168.4.1".to_string()],
                },
                ServiceDnsSnapshot {
                    service: "Ethernet".to_string(),
                    servers: Vec::new(),
                },
            ],
        };

        let encoded = serde_json::to_string(&state).expect("encode");
        let decoded: PrimaryDnsRestoreState = serde_json::from_str(&encoded).expect("decode");

        assert_eq!(decoded, state);
        assert!(decoded.services[1].servers.is_empty());
    }

    #[test]
    fn restore_state_lives_beside_the_config() {
        assert_eq!(
            restore_state_file_path(Path::new("/tmp/nvpn/config.toml")),
            PathBuf::from("/tmp/nvpn/macos-primary-dns-restore.json")
        );
    }
}
