use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use nostr_vpn_core::config::normalize_nostr_pubkey;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};

use crate::invite::{parse_network_invite, to_npub};

pub(crate) const LAN_PAIRING_ANNOUNCEMENT_VERSION: u8 = 2;
pub(crate) const LAN_PAIRING_DURATION: Duration = Duration::from_mins(15);
pub(crate) const LAN_PAIRING_STALE_AFTER: Duration = Duration::from_secs(16);

const LAN_PAIRING_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 73);
const LAN_PAIRING_PORT: u16 = 38_911;
const LAN_PAIRING_ANNOUNCE_EVERY: Duration = Duration::from_secs(3);
const LAN_PAIRING_READ_TIMEOUT: Duration = Duration::from_millis(250);
const LAN_PAIRING_BUFFER_BYTES: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LanPairingSignal {
    pub(crate) npub: String,
    pub(crate) node_name: String,
    pub(crate) endpoint: String,
    pub(crate) network_name: String,
    pub(crate) network_id: String,
    pub(crate) invite: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LanPairingAnnouncement {
    pub(crate) npub: String,
    pub(crate) node_name: String,
    pub(crate) endpoint: String,
    pub(crate) invite: String,
}

#[derive(Debug)]
pub(crate) struct LanPairingWorker {
    receiver: Receiver<LanPairingSignal>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LanPairingAnnouncementPayload {
    v: u8,
    npub: String,
    #[serde(default)]
    node_name: String,
    #[serde(default)]
    endpoint: String,
    invite: String,
    #[serde(default)]
    timestamp: u64,
}

impl LanPairingWorker {
    pub(crate) fn drain(&mut self) -> Vec<LanPairingSignal> {
        let mut signals = Vec::new();
        while let Ok(signal) = self.receiver.try_recv() {
            signals.push(signal);
        }
        signals
    }

    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LanPairingWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn spawn_lan_pairing_worker(
    announcement: LanPairingAnnouncement,
    expires_at: SystemTime,
) -> Result<LanPairingWorker> {
    let socket = bind_lan_pairing_socket()?;

    let (sender, receiver) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let own_npub = announcement.npub.clone();
    let handle = thread::spawn(move || {
        run_lan_pairing_loop(
            &socket,
            &announcement,
            &own_npub,
            expires_at,
            &thread_stop,
            &sender,
        );
    });

    Ok(LanPairingWorker {
        receiver,
        stop,
        handle: Some(handle),
    })
}

fn bind_lan_pairing_socket() -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create LAN pairing UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("failed to configure LAN pairing socket reuse")?;
    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin")
    ))]
    socket
        .set_reuse_port(true)
        .context("failed to configure LAN pairing port reuse")?;
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LAN_PAIRING_PORT).into())
        .context("failed to bind LAN pairing UDP socket")?;

    let socket: UdpSocket = socket.into();
    socket
        .join_multicast_v4(&LAN_PAIRING_ADDR, &Ipv4Addr::UNSPECIFIED)
        .context("failed to join LAN pairing multicast group")?;
    socket
        .set_read_timeout(Some(LAN_PAIRING_READ_TIMEOUT))
        .context("failed to configure LAN pairing socket timeout")?;
    socket
        .set_multicast_loop_v4(true)
        .context("failed to configure LAN pairing multicast loopback")?;
    socket
        .set_multicast_ttl_v4(1)
        .context("failed to configure LAN pairing multicast TTL")?;
    Ok(socket)
}

pub(crate) fn decode_lan_pairing_payload(
    payload: &[u8],
    own_npub: &str,
) -> Result<Option<LanPairingSignal>> {
    let announcement = serde_json::from_slice::<LanPairingAnnouncementPayload>(payload)
        .context("failed to parse LAN pairing announcement")?;
    if announcement.v != LAN_PAIRING_ANNOUNCEMENT_VERSION {
        return Ok(None);
    }

    let sender_npub = normalize_nostr_pubkey(&announcement.npub).map(|value| to_npub(&value))?;
    if sender_npub == own_npub.trim() {
        return Ok(None);
    }

    let invite =
        parse_network_invite(&announcement.invite).context("failed to parse LAN pairing invite")?;
    if !invite.admins.iter().any(|admin| admin == &sender_npub) {
        return Ok(None);
    }

    Ok(Some(LanPairingSignal {
        npub: sender_npub,
        node_name: announcement.node_name.trim().to_string(),
        endpoint: announcement.endpoint.trim().to_string(),
        network_name: if invite.network_name.trim().is_empty() {
            invite.network_id.clone()
        } else {
            invite.network_name
        },
        network_id: invite.network_id,
        invite: announcement.invite.trim().to_string(),
    }))
}

fn run_lan_pairing_loop(
    socket: &UdpSocket,
    announcement: &LanPairingAnnouncement,
    own_npub: &str,
    expires_at: SystemTime,
    stop: &Arc<AtomicBool>,
    sender: &mpsc::Sender<LanPairingSignal>,
) {
    let target = SocketAddrV4::new(LAN_PAIRING_ADDR, LAN_PAIRING_PORT);
    let mut next_announcement = SystemTime::UNIX_EPOCH;
    let mut buffer = [0_u8; LAN_PAIRING_BUFFER_BYTES];

    while !stop.load(Ordering::Relaxed) && SystemTime::now() < expires_at {
        let now = SystemTime::now();
        if now >= next_announcement {
            let _ = send_lan_pairing_announcement(socket, target, announcement);
            next_announcement = now
                .checked_add(LAN_PAIRING_ANNOUNCE_EVERY)
                .unwrap_or(expires_at);
        }

        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => {
                if let Ok(Some(signal)) = decode_lan_pairing_payload(&buffer[..len], own_npub) {
                    let _ = sender.send(signal);
                }
            }
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {
            }
            Err(_) => break,
        }
    }
}

fn send_lan_pairing_announcement(
    socket: &UdpSocket,
    target: SocketAddrV4,
    announcement: &LanPairingAnnouncement,
) -> Result<()> {
    let payload = LanPairingAnnouncementPayload {
        v: LAN_PAIRING_ANNOUNCEMENT_VERSION,
        npub: announcement.npub.clone(),
        node_name: announcement.node_name.clone(),
        endpoint: announcement.endpoint.clone(),
        invite: announcement.invite.clone(),
        timestamp: unix_timestamp(),
    };
    let encoded = serde_json::to_vec(&payload).context("failed to encode LAN announcement")?;
    socket
        .send_to(&encoded, target)
        .context("failed to publish LAN announcement")?;
    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use nostr_sdk::prelude::ToBech32;
    use serde_json::json;
    use std::time::Instant;

    use super::*;

    #[test]
    fn decodes_lan_announcement_with_invite_metadata() {
        let admin_npub = nostr_sdk::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("npub");
        let own_npub = nostr_sdk::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("npub");
        let invite = invite_for(&admin_npub, "Office mesh", "office-mesh");
        let payload = json!({
            "v": LAN_PAIRING_ANNOUNCEMENT_VERSION,
            "npub": admin_npub,
            "nodeName": "Alice Mac",
            "endpoint": "192.0.2.10:51820",
            "invite": invite,
            "timestamp": 42
        })
        .to_string();

        let signal = decode_lan_pairing_payload(payload.as_bytes(), &own_npub)
            .expect("decode")
            .expect("peer");

        assert_eq!(signal.node_name, "Alice Mac");
        assert_eq!(signal.endpoint, "192.0.2.10:51820");
        assert_eq!(signal.network_name, "Office mesh");
        assert_eq!(signal.network_id, "office-mesh");
    }

    #[test]
    fn lan_pairing_workers_exchange_invites_over_looped_multicast() {
        let alice_npub = nostr_sdk::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("alice npub");
        let bob_npub = nostr_sdk::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("bob npub");
        let alice_invite = invite_for(&alice_npub, "Alice mesh", "alice-mesh");
        let bob_invite = invite_for(&bob_npub, "Bob mesh", "bob-mesh");
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(7))
            .expect("expiry");

        let mut alice = spawn_lan_pairing_worker(
            LanPairingAnnouncement {
                npub: alice_npub.clone(),
                node_name: "Alice".to_string(),
                endpoint: "192.0.2.10:51820".to_string(),
                invite: alice_invite,
            },
            expires_at,
        )
        .expect("start alice LAN pairing");
        let mut bob = spawn_lan_pairing_worker(
            LanPairingAnnouncement {
                npub: bob_npub.clone(),
                node_name: "Bob".to_string(),
                endpoint: "192.0.2.11:51820".to_string(),
                invite: bob_invite,
            },
            expires_at,
        )
        .expect("start bob LAN pairing");

        let deadline = Instant::now() + Duration::from_secs(8);
        let mut alice_saw_bob = false;
        let mut bob_saw_alice = false;
        while Instant::now() < deadline && !(alice_saw_bob && bob_saw_alice) {
            alice_saw_bob |= alice.drain().into_iter().any(|signal| {
                signal.npub == bob_npub
                    && signal.node_name == "Bob"
                    && signal.network_id == "bob-mesh"
            });
            bob_saw_alice |= bob.drain().into_iter().any(|signal| {
                signal.npub == alice_npub
                    && signal.node_name == "Alice"
                    && signal.network_id == "alice-mesh"
            });
            thread::sleep(Duration::from_millis(100));
        }

        alice.stop();
        bob.stop();

        assert!(alice_saw_bob, "alice did not receive bob's LAN invite");
        assert!(bob_saw_alice, "bob did not receive alice's LAN invite");
    }

    fn invite_for(admin_npub: &str, network_name: &str, network_id: &str) -> String {
        let payload = json!({
            "v": 3,
            "networkName": network_name,
            "networkId": network_id,
            "admins": [admin_npub],
            "relays": ["wss://relay.example"]
        })
        .to_string();
        format!("nvpn://invite/{}", URL_SAFE_NO_PAD.encode(payload))
    }
}
