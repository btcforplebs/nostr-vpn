impl AppConfig {
    fn seed_self_magic_dns_alias_for_first_owned_network(&mut self) {
        if !self.networks.is_empty() {
            return;
        }

        let _ = self.ensure_self_magic_dns_alias();
    }

    pub fn rename_network(&mut self, network_id: &str, name: &str) -> Result<()> {
        let normalized = name.trim();
        if normalized.is_empty() {
            return Err(anyhow::anyhow!("network name cannot be empty"));
        }
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if own_pubkey.as_deref().is_none_or(|own_pubkey| {
                !network.admins.iter().any(|admin| admin == own_pubkey)
            }) {
                return Err(anyhow::anyhow!("only a network admin can rename it"));
            }
            network.name = normalized.to_string();
        }
        self.note_network_roster_local_change(network_id)?;
        Ok(())
    }

    pub fn remove_network(&mut self, network_id: &str) -> Result<()> {
        let previous_len = self.networks.len();
        self.networks.retain(|network| network.id != network_id);
        if self.networks.len() == previous_len {
            return Err(anyhow::anyhow!("network not found"));
        }

        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(())
    }

    /// Join an existing network using identifiers exchanged directly with an
    /// admin. The admin must add this device to the same network separately.
    pub fn add_manual_join_network(
        &mut self,
        admin_device_id: &str,
        mesh_network_id: &str,
    ) -> Result<String> {
        let admin = normalize_nostr_pubkey(admin_device_id.trim())?;
        let mesh_id = normalize_runtime_network_id(mesh_network_id);
        if mesh_id.is_empty() {
            return Err(anyhow::anyhow!("network id is empty"));
        }
        if self
            .networks
            .iter()
            .any(|network| normalize_runtime_network_id(&network.network_id) == mesh_id)
        {
            return Err(anyhow::anyhow!("network id is already configured"));
        }

        let network_id = self.add_network("");
        self.set_network_enabled(&network_id, true)?;
        self.set_network_mesh_id(&network_id, &mesh_id)?;
        let network = self
            .network_by_id_mut(&network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        // Trust only the two identifiers exchanged out of band until this
        // device appears in the admin's signed roster.
        network.devices = vec![admin.clone()];
        network.admins = vec![admin.clone()];
        network.join_request_admin.clone_from(&admin);
        network.local_identity_confirmation_pending = true;
        network.outbound_join_request = None;
        network.inbound_join_requests.clear();
        network.shared_roster_updated_at = 0;
        network.shared_roster_signed_by.clear();
        self.clear_pending_nostr_join_request();
        let _ = self.set_peer_alias(&admin, "admin");
        Ok(network_id)
    }

    pub fn set_network_enabled(&mut self, network_id: &str, enabled: bool) -> Result<()> {
        let index = self
            .networks
            .iter()
            .position(|network| network.id == network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;

        if enabled {
            for (candidate_index, network) in self.networks.iter_mut().enumerate() {
                network.enabled = candidate_index == index;
            }
            return Ok(());
        }

        self.networks[index].enabled = false;
        Ok(())
    }

    pub fn set_network_join_requests_enabled(
        &mut self,
        network_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network.listen_for_join_requests = enabled;
        Ok(())
    }

    pub fn join_requests_enabled(&self) -> bool {
        self.networks
            .iter()
            .any(|network| network.enabled && network.listen_for_join_requests)
    }

    pub fn record_inbound_join_request(
        &mut self,
        requested_network_id: &str,
        requested_join_secret: &str,
        requester: &str,
        requester_node_name: &str,
        requested_at: u64,
    ) -> Result<Option<String>> {
        let requested_network_id = normalize_runtime_network_id(requested_network_id);
        if requested_network_id.is_empty() {
            return Ok(None);
        }

        let requester = normalize_nostr_pubkey(requester)?;
        let requester_node_name = requester_node_name.trim().to_string();
        let Some(network) = self.networks.iter_mut().find(|network| {
            network.listen_for_join_requests
                && normalize_runtime_network_id(&network.network_id) == requested_network_id
        }) else {
            return Ok(None);
        };
        if !network.join_secret.trim().is_empty()
            && network.join_secret.trim() != requested_join_secret.trim()
        {
            return Ok(None);
        }

        if network
            .devices
            .iter()
            .any(|participant| participant == &requester)
        {
            return Ok(None);
        }

        let mut changed = false;
        if let Some(existing) = network
            .inbound_join_requests
            .iter_mut()
            .find(|request| request.requester == requester)
        {
            if existing.requested_at < requested_at
                || existing.requester_node_name != requester_node_name
            {
                existing.requested_at = existing.requested_at.max(requested_at);
                existing.requester_node_name = requester_node_name;
                changed = true;
            }
        } else {
            network
                .inbound_join_requests
                .push(PendingInboundJoinRequest {
                    requester,
                    requester_node_name,
                    requested_at,
                });
            network
                .inbound_join_requests
                .sort_by(|left, right| left.requester.cmp(&right.requester));
            changed = true;
        }

        if changed {
            Ok(Some(network.name.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn reject_inbound_join_request(&mut self, network_id: &str, requester: &str) -> Result<()> {
        let requester = normalize_nostr_pubkey(requester)?;
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network
            .inbound_join_requests
            .retain(|pending| pending.requester != requester);
        Ok(())
    }

    pub fn set_network_mesh_id(&mut self, network_id: &str, mesh_id: &str) -> Result<()> {
        let normalized = normalize_runtime_network_id(mesh_id);
        if normalized.is_empty() {
            return Err(anyhow::anyhow!("network id cannot be empty"));
        }

        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network.network_id = normalized;

        Ok(())
    }

    pub fn set_active_network_id(&mut self, network_id: &str) -> Result<()> {
        if self.active_network_opt().is_none() {
            let first_network_entry_id = self
                .networks
                .first()
                .map(|network| network.id.clone())
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            self.set_network_enabled(&first_network_entry_id, true)?;
        }
        let active_network_entry_id = self
            .active_network_opt()
            .ok_or_else(|| anyhow::anyhow!("network not found"))?
            .id
            .clone();
        self.set_network_mesh_id(&active_network_entry_id, network_id)
    }

    pub fn add_device_to_network(
        &mut self,
        network_id: &str,
        device: &str,
    ) -> Result<String> {
        let normalized = normalize_nostr_pubkey(device)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            network
                .removed_devices
                .retain(|removed| removed != &normalized);
            if !network
                .devices
                .iter()
                .any(|configured| configured == &normalized)
            {
                network.devices.push(normalized.clone());
                network.devices.sort();
                network.devices.dedup();
            }
        }

        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(normalized)
    }

    pub fn add_participant_to_network(
        &mut self,
        network_id: &str,
        participant: &str,
    ) -> Result<String> {
        self.add_device_to_network(network_id, participant)
    }

    pub fn remove_device_from_network(
        &mut self,
        network_id: &str,
        device: &str,
    ) -> Result<()> {
        let normalized = normalize_nostr_pubkey(device)?;
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if network.admins.len() == 1 && network.admins.iter().any(|admin| admin == &normalized)
            {
                return Err(anyhow::anyhow!("cannot remove the last admin"));
            }
            let was_member = network
                .devices
                .iter()
                .chain(network.admins.iter())
                .any(|configured| configured == &normalized);
            let can_publish_removal = own_pubkey
                .as_deref()
                .is_some_and(|own| network.admins.iter().any(|admin| admin == own));
            network
                .devices
                .retain(|configured| configured != &normalized);
            network
                .admins
                .retain(|configured| configured != &normalized);
            if was_member
                && can_publish_removal
                && !network
                .removed_devices
                .iter()
                .any(|removed| removed == &normalized)
            {
                network.removed_devices.push(normalized.clone());
                network.removed_devices.sort();
            }
            if network.join_request_admin == normalized {
                network.join_request_admin = network.admins.first().cloned().unwrap_or_default();
            }
            // Removing the nameserver leaves the override on, so members fail
            // closed until an admin picks another one or turns it off.
            if network.dns_node == normalized {
                network.dns_node = String::new();
            }
            network
                .dns_backup_nodes
                .retain(|backup| backup != &normalized);
        }

        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(())
    }

    pub fn remove_participant_from_network(
        &mut self,
        network_id: &str,
        participant: &str,
    ) -> Result<()> {
        self.remove_device_from_network(network_id, participant)
    }

    pub fn add_admin_to_network(&mut self, network_id: &str, admin: &str) -> Result<String> {
        let normalized = normalize_nostr_pubkey(admin)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if !network
                .admins
                .iter()
                .any(|configured| configured == &normalized)
            {
                network.admins.push(normalized.clone());
                network.admins.sort();
                network.admins.dedup();
            }
            if network.join_request_admin.is_empty() {
                network.join_request_admin = normalized.clone();
            }
        }
        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        Ok(normalized)
    }

    pub fn remove_admin_from_network(&mut self, network_id: &str, admin: &str) -> Result<()> {
        let normalized = normalize_nostr_pubkey(admin)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if !network
                .admins
                .iter()
                .any(|configured| configured == &normalized)
            {
                return Ok(());
            }
            if network.admins.len() <= 1 {
                return Err(anyhow::anyhow!("cannot remove the last admin"));
            }
            network
                .admins
                .retain(|configured| configured != &normalized);
            if network.join_request_admin == normalized {
                network.join_request_admin = network.admins.first().cloned().unwrap_or_default();
            }
        }
        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        Ok(())
    }

    /// Point a network at one of its own members as the network nameserver.
    /// Pass an empty `dns_node` to clear the selection.
    ///
    /// Admin-only, enforced here rather than at each caller: a non-admin's
    /// roster is rejected by every peer anyway, so failing loudly beats
    /// writing a setting that would never take effect.
    pub fn set_network_dns(
        &mut self,
        network_id: &str,
        dns_node: &str,
        dns_override: bool,
    ) -> Result<String> {
        let normalized = if dns_node.trim().is_empty() {
            String::new()
        } else {
            normalize_nostr_pubkey(dns_node)?
        };
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if own_pubkey
                .as_deref()
                .is_none_or(|own| !network.admins.iter().any(|admin| admin == own))
            {
                return Err(anyhow::anyhow!(
                    "only a network admin can change the network DNS settings"
                ));
            }
            if !normalized.is_empty()
                && !network_has_member(network, &normalized, own_pubkey.as_deref())
            {
                return Err(anyhow::anyhow!(
                    "the DNS device must be a member of this network"
                ));
            }
            network.dns_override = dns_override && !normalized.is_empty();
            network.dns_node = normalized.clone();
            // A device promoted to primary stops being its own backup.
            network
                .dns_backup_nodes
                .retain(|backup| backup != &normalized);
        }
        self.note_network_roster_local_change(network_id)?;
        Ok(normalized)
    }

    /// Replace a network's backup nameservers, in the order members should
    /// try them after the primary. An empty list clears them.
    ///
    /// Admin-only, like [`Self::set_network_dns`]. Every backup must already be
    /// a member, and the primary cannot also be a backup. Returns the stored
    /// list.
    pub fn set_network_dns_backups(
        &mut self,
        network_id: &str,
        backups: &[String],
    ) -> Result<Vec<String>> {
        let normalized = backups
            .iter()
            .map(|backup| backup.trim())
            .filter(|backup| !backup.is_empty())
            .map(normalize_nostr_pubkey)
            .collect::<Result<Vec<_>>>()?;
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let stored = {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if own_pubkey
                .as_deref()
                .is_none_or(|own| !network.admins.iter().any(|admin| admin == own))
            {
                return Err(anyhow::anyhow!(
                    "only a network admin can change the network DNS settings"
                ));
            }
            if let Some(stranger) = normalized
                .iter()
                .find(|backup| !network_has_member(network, backup, own_pubkey.as_deref()))
            {
                return Err(anyhow::anyhow!(
                    "backup DNS device {} must be a member of this network",
                    npub_for_pubkey_hex(stranger)
                ));
            }
            if !network.dns_node.is_empty() && normalized.contains(&network.dns_node) {
                return Err(anyhow::anyhow!(
                    "the primary DNS device cannot also be a backup"
                ));
            }
            network.dns_backup_nodes =
                normalize_dns_backup_nodes(normalized, &network.dns_node, |_| true);
            network.dns_backup_nodes.clone()
        };
        self.note_network_roster_local_change(network_id)?;
        Ok(stored)
    }

    /// Give one device a DNS role without disturbing the other boxes, in one
    /// step so the roster never passes through a half-changed state.
    ///
    /// - `Primary`: the device becomes the primary. The old primary, if any,
    ///   becomes the first backup rather than dropping out.
    /// - `Backup`: the device goes to the end of the backup list. If it was
    ///   the primary, the first backup takes its place.
    /// - `None`: the device stops serving DNS. If it was the primary, the
    ///   first backup takes its place; with no backup left the selection is
    ///   cleared, as in [`Self::set_network_dns`].
    ///
    /// The override setting is kept. Admin-only, and the device must be a
    /// member; both checks come from the two setters this calls.
    pub fn set_network_dns_role(
        &mut self,
        network_id: &str,
        device: &str,
        role: NetworkDnsRole,
    ) -> Result<()> {
        let device = normalize_nostr_pubkey(device)?;
        let (mut primary, dns_override, mut backups) = {
            let network = self
                .network_by_id(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            (
                network.dns_node.clone(),
                network.dns_override,
                network.dns_backup_nodes.clone(),
            )
        };
        backups.retain(|backup| backup != &device);
        let was_primary = primary == device;
        match role {
            NetworkDnsRole::Primary => {
                if !primary.is_empty() && !was_primary {
                    backups.insert(0, primary);
                }
                primary = device;
            }
            NetworkDnsRole::Backup | NetworkDnsRole::None => {
                if was_primary {
                    primary = if backups.is_empty() {
                        String::new()
                    } else {
                        backups.remove(0)
                    };
                }
                if role == NetworkDnsRole::Backup {
                    backups.push(device);
                }
            }
        }
        // Apply to a copy so a refused change leaves the config untouched.
        let mut next = self.clone();
        next.set_network_dns(network_id, &primary, dns_override)?;
        next.set_network_dns_backups(network_id, &backups)?;
        *self = next;
        Ok(())
    }

    pub fn network_admin_pubkeys_hex(&self, network_id: &str) -> Result<Vec<String>> {
        let network = self
            .network_by_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let mut admins = network.admins.clone();
        admins.sort();
        admins.dedup();
        Ok(admins)
    }

    pub fn network_signal_pubkeys_hex(&self, network_id: &str) -> Result<Vec<String>> {
        let network = self
            .network_by_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let mut members = network
            .devices
            .iter()
            .chain(network.admins.iter())
            .filter_map(|member| normalize_nostr_pubkey(member).ok())
            .collect::<Vec<_>>();
        members.sort();
        members.dedup();
        Ok(members)
    }

    pub fn active_network_admin_pubkeys_hex(&self) -> Vec<String> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut admins = network.admins.clone();
        admins.sort();
        admins.dedup();
        admins
    }

    pub fn active_network_signal_pubkeys_hex(&self) -> Vec<String> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut members = network
            .devices
            .iter()
            .chain(network.admins.iter())
            .filter_map(|member| normalize_nostr_pubkey(member).ok())
            .collect::<Vec<_>>();
        members.sort();
        members.dedup();
        members
    }

    pub fn is_network_admin(&self, network_id: &str, pubkey: &str) -> bool {
        let Ok(normalized) = normalize_nostr_pubkey(pubkey) else {
            return false;
        };
        self.network_by_id(network_id)
            .map(|network| network.admins.iter().any(|admin| admin == &normalized))
            .unwrap_or(false)
    }

}

#[cfg(test)]
mod active_network_tests {
    use super::AppConfig;

    #[test]
    fn setting_mesh_id_activates_the_generated_network() {
        let mut app = AppConfig::generated();
        assert!(app.active_network_opt().is_none());

        app.set_active_network_id("independent-paid-seller")
            .expect("generated network can be configured");

        assert_eq!(app.enabled_network_count(), 1);
        assert_eq!(app.effective_network_id(), "independent-paid-seller");
    }
}
