package org.nostrvpn.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nostrvpn.app.core.parseAppState

// The keys are the ones app-core writes (state_json_marks_the_dns_box_and_its_backup_for_the_apps).
class DnsBadgeTest {
    private val participants = parseAppState(
        """{"networks":[{"participants":[
            {"npub":"npub1box","servesNetworkDns":true,"servesNetworkDnsBackup":false},
            {"npub":"npub1pi","servesNetworkDns":false,"servesNetworkDnsBackup":true},
            {"npub":"npub1phone"}
        ]}]}""",
    ).networks.single().participants

    @Test
    fun theDnsBoxIsMarkedAsTheDnsServer() {
        val box = participants.single { it.npub == "npub1box" }
        assertTrue(box.servesNetworkDns)
        assertFalse(box.servesNetworkDnsBackup)
    }

    @Test
    fun aBackupBoxIsMarkedAsADnsBackup() {
        val pi = participants.single { it.npub == "npub1pi" }
        assertTrue(pi.servesNetworkDnsBackup)
        assertFalse(pi.servesNetworkDns)
    }

    @Test
    fun anOrdinaryDeviceHasNeitherBadge() {
        val phone = participants.single { it.npub == "npub1phone" }
        assertFalse(phone.servesNetworkDns)
        assertFalse(phone.servesNetworkDnsBackup)
    }
}
