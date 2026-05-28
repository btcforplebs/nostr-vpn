package org.nostrvpn.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ModelsTest {
    @Test
    fun joinRequestNetworkPrefersPendingNetworkOverActiveNetwork() {
        val active = NetworkState(id = "home", enabled = true, name = "Home")
        val pending =
            NetworkState(
                id = "invite",
                enabled = false,
                name = "Invite",
                inviteInviterNpub = "npub1admin",
                outboundJoinRequest = true,
            )

        assertEquals(pending, AppState(networks = listOf(active, pending)).joinRequestNetwork)
    }

    @Test
    fun joinRequestNetworkKeepsImportedInviteAvailableBeforeRequestIsSent() {
        val invited =
            NetworkState(
                id = "invite",
                enabled = true,
                name = "Invite",
                inviteInviterNpub = "npub1admin",
            )

        assertEquals(invited, AppState(networks = listOf(invited)).joinRequestNetwork)
    }

    @Test
    fun joinRequestNetworkIgnoresRegularNetwork() {
        val active = NetworkState(id = "home", enabled = true, name = "Home")

        assertNull(AppState(networks = listOf(active)).joinRequestNetwork)
    }
}
