package org.nostrvpn.app.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class NostrVpnBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }
        if (!VpnStartState.userWantsVpn(context)) {
            return
        }
        runCatching {
            NostrVpnService.startRestore(context)
        }.onFailure { error ->
            Log.w("NostrVpnBootReceiver", "Failed to restore VPN service", error)
        }
    }
}
