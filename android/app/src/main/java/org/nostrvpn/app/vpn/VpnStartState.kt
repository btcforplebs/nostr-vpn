package org.nostrvpn.app.vpn

import android.content.Context

internal object VpnStartState {
    private const val PREFS = "nostr_vpn_service"
    private const val USER_WANTS_VPN = "user_wants_vpn"
    private const val LOCKDOWN_ACTIVE = "lockdown_active"

    fun setUserWantsVpn(context: Context, enabled: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(USER_WANTS_VPN, enabled)
            .apply()
    }

    fun userWantsVpn(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(USER_WANTS_VPN, false)

    fun setLockdownActive(context: Context, enabled: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(LOCKDOWN_ACTIVE, enabled)
            .apply()
    }

    fun lockdownActive(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(LOCKDOWN_ACTIVE, false)
}
