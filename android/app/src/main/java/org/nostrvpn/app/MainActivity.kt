package org.nostrvpn.app

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.net.VpnService
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.delay
import org.json.JSONObject
import org.nostrvpn.app.core.AppCoreClient
import org.nostrvpn.app.core.NativeActions
import org.nostrvpn.app.vpn.NostrVpnService

class MainActivity : ComponentActivity() {
    private var deepLink by mutableStateOf<String?>(null)
    private var debugAction by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        deepLink = intent?.dataString
        debugAction = intent?.getStringExtra(EXTRA_DEBUG_ACTION)
        val core = AppCoreClient(filesDir.resolve("app-core").absolutePath, BuildConfig.VERSION_NAME)

        setContent {
            var state by remember { mutableStateOf(core.state()) }
            var pendingVpnStart by remember { mutableStateOf(false) }
            fun startVpnTunnel() {
                startVpnService(
                    Intent(this, NostrVpnService::class.java)
                        .setAction(NostrVpnService.ACTION_CONNECT)
                        .putExtra(
                            NostrVpnService.EXTRA_CONFIG_JSON,
                            core.mobileTunnelConfigJson(),
                        ),
                )
            }
            val vpnPermissionLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.StartActivityForResult(),
            ) { result ->
                if (result.resultCode == RESULT_OK && state.vpnEnabled) {
                    startVpnTunnel()
                } else if (pendingVpnStart && state.vpnEnabled) {
                    state = try {
                        core.dispatch(NativeActions.disconnectVpn())
                    } catch (error: Exception) {
                        state.copy(error = error.message ?: "Android action failed")
                    }
                }
                pendingVpnStart = false
            }
            fun requestVpnTunnel() {
                val intent = VpnService.prepare(this)
                if (intent == null) {
                    startVpnTunnel()
                } else {
                    pendingVpnStart = true
                    vpnPermissionLauncher.launch(intent)
                }
            }
            val dispatch: (JSONObject) -> Unit = { action ->
                val wasEnabled = state.vpnEnabled
                state = try {
                    core.dispatch(action)
                } catch (error: Exception) {
                    state.copy(error = error.message ?: "Android action failed")
                }
                if (!wasEnabled && state.vpnEnabled) {
                    requestVpnTunnel()
                } else if (wasEnabled && !state.vpnEnabled) {
                    startVpnService(
                        Intent(this, NostrVpnService::class.java)
                            .setAction(NostrVpnService.ACTION_DISCONNECT),
                    )
                }
            }

            DisposableEffect(core) {
                onDispose { core.close() }
            }
            LaunchedEffect(core) {
                while (true) {
                    delay(2_000)
                    state = try {
                        core.refresh()
                    } catch (error: Exception) {
                        state.copy(error = error.message ?: "Android refresh failed")
                    }
                }
            }
            LaunchedEffect(deepLink, debugAction) {
                val invite = deepLink
                if (!invite.isNullOrBlank() && invite.startsWith("nvpn://", ignoreCase = true)) {
                    dispatch(NativeActions.importInvite(invite))
                    deepLink = null
                }
                when (val action = debugAction) {
                    DEBUG_ACTION_CONNECT -> {
                        if (BuildConfig.DEBUG) {
                            dispatch(NativeActions.connectVpn())
                        }
                        debugAction = null
                    }
                    DEBUG_ACTION_DISCONNECT -> {
                        if (BuildConfig.DEBUG) {
                            dispatch(NativeActions.disconnectVpn())
                        }
                        debugAction = null
                    }
                    null -> Unit
                    else -> {
                        debugAction = null
                    }
                }
            }

            NostrVpnTheme {
                NostrVpnApp(
                    state = state,
                    qrJson = { invite -> core.qrMatrix(invite) },
                    dispatch = dispatch,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        deepLink = intent.dataString
        debugAction = intent.getStringExtra(EXTRA_DEBUG_ACTION)
    }

    private fun startVpnService(intent: Intent) {
        if (intent.action == NostrVpnService.ACTION_CONNECT && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    companion object {
        const val EXTRA_DEBUG_ACTION = "org.nostrvpn.app.DEBUG_ACTION"
        const val DEBUG_ACTION_CONNECT = "connect"
        const val DEBUG_ACTION_DISCONNECT = "disconnect"
    }
}
