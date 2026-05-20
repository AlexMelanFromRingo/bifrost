package org.norn.bifrost

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlin.concurrent.thread

/**
 * The VPN tunnel service. On start it builds a TUN via
 * [VpnService.Builder], hands the file descriptor to the native client
 * pump, and lets [NativeBridge.nativeRunClient] block on a worker
 * thread for the life of the session.
 *
 * Stopping closes the TUN: the system tears the VPN interface down,
 * which makes the native pump's TUN reads fail and unwinds
 * `nativeRunClient` cleanly.
 */
class BifrostVpnService : VpnService() {

    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            return START_NOT_STICKY
        }
        val config = intent?.getStringExtra(EXTRA_CONFIG)
        val exitKey = intent?.getStringExtra(EXTRA_EXIT_KEY)
        val tunAddr = intent?.getStringExtra(EXTRA_TUN_ADDR) ?: DEFAULT_TUN_ADDR
        if (config.isNullOrBlank() || exitKey.isNullOrBlank()) {
            Log.e(TAG, "missing config or exit key — not starting")
            stopSelf()
            return START_NOT_STICKY
        }
        startTunnel(config, exitKey, tunAddr)
        return START_STICKY
    }

    private fun startTunnel(config: String, exitKey: String, tunAddr: String) {
        if (worker != null) {
            Log.w(TAG, "tunnel already running")
            return
        }
        val pfd = try {
            Builder()
                .setSession("Bifrost")
                .addAddress(tunAddr, 32)        // the exit-leased IPv4
                .addRoute("0.0.0.0", 0)         // route everything through the mesh
                .addDnsServer("1.1.1.1")
                .setMtu(1280)
                .establish()
        } catch (t: Throwable) {
            Log.e(TAG, "VpnService.Builder failed", t)
            null
        }
        if (pfd == null) {
            Log.e(TAG, "establish() returned null — VPN not prepared?")
            stopSelf()
            return
        }
        tun = pfd

        // The native side dup(2)s this fd, so we keep the PFD and close
        // it (plus stopSelf) to tear the tunnel down later.
        val fd = pfd.fd
        worker = thread(name = "bifrost-pump", isDaemon = true) {
            Log.i(TAG, "native client pump starting (fd=$fd)")
            val status = try {
                NativeBridge.nativeRunClient(fd, config, exitKey)
            } catch (t: Throwable) {
                Log.e(TAG, "native pump threw", t)
                -1
            }
            Log.i(TAG, "native pump exited: status=$status err=${NativeBridge.nativeLastError()}")
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        worker = null
        try {
            tun?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "closing TUN fd", t)
        }
        tun = null
        stopSelf()
    }

    override fun onRevoke() {
        // The user revoked the VPN, or another VPN took over.
        Log.i(TAG, "VPN revoked")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "BifrostVpn"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_EXIT_KEY = "exitKey"
        const val EXTRA_TUN_ADDR = "tunAddr"
        const val ACTION_STOP = "org.norn.bifrost.STOP"
        const val DEFAULT_TUN_ADDR = "10.99.0.2"
    }
}
