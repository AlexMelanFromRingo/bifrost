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
 * ## Why the routes exclude the exit IP
 *
 * A VpnService that routes `0.0.0.0/0` captures *every* socket the app
 * opens — including the mesh TCP socket the native client uses to
 * reach the exit. That socket would then be routed into the very
 * tunnel it is trying to build: a deadlock, and the phone gets no
 * traffic at all. So instead of one `0.0.0.0/0` route we install the
 * 32 CIDR blocks that cover everything *except* the exit's `/32` —
 * the mesh socket reaches the exit over the real network, everything
 * else goes through the tunnel.
 *
 * Stopping closes the TUN: the system tears the VPN interface down,
 * which makes the native pump's reads fail and unwinds the call.
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
        val exitAddr = intent?.getStringExtra(EXTRA_EXIT_ADDR) ?: ""
        if (config.isNullOrBlank() || exitKey.isNullOrBlank()) {
            Log.e(TAG, "missing config or exit key — not starting")
            stopSelf()
            return START_NOT_STICKY
        }
        startTunnel(config, exitKey, tunAddr, exitAddr)
        return START_STICKY
    }

    private fun startTunnel(config: String, exitKey: String, tunAddr: String, exitAddr: String) {
        if (worker != null) {
            Log.w(TAG, "tunnel already running")
            return
        }
        val pfd = try {
            val b = Builder()
                .setSession("Bifrost")
                .addAddress(tunAddr, 32)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setMtu(1280)
            // The exit's own IP must NOT go through the tunnel, or the
            // mesh transport loops into itself. Route everything else.
            val exitIp = ipv4Of(exitAddr)
            if (exitIp == null) {
                Log.w(TAG, "exit address '$exitAddr' is not an IPv4 literal — " +
                    "falling back to a full 0.0.0.0/0 route (mesh may loop)")
                b.addRoute("0.0.0.0", 0)
            } else {
                Log.i(TAG, "routing 0.0.0.0/0 except exit $exitIp")
                for ((addr, prefix) in routesExcluding(exitIp)) {
                    b.addRoute(addr, prefix)
                }
            }
            b.establish()
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

        // The native side dup(2)s this fd; we keep the PFD and close it
        // (plus stopSelf) to tear the tunnel down later.
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
        const val EXTRA_EXIT_ADDR = "exitAddr"
        const val ACTION_STOP = "org.norn.bifrost.STOP"
        const val DEFAULT_TUN_ADDR = "10.55.0.2"

        /**
         * Pull the IPv4 literal out of an exit address like
         * `tcp://158.178.147.95:9000`. Returns null for a hostname
         * (resolving one would need a background thread).
         */
        fun ipv4Of(exitAddr: String): String? {
            val hostPort = exitAddr.substringAfter("://", exitAddr)
            val host = hostPort.substringBefore(":").substringBefore("/")
            val parts = host.split(".")
            if (parts.size != 4) return null
            if (parts.any { it.toIntOrNull()?.let { n -> n in 0..255 } != true }) return null
            return host
        }

        /**
         * The 32 CIDR routes that together cover `0.0.0.0/0` minus the
         * single host [excludeIp]. Each route is the sibling subtree at
         * one prefix length that does not contain the excluded host.
         */
        fun routesExcluding(excludeIp: String): List<Pair<String, Int>> {
            val h = ipToInt(excludeIp)
            val out = ArrayList<Pair<String, Int>>(32)
            for (p in 1..32) {
                val flipped = h xor (1 shl (32 - p))
                val mask = -1 shl (32 - p)          // top p bits
                out.add(intToIp(flipped and mask) to p)
            }
            return out
        }

        private fun ipToInt(ip: String): Int {
            val o = ip.split(".").map { it.toInt() }
            return (o[0] shl 24) or (o[1] shl 16) or (o[2] shl 8) or o[3]
        }

        private fun intToIp(v: Int): String =
            "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}." +
                "${(v ushr 8) and 0xFF}.${v and 0xFF}"
    }
}
