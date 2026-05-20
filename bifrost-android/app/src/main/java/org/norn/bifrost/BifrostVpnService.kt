package org.norn.bifrost

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlin.concurrent.thread

/**
 * The VPN tunnel service. On start it builds a TUN via
 * [VpnService.Builder] and hands the file descriptor to the native
 * client.
 *
 * ## Lifecycle
 *
 * `NativeBridge.nativeClientStart` blocks only for the handshake, then
 * returns a handle to a tunnel that keeps running on the native tokio
 * runtime. The service holds that handle for the whole session and
 * passes it to `nativeClientStop` on teardown. (An earlier version
 * mistakenly stopped the tunnel right after start — the VPN came up
 * for ~100 ms and dropped.)
 *
 * ## Why the routes exclude the exit IP
 *
 * A VpnService routing `0.0.0.0/0` captures every socket the app
 * opens — including the mesh transport's TCP socket to the exit, which
 * would then loop into its own tunnel. So we route everything *except*
 * the exit's `/32`.
 */
class BifrostVpnService : VpnService() {

    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var nativeHandle: Long = 0L
    @Volatile private var stopRequested: Boolean = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.init(this)
        if (intent?.action == ACTION_STOP) {
            Logger.line("service: STOP requested")
            stopTunnel()
            return START_NOT_STICKY
        }
        val config = intent?.getStringExtra(EXTRA_CONFIG)
        val exitKey = intent?.getStringExtra(EXTRA_EXIT_KEY)
        val tunAddr = intent?.getStringExtra(EXTRA_TUN_ADDR) ?: DEFAULT_TUN_ADDR
        val exitAddr = intent?.getStringExtra(EXTRA_EXIT_ADDR) ?: ""
        if (config.isNullOrBlank() || exitKey.isNullOrBlank()) {
            Logger.line("service: missing config or exit key — not starting")
            stopSelf()
            return START_NOT_STICKY
        }
        startTunnel(config, exitKey, tunAddr, exitAddr)
        return START_STICKY
    }

    private fun startTunnel(config: String, exitKey: String, tunAddr: String, exitAddr: String) {
        if (tun != null) {
            Logger.line("service: tunnel already running — ignoring start")
            return
        }
        stopRequested = false
        Logger.startSession()
        Logger.line("service: starting tunnel — tunAddr=$tunAddr exitAddr=$exitAddr")
        Logger.line("service: exit key=${exitKey.take(16)}…")

        val pfd = try {
            val b = Builder()
                .setSession("Bifrost")
                .addAddress(tunAddr, 32)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setMtu(1280)
            val exitIp = ipv4Of(exitAddr)
            if (exitIp == null) {
                Logger.line("service: WARNING exit '$exitAddr' is not an IPv4 literal — " +
                    "using full 0.0.0.0/0 route (mesh transport may loop into the tunnel)")
                b.addRoute("0.0.0.0", 0)
            } else {
                val routes = routesExcluding(exitIp)
                Logger.line("service: routing 0.0.0.0/0 except exit $exitIp (${routes.size} routes)")
                for ((addr, prefix) in routes) b.addRoute(addr, prefix)
            }
            Logger.line("service: calling VpnService.Builder.establish()")
            b.establish()
        } catch (t: Throwable) {
            Logger.line("service: Builder/establish threw: ${t.javaClass.simpleName}: ${t.message}")
            null
        }
        if (pfd == null) {
            Logger.line("service: establish() returned null — VPN consent missing? aborting")
            stopSelf()
            return
        }
        tun = pfd
        val fd = pfd.fd
        Logger.line("service: TUN established, fd=$fd — connecting (handshake may take a few s)")

        thread(name = "bifrost-connect", isDaemon = true) {
            val handle = try {
                NativeBridge.nativeClientStart(fd, config, exitKey, Logger.nativeLogPath())
            } catch (t: Throwable) {
                Logger.line("service: nativeClientStart threw: ${t.javaClass.simpleName}: ${t.message}")
                0L
            }
            if (handle == 0L) {
                val err = try { NativeBridge.nativeLastError() } catch (_: Throwable) { "?" }
                Logger.line("service: connect FAILED — $err")
                exportLog()
                stopTunnel()
                return@thread
            }
            // Tunnel is up and stays up on the native runtime.
            if (stopRequested) {
                // Disconnected while we were still connecting — tear down now.
                Logger.line("service: stop requested during connect — stopping fresh tunnel")
                NativeBridge.nativeClientStop(handle)
            } else {
                nativeHandle = handle
                Logger.line("service: tunnel UP — traffic now routes through the exit")
            }
            exportLog()
        }
    }

    private fun stopTunnel() {
        stopRequested = true
        val h = nativeHandle
        nativeHandle = 0L
        if (h != 0L) {
            Logger.line("service: stopping native tunnel")
            try { NativeBridge.nativeClientStop(h) } catch (t: Throwable) {
                Logger.line("service: nativeClientStop threw: ${t.message}")
            }
        }
        try {
            tun?.close()
        } catch (t: Throwable) {
            Logger.line("service: error closing TUN fd: ${t.message}")
        }
        tun = null
        stopSelf()
    }

    /** Best-effort copy of the session log into Downloads. */
    private fun exportLog() {
        val saved = Logger.exportToDownloads(this)
        Logger.line(
            if (saved != null) "service: session log saved to Downloads/$saved"
            else "service: could not export log to Downloads"
        )
    }

    override fun onRevoke() {
        Logger.line("service: VPN revoked by system / another VPN")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_CONFIG = "config"
        const val EXTRA_EXIT_KEY = "exitKey"
        const val EXTRA_TUN_ADDR = "tunAddr"
        const val EXTRA_EXIT_ADDR = "exitAddr"
        const val ACTION_STOP = "org.norn.bifrost.STOP"
        const val DEFAULT_TUN_ADDR = "10.55.0.2"

        /**
         * Pull the IPv4 literal out of an exit address like
         * `tcp://***REMOVED***:9000`. Returns null for a hostname.
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
         * The 32 CIDR routes covering `0.0.0.0/0` minus the single host
         * [excludeIp].
         */
        fun routesExcluding(excludeIp: String): List<Pair<String, Int>> {
            val h = ipToInt(excludeIp)
            val out = ArrayList<Pair<String, Int>>(32)
            for (p in 1..32) {
                val flipped = h xor (1 shl (32 - p))
                val mask = -1 shl (32 - p)
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
