package org.norn.bifrost

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
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
 * opens — including the native mesh transport's TCP socket to the
 * exit. That socket would then be routed into the very tunnel it is
 * building: a deadlock, no traffic at all. So instead of one
 * `0.0.0.0/0` route we install the 32 CIDR blocks covering everything
 * *except* the exit's `/32`.
 *
 * Every step is logged (see [Logger]); the session log is exported to
 * the Downloads folder when the pump exits.
 */
class BifrostVpnService : VpnService() {

    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var worker: Thread? = null

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
        if (worker != null) {
            Logger.line("service: tunnel already running — ignoring start")
            return
        }
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
        Logger.line("service: TUN established, fd=$fd — starting native pump")

        worker = thread(name = "bifrost-pump", isDaemon = true) {
            val status = try {
                NativeBridge.nativeRunClient(fd, config, exitKey, Logger.nativeLogPath())
            } catch (t: Throwable) {
                Logger.line("service: native pump threw: ${t.javaClass.simpleName}: ${t.message}")
                -1
            }
            val err = try { NativeBridge.nativeLastError() } catch (_: Throwable) { "?" }
            Logger.line("service: native pump exited — status=$status lastError=$err")
            Logger.line("service: status meaning — 0=clean 1=bad-arg 2=tun-fd 3=node-init " +
                "4=handshake 5=runtime")
            val saved = Logger.exportToDownloads(this)
            Logger.line(
                if (saved != null) "service: session log saved to Downloads/$saved"
                else "service: could not export log to Downloads"
            )
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        worker = null
        try {
            tun?.close()
        } catch (t: Throwable) {
            Logger.line("service: error closing TUN fd: ${t.message}")
        }
        tun = null
        stopSelf()
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
         * [excludeIp] — each the sibling subtree at one prefix length
         * that does not contain the excluded host.
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
