package org.norn.bifrost

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlin.concurrent.thread

/**
 * The VPN tunnel service.
 *
 * ## Lifecycle — two-phase bring-up
 *
 * `VpnService.Builder` must commit the TUN's IP address *before* it
 * hands us the fd, yet that address is leased by the exit during the
 * handshake. So bring-up runs in two native phases on a background
 * thread:
 *
 *  1. `NativeBridge.nativeClientConnect` — start the mesh node and run
 *     the egress handshake; it returns the exit-assigned IPv4 lease.
 *  2. `Builder.addAddress(lease)…establish()` — build the TUN with
 *     *that* address.
 *  3. `NativeBridge.nativeClientRun` — attach the fd and start the
 *     data plane, which keeps running on the native tokio runtime.
 *
 * The service holds the native handle for the whole session and passes
 * it to `nativeClientStop` on teardown. (An earlier version hardcoded
 * the TUN address to a guess that didn't match the exit's lease, so
 * the exit dropped every packet as spoofed.)
 *
 * ## Surviving a network roam (Wi-Fi ↔ LTE)
 *
 * Two things keep the tunnel up when the phone changes networks:
 *
 *  * **Foreground service** — without it the OS may kill the service
 *    during the roam window. We `startForeground()` with an ongoing
 *    notification for the whole session.
 *  * **Default-network callback** — on every roam we re-pin the VPN's
 *    underlay with `setUnderlyingNetworks()`. The native data plane
 *    has its own reconnect supervisor (`run_client_pump`): once the
 *    transport re-dials the exit on the new network it rebuilds the
 *    egress session automatically, and the address lease is sticky so
 *    the TUN never has to be re-established.
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

    /** Default-network watcher — non-null only while a tunnel is up. */
    @Volatile private var netCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.init(this)
        if (intent?.action == ACTION_STOP) {
            Logger.line("service: STOP requested")
            stopTunnel()
            return START_NOT_STICKY
        }
        val config = intent?.getStringExtra(EXTRA_CONFIG)
        val exitKey = intent?.getStringExtra(EXTRA_EXIT_KEY)
        val exitAddr = intent?.getStringExtra(EXTRA_EXIT_ADDR) ?: ""
        if (config.isNullOrBlank() || exitKey.isNullOrBlank()) {
            Logger.line("service: missing config or exit key — not starting")
            stopSelf()
            return START_NOT_STICKY
        }
        // Become a foreground service before any slow work so the OS
        // can't reclaim us mid-handshake or mid-roam.
        goForeground("Connecting…")
        startTunnel(config, exitKey, exitAddr)
        return START_STICKY
    }

    private fun startTunnel(config: String, exitKey: String, exitAddr: String) {
        if (tun != null) {
            Logger.line("service: tunnel already running — ignoring start")
            return
        }
        stopRequested = false
        Logger.startSession()
        Logger.line("service: starting tunnel — exitAddr=$exitAddr")
        Logger.line("service: exit key=${exitKey.take(16)}…")

        thread(name = "bifrost-connect", isDaemon = true) {
            // ── Phase 1: mesh node + egress handshake ──────────────
            Logger.line("service: connecting to mesh + egress handshake (may take a few s)")
            val info = try {
                NativeBridge.nativeClientConnect(config, exitKey, Logger.nativeLogPath())
            } catch (t: Throwable) {
                Logger.line("service: nativeClientConnect threw: ${t.javaClass.simpleName}: ${t.message}")
                LongArray(1) // [0] == failure
            }
            if (info.size < 3 || info[0] == 0L) {
                val err = try { NativeBridge.nativeLastError() } catch (_: Throwable) { "?" }
                Logger.line("service: connect FAILED — $err")
                exportLog()
                stopSelf()
                return@thread
            }
            val handle = info[0]
            val leaseIp = ipv4FromHostOrder(info[1])
            val mtu = info[2].toInt().let { if (it in 576..4080) it else 1280 }
            Logger.line("service: exit leased $leaseIp, mtu=$mtu")

            if (stopRequested) {
                Logger.line("service: stop requested during handshake — tearing down")
                NativeBridge.nativeClientStop(handle)
                exportLog(); stopSelf(); return@thread
            }

            // ── Phase 2: build the TUN with the leased address ─────
            val pfd = try {
                val b = Builder()
                    .setSession("Bifrost")
                    .addAddress(leaseIp, 32)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    .setMtu(mtu)
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
                Logger.line("service: calling VpnService.Builder.establish() with addr=$leaseIp")
                b.establish()
            } catch (t: Throwable) {
                Logger.line("service: Builder/establish threw: ${t.javaClass.simpleName}: ${t.message}")
                null
            }
            if (pfd == null) {
                Logger.line("service: establish() returned null — VPN consent missing? aborting")
                NativeBridge.nativeClientStop(handle)
                exportLog(); stopSelf(); return@thread
            }
            tun = pfd
            val fd = pfd.fd
            Logger.line("service: TUN established, fd=$fd — starting data plane")

            if (stopRequested) {
                Logger.line("service: stop requested before data plane — tearing down")
                teardown(handle, pfd)
                exportLog(); stopSelf(); return@thread
            }

            // ── Phase 3: attach the fd + start the data plane ──────
            val status = try {
                NativeBridge.nativeClientRun(handle, fd)
            } catch (t: Throwable) {
                Logger.line("service: nativeClientRun threw: ${t.javaClass.simpleName}: ${t.message}")
                -1
            }
            if (status != 0) {
                val err = try { NativeBridge.nativeLastError() } catch (_: Throwable) { "?" }
                Logger.line("service: data plane FAILED (status=$status) — $err")
                teardown(handle, pfd)
                exportLog(); stopSelf(); return@thread
            }

            // Tunnel is up and stays up on the native runtime.
            if (stopRequested) {
                Logger.line("service: stop requested right after start — stopping fresh tunnel")
                teardown(handle, pfd)
            } else {
                nativeHandle = handle
                // Start watching the default network so the tunnel rides
                // Wi-Fi↔LTE roams; the native supervisor rebuilds the
                // egress session once the transport re-dials.
                registerNetCallback()
                updateNotification("Connected — $leaseIp")
                Logger.line("service: tunnel UP ($leaseIp) — traffic now routes through the exit")
            }
            exportLog()
        }
    }

    /** Stop a native handle and close a TUN fd — used on the failure paths. */
    private fun teardown(handle: Long, pfd: ParcelFileDescriptor) {
        unregisterNetCallback()
        try { NativeBridge.nativeClientStop(handle) } catch (t: Throwable) {
            Logger.line("service: nativeClientStop threw: ${t.message}")
        }
        try { pfd.close() } catch (_: Throwable) {}
        tun = null
    }

    private fun stopTunnel() {
        stopRequested = true
        unregisterNetCallback()
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
        stopForeground(STOP_FOREGROUND_REMOVE)
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

    // ── Roaming: follow the default network ──────────────────────────
    //
    // `registerDefaultNetworkCallback` fires `onAvailable` with the
    // current default network right after registration, and again on
    // every roam. Each time we re-pin the VPN underlay so the system
    // keeps the tunnel "connected" and routes the (route-excluded)
    // mesh transport socket onto the live network. The native data
    // plane notices the old socket die and re-dials on its own.

    private fun registerNetCallback() {
        if (netCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: run {
            Logger.line("net: no ConnectivityManager — roaming support disabled")
            return
        }
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Logger.line("net: default network → $network — re-pinning VPN underlay")
                try {
                    setUnderlyingNetworks(arrayOf(network))
                } catch (t: Throwable) {
                    Logger.line("net: setUnderlyingNetworks failed: ${t.message}")
                }
            }

            override fun onLost(network: Network) {
                Logger.line("net: default network $network lost — awaiting roam")
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
            Logger.line("net: default-network callback registered (roaming support on)")
        } catch (t: Throwable) {
            Logger.line("net: could not register network callback: ${t.message}")
        }
    }

    private fun unregisterNetCallback() {
        val cb = netCallback ?: return
        netCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (t: Throwable) {
            Logger.line("net: unregister callback failed: ${t.message}")
        }
    }

    // ── Foreground-service notification ──────────────────────────────

    /** Create the notification channel (idempotent) and go foreground. */
    private fun goForeground(text: String) {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(
                NotificationChannel(
                    NOTIF_CHANNEL, "Bifrost VPN", NotificationManager.IMPORTANCE_LOW,
                ).apply { description = "Ongoing mesh VPN tunnel status" }
            )
            startForeground(NOTIF_ID, buildNotification(text))
        } catch (t: Throwable) {
            Logger.line("service: startForeground failed: ${t.message}")
        }
    }

    /** Update the ongoing-notification text without changing FGS state. */
    private fun updateNotification(text: String) {
        try {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIF_ID, buildNotification(text))
        } catch (_: Throwable) {}
    }

    private fun buildNotification(text: String): Notification {
        val tap = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle("Bifrost VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setContentIntent(tap)
            .build()
    }

    companion object {
        const val EXTRA_CONFIG = "config"
        const val EXTRA_EXIT_KEY = "exitKey"
        const val EXTRA_EXIT_ADDR = "exitAddr"
        const val ACTION_STOP = "org.norn.bifrost.STOP"

        private const val NOTIF_CHANNEL = "bifrost-vpn"
        private const val NOTIF_ID = 1

        /**
         * Render a host-byte-order IPv4 (as returned in
         * `nativeClientConnect`'s `[1]` slot) as dotted-quad.
         * `0x0A370003` → `"10.55.0.3"`.
         */
        fun ipv4FromHostOrder(v: Long): String =
            "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}." +
                "${(v ushr 8) and 0xFF}.${v and 0xFF}"

        /**
         * Pull the IPv4 literal out of an exit address like
         * `tcp://203.0.113.10:9000`. Returns null for a hostname.
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
