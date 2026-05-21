package org.norn.bifrost

import android.content.ContentValues
import android.content.Context
import android.provider.MediaStore
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * File-backed diagnostic logging.
 *
 * Both sides of the client log to one session file: the Kotlin
 * `VpnService` side via [line], and the native Rust side (norn-rs
 * transport / handshake / data-plane counters) via the file-backed
 * `tracing` subscriber, given [nativeLogPath].
 *
 *  - [exportToDownloads] copies the file to the public `Download/`
 *    folder via MediaStore.
 *  - A loopback TCP server (port [LOG_PORT]) tails the file live, so
 *    it can be watched over `adb forward tcp:5599 tcp:5599` + `nc`.
 */
object Logger {
    private const val TAG = "BifrostVpn"
    private const val SESSION_FILE = "bifrost-session.log"
    private const val LOG_PORT = 5599

    /** Build marker — bump every build so a log identifies its APK. */
    const val BUILD = "2026-05-21 roaming+privacy+optlogs"

    @Volatile private var file: File? = null
    @Volatile private var serverUp = false
    /** When false, [line] / [startSession] skip all file writes and the
     *  live-tail server is not started — diagnostics off. */
    @Volatile private var fileLogging = true
    private val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    /** Bind the session file + start the live-log TCP server. Idempotent.
     *  Reads the user's diagnostic-logging preference; when off, the
     *  file path is still bound (so a later toggle-on works) but nothing
     *  is written and the live-tail server stays down. */
    fun init(ctx: Context) {
        // "bifrost" mirrors MainActivity.PREFS — the diagnostic-logging
        // toggle is persisted there.
        fileLogging = ctx.getSharedPreferences("bifrost", Context.MODE_PRIVATE)
            .getBoolean("logging_enabled", true)
        if (file == null) {
            file = File(ctx.getExternalFilesDir(null), SESSION_FILE)
        }
        if (fileLogging) startServer()
    }

    /** Flip diagnostic file logging at runtime (the caller persists the
     *  preference). Turning it on lazily starts the live-tail server. */
    fun setFileLogging(enabled: Boolean) {
        fileLogging = enabled
        if (enabled) startServer()
    }

    /** Absolute path of the session log — passed to the native layer.
     *  Empty when diagnostic logging is off, which disables the native
     *  file log too. */
    fun nativeLogPath(): String =
        if (fileLogging) file?.absolutePath ?: "" else ""

    /** Truncate the log — call at the start of each connection attempt.
     *  A no-op when diagnostic logging is off. */
    fun startSession() {
        if (!fileLogging) return
        try { file?.writeText("") } catch (_: Throwable) {}
        val now = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        line("===== session start $now =====")
        line("build=$BUILD  native-abi=${runCatching { NativeBridge.nativeAbiVersion() }.getOrDefault(-1)}")
    }

    /** Append one app-side line (always mirrored to logcat; the on-disk
     *  session file is written only when diagnostic logging is on). */
    fun line(msg: String) {
        Log.i(TAG, msg)
        if (!fileLogging) return
        try {
            file?.appendText("${stamp.format(Date())} [app]  $msg\n")
        } catch (_: Throwable) {}
    }

    /**
     * Copy the session log into the public Downloads folder.
     * Returns the created file name, or null on failure.
     */
    fun exportToDownloads(ctx: Context): String? {
        val content = try { file?.readText() } catch (_: Throwable) { null } ?: return null
        val name = "bifrost-vpn-" +
            SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) + ".log"
        return try {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
            }
            val uri = ctx.contentResolver
                .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return null
            ctx.contentResolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
            name
        } catch (t: Throwable) {
            Log.e(TAG, "exportToDownloads failed", t)
            null
        }
    }

    // ── live-log TCP server ──────────────────────────────────────────────
    //
    // Watch from a dev machine:
    //   adb forward tcp:5599 tcp:5599
    //   nc 127.0.0.1 5599
    // Each connection gets the whole session log so far, then a live
    // tail. Bound to loopback only — reachable via adb forward, not the
    // network.

    private fun startServer() {
        if (serverUp) return
        serverUp = true
        thread(name = "bifrost-log-srv", isDaemon = true) {
            try {
                val srv = ServerSocket(LOG_PORT, 4, InetAddress.getByName("127.0.0.1"))
                Log.i(TAG, "live-log server on 127.0.0.1:$LOG_PORT")
                while (true) {
                    val sock = srv.accept()
                    thread(name = "bifrost-log-tail", isDaemon = true) { tail(sock) }
                }
            } catch (t: Throwable) {
                Log.e(TAG, "live-log server stopped", t)
                serverUp = false
            }
        }
    }

    /** Stream the session file to one connected socket, tail -f style. */
    private fun tail(sock: Socket) {
        try {
            sock.use { s ->
                val out = s.getOutputStream()
                out.write("--- bifrost live log (build $BUILD) ---\n".toByteArray())
                out.flush()
                var offset = 0L
                while (!s.isClosed) {
                    val f = file
                    val len = f?.length() ?: 0L
                    if (len < offset) offset = 0L          // file truncated (new session)
                    if (f != null && len > offset) {
                        RandomAccessFile(f, "r").use { raf ->
                            raf.seek(offset)
                            val chunk = ByteArray((len - offset).coerceAtMost(65536).toInt())
                            val n = raf.read(chunk)
                            if (n > 0) {
                                out.write(chunk, 0, n)
                                out.flush()
                                offset += n
                            }
                        }
                    } else {
                        Thread.sleep(250)
                    }
                }
            }
        } catch (_: Throwable) {
            // client disconnected — just end this tail thread
        }
    }
}
