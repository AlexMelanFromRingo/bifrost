package org.norn.bifrost

import android.content.ContentValues
import android.content.Context
import android.provider.MediaStore
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * File-backed diagnostic logging.
 *
 * Both sides of the client log to one session file:
 *  - the Kotlin `VpnService` side via [line],
 *  - the native Rust side (norn-rs transport / handshake) via the
 *    file-backed `tracing` subscriber, given [nativeLogPath].
 *
 * The file lives in the app's external files dir — a plain path the
 * native code can also open. [exportToDownloads] copies it into the
 * public `Download/` folder via MediaStore so it is easy to retrieve
 * after a failed connection.
 */
object Logger {
    private const val TAG = "BifrostVpn"
    private const val SESSION_FILE = "bifrost-session.log"

    @Volatile private var file: File? = null
    private val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    /** Bind the session file. Idempotent — safe to call from anywhere. */
    fun init(ctx: Context) {
        if (file == null) {
            file = File(ctx.getExternalFilesDir(null), SESSION_FILE)
        }
    }

    /** Absolute path of the session log — passed to the native layer. */
    fun nativeLogPath(): String = file?.absolutePath ?: ""

    /** Truncate the log — call at the start of each connection attempt. */
    fun startSession() {
        try { file?.writeText("") } catch (_: Throwable) {}
        val now = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        line("===== session start $now =====")
    }

    /** Append one app-side line (also mirrored to logcat). */
    fun line(msg: String) {
        Log.i(TAG, msg)
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
            ctx.contentResolver.openOutputStream(uri)?.use {
                it.write(content.toByteArray())
            }
            name
        } catch (t: Throwable) {
            Log.e(TAG, "exportToDownloads failed", t)
            null
        }
    }
}
