package org.norn.bifrost

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

/**
 * QR payload format + bitmap generation for sharing exit-connection
 * details between devices.
 *
 * The payload is a single line:
 *
 *     bifrost1:<64-hex exit key>:<exit address>
 *
 * The address itself contains ':' (e.g. `quic://host:9000`), so parsing
 * splits on the first two ':' only and keeps the rest as the address.
 */
object Qr {
    private const val PREFIX = "bifrost1"

    /** Pack an exit key + address into the scannable payload string. */
    fun pack(exitKey: String, exitAddr: String): String =
        "$PREFIX:${exitKey.trim()}:${exitAddr.trim()}"

    /** Parse a scanned payload back to (key, addr); null if not ours. */
    fun parse(text: String): Pair<String, String>? {
        val parts = text.trim().split(":", limit = 3)
        if (parts.size != 3 || parts[0] != PREFIX) return null
        val key = parts[1].trim()
        val addr = parts[2].trim()
        if (key.length != 64 || addr.isEmpty()) return null
        return key to addr
    }

    /** Render [text] as a square black-on-white QR bitmap, [size] px. */
    fun encode(text: String, size: Int): Bitmap {
        val matrix = QRCodeWriter().encode(
            text, BarcodeFormat.QR_CODE, size, size,
            mapOf(EncodeHintType.MARGIN to 1),
        )
        val px = IntArray(size * size)
        for (y in 0 until size) {
            val row = y * size
            for (x in 0 until size) {
                px[row + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
            }
        }
        return Bitmap.createBitmap(px, size, size, Bitmap.Config.RGB_565)
    }
}
