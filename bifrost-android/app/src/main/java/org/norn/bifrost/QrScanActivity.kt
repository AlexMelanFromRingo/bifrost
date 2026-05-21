package org.norn.bifrost

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.hardware.Camera
import android.os.Bundle
import android.view.Gravity
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Full-screen QR scanner.
 *
 * Uses the deprecated-but-dependency-free Camera1 API (no camera2
 * boilerplate, no AndroidX CameraX) plus ZXing `core` for decoding.
 * Preview frames arrive as NV21; ZXing reads the Y (luminance) plane
 * directly. The QR detector locates finder patterns at any rotation,
 * so the frame is decoded as-is regardless of how the code is held.
 *
 * On a successful decode the raw text is returned to the caller via
 * [EXTRA_RESULT]; MainActivity parses it with [Qr.parse].
 */
@Suppress("DEPRECATION") // Camera1 — intentional, keeps the app AndroidX-free
class QrScanActivity : Activity(), SurfaceHolder.Callback, Camera.PreviewCallback {

    private lateinit var surface: SurfaceView
    private var camera: Camera? = null
    @Volatile private var previewW = 0
    @Volatile private var previewH = 0
    @Volatile private var done = false

    private val busy = AtomicBoolean(false)
    private val decodePool = Executors.newSingleThreadExecutor()
    private val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        surface = SurfaceView(this)
        root.addView(surface, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        root.addView(TextView(this).apply {
            text = "Point the camera at a Bifrost config QR"
            setTextColor(Color.WHITE)
            setBackgroundColor(0xCC000000.toInt())
            textSize = 14f
            setPadding(48, 32, 48, 32)
        }, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { gravity = Gravity.BOTTOM })
        setContentView(root)

        surface.holder.addCallback(this)
        if (!hasCameraPermission()) {
            requestPermissions(arrayOf(android.Manifest.permission.CAMERA), REQ_CAM)
        }
    }

    private fun hasCameraPermission() =
        checkSelfPermission(android.Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_CAM) return
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
            if (surface.holder.surface?.isValid == true) openCamera()
        } else {
            fail("Camera permission denied")
        }
    }

    // ── SurfaceHolder.Callback ───────────────────────────────────────

    override fun surfaceCreated(holder: SurfaceHolder) {
        if (hasCameraPermission()) openCamera()
    }

    override fun surfaceChanged(holder: SurfaceHolder, fmt: Int, w: Int, h: Int) {}

    override fun surfaceDestroyed(holder: SurfaceHolder) = releaseCamera()

    // ── camera lifecycle ─────────────────────────────────────────────

    private fun openCamera() {
        if (camera != null) return
        try {
            val cam = Camera.open() ?: return fail("No camera available")
            camera = cam
            cam.setDisplayOrientation(90)
            cam.setPreviewDisplay(surface.holder)
            cam.parameters.previewSize.let { previewW = it.width; previewH = it.height }
            cam.setPreviewCallback(this)
            cam.startPreview()
        } catch (t: Throwable) {
            fail("Camera open failed: ${t.message}")
        }
    }

    private fun releaseCamera() {
        camera?.let {
            try {
                it.setPreviewCallback(null)
                it.stopPreview()
                it.release()
            } catch (_: Throwable) {}
        }
        camera = null
    }

    override fun onPause() {
        super.onPause()
        releaseCamera()
    }

    override fun onDestroy() {
        super.onDestroy()
        releaseCamera()
        decodePool.shutdownNow()
    }

    // ── Camera.PreviewCallback ───────────────────────────────────────

    override fun onPreviewFrame(data: ByteArray?, cam: Camera?) {
        if (data == null || done || previewW == 0) return
        if (!busy.compareAndSet(false, true)) return
        val w = previewW
        val h = previewH
        try {
            decodePool.execute {
                val text = decode(data, w, h)
                busy.set(false)
                if (text != null && !done) {
                    done = true
                    runOnUiThread { succeed(text) }
                }
            }
        } catch (_: Throwable) {
            busy.set(false) // pool shutting down — ignore this frame
        }
    }

    /** ZXing decode of the NV21 Y-plane. Returns the QR text or null. */
    private fun decode(nv21: ByteArray, w: Int, h: Int): String? {
        return try {
            val src = PlanarYUVLuminanceSource(nv21, w, h, 0, 0, w, h, false)
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(src))).text
        } catch (_: Throwable) {
            reader.reset()
            null
        }
    }

    private fun succeed(text: String) {
        setResult(RESULT_OK, Intent().putExtra(EXTRA_RESULT, text))
        finish()
    }

    private fun fail(msg: String) {
        setResult(RESULT_CANCELED, Intent().putExtra(EXTRA_ERROR, msg))
        finish()
    }

    companion object {
        const val EXTRA_RESULT = "qr_result"
        const val EXTRA_ERROR = "qr_error"
        private const val REQ_CAM = 7001
    }
}
