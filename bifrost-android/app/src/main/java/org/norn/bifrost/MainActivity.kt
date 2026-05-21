package org.norn.bifrost

import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.res.Configuration
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import java.security.SecureRandom

/**
 * Configuration + control screen for the Bifrost mesh VPN client.
 *
 * Everything is set here — no JSON editing, no config files. Each field
 * is persisted to [SharedPreferences], so the app reopens with the last
 * setup ready to go. On first launch a fresh node identity (private
 * key) is generated locally.
 *
 * The UI is built entirely in code — no AndroidX / Material / layout
 * XML — so the app stays a small, dependency-light reference client.
 * The styling (cards, palette, day/night) is hand-rolled below; a live
 * status banner is fed by [BifrostVpnService]'s state broadcasts.
 */
class MainActivity : Activity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var exitKey: EditText
    private lateinit var exitAddr: EditText
    private lateinit var privKey: EditText
    private lateinit var status: TextView

    // Connection-state banner, driven by BifrostVpnService broadcasts.
    private lateinit var dot: View
    private lateinit var stateLabel: TextView
    private lateinit var stateDetail: TextView

    private val reqConnect = 1001
    private val reqScan = 1002

    /** Colour palette, resolved per-onCreate against the day/night theme. */
    private var pal = Palette.light()

    /** Receives BifrostVpnService.ACTION_STATE while the screen is foreground. */
    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context?, i: Intent?) {
            if (i?.action != BifrostVpnService.ACTION_STATE) return
            applyState(
                i.getStringExtra(BifrostVpnService.EXTRA_STATE) ?: return,
                i.getStringExtra(BifrostVpnService.EXTRA_DETAIL) ?: "",
            )
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        Logger.init(this)
        pal = if (isNight()) Palette.dark() else Palette.light()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(pal.bg)
            setPadding(dp(18), dp(26), dp(18), dp(26))
        }

        root.addView(TextView(this).apply {
            text = "Bifrost VPN"
            textSize = 24f
            setTextColor(pal.text)
        })
        root.addView(TextView(this).apply {
            text = "mesh VPN client"
            textSize = 13f
            setTextColor(pal.sub)
            setPadding(0, dp(1), 0, 0)
        })

        buildBanner(root)

        // ── Exit server ──────────────────────────────────────────────
        card(root, "Exit server").let { c ->
            exitKey = field(c, "Public key", "64 hex characters",
                prefs.getString(K_EXIT_KEY, DEFAULT_EXIT_KEY)!!)
            exitAddr = field(c, "Address", "tcp:// or quic://host:port",
                prefs.getString(K_EXIT_ADDR, DEFAULT_EXIT_ADDR)!!)
            flatButton(c, "Scan QR", pal.accent) { startQrScan() }
            flatButton(c, "Show QR for sharing", pal.accent) { showQrDialog() }
        }

        // ── Identity ─────────────────────────────────────────────────
        // The node key is generated once on first launch and reused, so
        // the exit hands this device the same sticky lease every time.
        card(root, "Identity").let { c ->
            var pk = prefs.getString(K_PRIV_KEY, "") ?: ""
            if (pk.length != 64) {
                pk = randomPrivateKey()
                prefs.edit().putString(K_PRIV_KEY, pk).apply()
            }
            privKey = field(c, "Private key", "node identity — keep secret", pk)
            flatButton(c, "Regenerate identity", pal.accent) {
                privKey.setText(randomPrivateKey())
                save()
                note("New identity generated — the exit will lease a fresh IP")
            }
        }

        // ── Controls ─────────────────────────────────────────────────
        primaryButton(root, "Connect") { onConnect() }
        flatButton(root, "Disconnect", pal.danger, topMargin = 8) { onDisconnect() }

        // ── Diagnostics ──────────────────────────────────────────────
        card(root, "Diagnostics").let { c ->
            c.addView(Switch(this).apply {
                text = "Diagnostic logging"
                textSize = 14f
                setTextColor(pal.text)
                isChecked = prefs.getBoolean(K_LOGGING, true)
                setOnCheckedChangeListener { _, checked ->
                    prefs.edit().putBoolean(K_LOGGING, checked).apply()
                    Logger.setFileLogging(checked)
                    note(if (checked) "Diagnostic logging on"
                        else "Diagnostic logging off — no session file written")
                }
            }, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            flatButton(c, "Save log to Downloads", pal.accent) {
                val name = Logger.exportToDownloads(this@MainActivity)
                note(if (name != null) "Log saved: Downloads/$name"
                    else "No log to save yet — connect first")
            }
        }

        status = TextView(this).apply {
            setPadding(dp(2), dp(16), dp(2), 0)
            textSize = 12f
            setTextColor(pal.sub)
        }
        root.addView(status)

        setContentView(ScrollView(this).apply {
            setBackgroundColor(pal.bg)
            addView(root)
        })

        val abi = NativeBridge.nativeAbiVersion()
        status.text = if (abi == NativeBridge.EXPECTED_ABI_VERSION) {
            "Native library OK (ABI $abi)"
        } else {
            "WARNING: native ABI $abi, app expects ${NativeBridge.EXPECTED_ABI_VERSION}"
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(BifrostVpnService.ACTION_STATE)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(stateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(stateReceiver, filter)
        }
        // Seed the banner from the service's last known state.
        applyState(BifrostVpnService.currentState, BifrostVpnService.currentDetail)
    }

    /** Persist every field + drop the receiver when the screen leaves. */
    override fun onPause() {
        super.onPause()
        save()
        try { unregisterReceiver(stateReceiver) } catch (_: Throwable) {}
    }

    private fun save() {
        prefs.edit()
            .putString(K_EXIT_KEY, exitKey.text.toString().trim())
            .putString(K_EXIT_ADDR, exitAddr.text.toString().trim())
            .putString(K_PRIV_KEY, privKey.text.toString().trim())
            .apply()
    }

    private fun onConnect() {
        save()
        if (exitKey.text.toString().trim().length != 64) {
            note("Enter the exit's 64-hex public key first")
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, reqConnect)
        } else {
            @Suppress("DEPRECATION")
            onActivityResult(reqConnect, RESULT_OK, null)
        }
    }

    @Deprecated("startActivityForResult — fine for a single-screen app")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            reqConnect -> {
                if (resultCode != RESULT_OK) {
                    note("VPN consent denied")
                    return
                }
                startService(Intent(this, BifrostVpnService::class.java).apply {
                    putExtra(BifrostVpnService.EXTRA_CONFIG, buildNodeConfig())
                    putExtra(BifrostVpnService.EXTRA_EXIT_KEY, exitKey.text.toString().trim())
                    putExtra(BifrostVpnService.EXTRA_EXIT_ADDR, exitAddr.text.toString().trim())
                })
                // The banner updates itself from the service's state broadcasts.
            }
            reqScan -> {
                if (resultCode == RESULT_OK) {
                    val parsed = data?.getStringExtra(QrScanActivity.EXTRA_RESULT)
                        ?.let { Qr.parse(it) }
                    if (parsed != null) {
                        exitKey.setText(parsed.first)
                        exitAddr.setText(parsed.second)
                        save()
                        note("Exit config imported from QR")
                    } else {
                        note("That QR is not a Bifrost config code")
                    }
                } else {
                    note(data?.getStringExtra(QrScanActivity.EXTRA_ERROR) ?: "QR scan cancelled")
                }
            }
        }
    }

    private fun onDisconnect() {
        startService(Intent(this, BifrostVpnService::class.java).apply {
            action = BifrostVpnService.ACTION_STOP
        })
    }

    /** Launch the camera QR scanner; the result lands in onActivityResult. */
    private fun startQrScan() {
        startActivityForResult(Intent(this, QrScanActivity::class.java), reqScan)
    }

    /** Show the current exit key + address as a QR for another device. */
    private fun showQrDialog() {
        val key = exitKey.text.toString().trim()
        val addr = exitAddr.text.toString().trim()
        if (key.length != 64 || addr.isEmpty()) {
            note("Fill in the exit key and address first")
            return
        }
        val bmp = try {
            Qr.encode(Qr.pack(key, addr), dp(260))
        } catch (t: Throwable) {
            note("QR generation failed: ${t.message}")
            return
        }
        val img = ImageView(this).apply {
            setImageBitmap(bmp)
            val p = dp(18)
            setPadding(p, p, p, p)
        }
        AlertDialog.Builder(this)
            .setTitle("Exit config QR")
            .setMessage("Scan this from another device to import the exit key + address.")
            .setView(img)
            .setPositiveButton("Close", null)
            .show()
    }

    /** Render a connection state into the status banner. */
    private fun applyState(state: String, detail: String) {
        val (color, label) = when (state) {
            BifrostVpnService.STATE_CONNECTING -> pal.warn to "Connecting…"
            BifrostVpnService.STATE_CONNECTED -> pal.ok to "Connected"
            BifrostVpnService.STATE_FAILED -> pal.danger to "Connection failed"
            else -> pal.sub to "Not connected"
        }
        dot.background = circle(color)
        stateLabel.text = label
        stateDetail.text = when (state) {
            BifrostVpnService.STATE_CONNECTED ->
                if (detail.isNotEmpty()) "Tunnel address $detail" else "Tunnel active"
            BifrostVpnService.STATE_CONNECTING -> "Mesh handshake in progress…"
            BifrostVpnService.STATE_FAILED -> detail.take(140)
            else -> "Tap Connect to route traffic through the exit"
        }
    }

    /** Show a one-line transient note in the footer status line. */
    private fun note(msg: String) {
        if (::status.isInitialized) status.text = msg
    }

    /**
     * Assemble the norn-rs `NodeConfig` JSON the native layer expects.
     * `tun_name` is null — the host owns the single TUN fd; `listen`
     * is empty — a phone client doesn't accept inbound mesh links.
     */
    private fun buildNodeConfig(): String {
        val pk = privKey.text.toString().trim()
        val peer = exitAddr.text.toString().trim().jsonEscape()
        // A phone client only ever talks to its configured exit: no LAN
        // multicast / mDNS discovery, and no on-disk peer cache (the
        // default path is a server location the app can't write).
        return """{"private_key":"$pk","listen":[],"peers":["$peer"],""" +
            """"tun_name":null,"multicast_enabled":false,"mdns_enabled":false,""" +
            """"peer_cache_path":""}"""
    }

    private fun String.jsonEscape(): String =
        replace("\\", "\\\\").replace("\"", "\\\"")

    /** 32 cryptographically-random bytes, hex — a valid norn-rs private key. */
    private fun randomPrivateKey(): String {
        val b = ByteArray(32)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    // ── code-built UI helpers ────────────────────────────────────────

    private fun isNight(): Boolean =
        (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    /** A rounded-rectangle drawable for cards / fields / buttons. */
    private fun roundedBg(fill: Int, radiusDp: Int, strokeDp: Int = 0, strokeColor: Int = 0) =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(radiusDp).toFloat()
            if (strokeDp > 0) setStroke(dp(strokeDp), strokeColor)
        }

    private fun circle(color: Int) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color)
    }

    /** A titled section card appended to [parent]; returns its body. */
    private fun card(parent: LinearLayout, title: String): LinearLayout {
        val c = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBg(pal.card, 14)
            setPadding(dp(16), dp(13), dp(16), dp(16))
        }
        parent.addView(c, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(12) })
        c.addView(TextView(this).apply {
            text = title.uppercase()
            textSize = 11f
            setTextColor(pal.sub)
            letterSpacing = 0.09f
            setPadding(0, 0, 0, dp(6))
        })
        return c
    }

    /** The connection-state banner: coloured dot + label + detail. */
    private fun buildBanner(parent: LinearLayout) {
        val c = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = roundedBg(pal.card, 14)
            setPadding(dp(16), dp(15), dp(16), dp(15))
        }
        parent.addView(c, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(16) })

        dot = View(this).apply { background = circle(pal.sub) }
        c.addView(dot, LinearLayout.LayoutParams(dp(12), dp(12)).apply {
            rightMargin = dp(12)
        })

        val texts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        c.addView(texts)
        stateLabel = TextView(this).apply {
            text = "Not connected"
            textSize = 15f
            setTextColor(pal.text)
        }
        stateDetail = TextView(this).apply {
            text = "Tap Connect to route traffic through the exit"
            textSize = 12f
            setTextColor(pal.sub)
        }
        texts.addView(stateLabel)
        texts.addView(stateDetail)
    }

    /** A labelled, single-line text field appended to [parent]. */
    private fun field(parent: LinearLayout, label: String, hint: String, value: String): EditText {
        parent.addView(TextView(this).apply {
            text = label
            textSize = 12f
            setTextColor(pal.sub)
            setPadding(0, dp(8), 0, dp(4))
        })
        val e = EditText(this).apply {
            setText(value)
            this.hint = hint
            setHintTextColor(pal.sub)
            setTextColor(pal.text)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
            textSize = 14f
            background = roundedBg(pal.field, 9)
            setPadding(dp(12), dp(11), dp(12), dp(11))
        }
        parent.addView(e, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ))
        return e
    }

    /** The full-width accent action button. */
    private fun primaryButton(parent: LinearLayout, text: String, onClick: () -> Unit) {
        parent.addView(Button(this).apply {
            this.text = text
            isAllCaps = false
            textSize = 16f
            setTextColor(pal.onAccent)
            background = roundedBg(pal.accent, 12)
            stateListAnimator = null
            setOnClickListener { onClick() }
        }, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(52),
        ).apply { topMargin = dp(18) })
    }

    /** A flat, outlined button in [color]. */
    private fun flatButton(
        parent: LinearLayout, text: String, color: Int,
        topMargin: Int = 10, onClick: () -> Unit,
    ) {
        parent.addView(Button(this).apply {
            this.text = text
            isAllCaps = false
            textSize = 14f
            setTextColor(color)
            background = roundedBg(0, 10, 1, (color and 0xFFFFFF) or 0x55000000.toInt())
            stateListAnimator = null
            setOnClickListener { onClick() }
        }, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(46),
        ).apply { this.topMargin = dp(topMargin) })
    }

    /** Hand-rolled day/night colour palette — no resources, no AndroidX. */
    private class Palette(
        val bg: Int, val card: Int, val field: Int,
        val text: Int, val sub: Int,
        val accent: Int, val onAccent: Int,
        val ok: Int, val warn: Int, val danger: Int,
    ) {
        companion object {
            fun light() = Palette(
                bg = 0xFFF2F3F5.toInt(), card = 0xFFFFFFFF.toInt(), field = 0xFFECEDF0.toInt(),
                text = 0xFF1B1C1F.toInt(), sub = 0xFF6A6B70.toInt(),
                accent = 0xFF3B6FE0.toInt(), onAccent = 0xFFFFFFFF.toInt(),
                ok = 0xFF2E9E63.toInt(), warn = 0xFFC9871F.toInt(), danger = 0xFFD33A30.toInt(),
            )

            fun dark() = Palette(
                bg = 0xFF121316.toInt(), card = 0xFF1E2026.toInt(), field = 0xFF282A31.toInt(),
                text = 0xFFE5E5E8.toInt(), sub = 0xFF9B9CA3.toInt(),
                accent = 0xFF5B8DEF.toInt(), onAccent = 0xFFFFFFFF.toInt(),
                ok = 0xFF3FB97A.toInt(), warn = 0xFFE0A33B.toInt(), danger = 0xFFE5544B.toInt(),
            )
        }
    }

    private companion object {
        const val PREFS = "bifrost"
        const val K_EXIT_KEY = "exit_key"
        const val K_EXIT_ADDR = "exit_addr"
        const val K_PRIV_KEY = "priv_key"
        const val K_LOGGING = "logging_enabled"

        // Exit defaults are injected at build time from the gitignored
        // `exit.properties` via BuildConfig — the repo never carries a
        // real server address. Blank when the file is absent; the user
        // types the address once and it persists to SharedPreferences.
        val DEFAULT_EXIT_KEY: String = BuildConfig.DEFAULT_EXIT_KEY
        val DEFAULT_EXIT_ADDR: String = BuildConfig.DEFAULT_EXIT_ADDR
    }
}
