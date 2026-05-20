package org.norn.bifrost

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.security.SecureRandom

/**
 * Configuration + control screen for the Bifrost mesh VPN client.
 *
 * Everything is set here — no JSON editing, no config files. Each
 * field is persisted to [SharedPreferences], so the app reopens with
 * the last setup ready to go. On first launch a fresh node identity
 * (private key) is generated locally.
 *
 * Built in code with no AndroidX / layout XML on purpose — the app
 * stays a small, dependency-light reference client.
 */
class MainActivity : Activity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var exitKey: EditText
    private lateinit var exitAddr: EditText
    private lateinit var tunAddr: EditText
    private lateinit var privKey: EditText
    private lateinit var status: TextView

    private val reqConnect = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        Logger.init(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(28), dp(20), dp(20))
        }

        root.addView(TextView(this).apply {
            text = "Bifrost VPN"
            textSize = 22f
            setPadding(0, 0, 0, dp(2))
        })
        root.addView(TextView(this).apply {
            text = "mesh VPN client"
            textSize = 13f
            setTextColor(Color.GRAY)
            setPadding(0, 0, 0, dp(8))
        })

        exitKey = field(root, "Exit public key", "64 hex characters",
            prefs.getString(K_EXIT_KEY, DEFAULT_EXIT_KEY)!!)
        exitAddr = field(root, "Exit address", "tcp://host:port",
            prefs.getString(K_EXIT_ADDR, DEFAULT_EXIT_ADDR)!!)
        tunAddr = field(root, "TUN address", "IPv4 the exit leases you",
            prefs.getString(K_TUN_ADDR, DEFAULT_TUN_ADDR)!!)

        // Node identity — generated once on first launch, then reused so
        // the exit hands this device the same sticky lease every time.
        var pk = prefs.getString(K_PRIV_KEY, "") ?: ""
        if (pk.length != 64) {
            pk = randomPrivateKey()
            prefs.edit().putString(K_PRIV_KEY, pk).apply()
        }
        privKey = field(root, "Your private key", "node identity — keep secret", pk)

        root.addView(Button(this).apply {
            text = "Connect"
            setOnClickListener { onConnect() }
        })
        root.addView(Button(this).apply {
            text = "Disconnect"
            setOnClickListener { onDisconnect() }
        })
        root.addView(Button(this).apply {
            text = "Regenerate identity"
            setOnClickListener {
                privKey.setText(randomPrivateKey())
                save()
                status.text = "new identity generated — the exit will lease a fresh IP"
            }
        })
        root.addView(Button(this).apply {
            text = "Save log to Downloads"
            setOnClickListener {
                val name = Logger.exportToDownloads(this@MainActivity)
                status.text = if (name != null) "log saved: Downloads/$name"
                    else "no log to save yet — connect first"
            }
        })

        status = TextView(this).apply {
            setPadding(0, dp(18), 0, 0)
            textSize = 13f
        }
        root.addView(status)

        setContentView(ScrollView(this).apply { addView(root) })

        val abi = NativeBridge.nativeAbiVersion()
        status.text = if (abi == NativeBridge.EXPECTED_ABI_VERSION) {
            "native library OK (ABI $abi) — ready"
        } else {
            "WARNING: native ABI $abi, app expects ${NativeBridge.EXPECTED_ABI_VERSION}"
        }
    }

    /** Persist every field so the next launch comes up pre-filled. */
    override fun onPause() {
        super.onPause()
        save()
    }

    private fun save() {
        prefs.edit()
            .putString(K_EXIT_KEY, exitKey.text.toString().trim())
            .putString(K_EXIT_ADDR, exitAddr.text.toString().trim())
            .putString(K_TUN_ADDR, tunAddr.text.toString().trim())
            .putString(K_PRIV_KEY, privKey.text.toString().trim())
            .apply()
    }

    private fun onConnect() {
        save()
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
        if (requestCode != reqConnect) return
        if (resultCode != RESULT_OK) {
            status.text = "VPN consent denied"
            return
        }
        val svc = Intent(this, BifrostVpnService::class.java).apply {
            putExtra(BifrostVpnService.EXTRA_CONFIG, buildNodeConfig())
            putExtra(BifrostVpnService.EXTRA_EXIT_KEY, exitKey.text.toString().trim())
            putExtra(BifrostVpnService.EXTRA_TUN_ADDR, tunAddr.text.toString().trim())
            putExtra(BifrostVpnService.EXTRA_EXIT_ADDR, exitAddr.text.toString().trim())
        }
        startService(svc)
        status.text = "VPN starting — traffic now routes through the exit\n" +
            "(native logs: logcat tag BifrostVpn)"
    }

    private fun onDisconnect() {
        startService(Intent(this, BifrostVpnService::class.java).apply {
            action = BifrostVpnService.ACTION_STOP
        })
        status.text = "VPN stopping"
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

    // ── tiny code-built form helpers ─────────────────────────────────────

    /** A labelled, single-line text field appended to [parent]. */
    private fun field(parent: LinearLayout, label: String, hint: String, value: String): EditText {
        parent.addView(TextView(this).apply {
            text = label
            textSize = 13f
            setPadding(0, dp(14), 0, dp(2))
        })
        val e = EditText(this).apply {
            setText(value)
            this.hint = hint
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
            textSize = 14f
        }
        parent.addView(e)
        parent.addView(TextView(this).apply {
            text = hint
            textSize = 11f
            setTextColor(Color.GRAY)
        })
        return e
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private companion object {
        const val PREFS = "bifrost"
        const val K_EXIT_KEY = "exit_key"
        const val K_EXIT_ADDR = "exit_addr"
        const val K_TUN_ADDR = "tun_addr"
        const val K_PRIV_KEY = "priv_key"

        // Defaults point at the standing Oracle exit.
        const val DEFAULT_EXIT_KEY =
            "***REMOVED***"
        const val DEFAULT_EXIT_ADDR = "tcp://***REMOVED***:9000"
        const val DEFAULT_TUN_ADDR = "10.55.0.2"
    }
}
