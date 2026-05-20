package org.norn.bifrost

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * One-screen test harness for the Bifrost mesh VPN client. The user
 * supplies the exit node's public key, the TUN address the exit leases
 * them, and a norn-rs node config (JSON); "Connect" requests the system
 * VPN consent and starts [BifrostVpnService].
 *
 * Built with no AndroidX / layout XML on purpose — the UI is assembled
 * in code so the project stays a minimal, dependency-light reference.
 */
class MainActivity : Activity() {

    private lateinit var exitKey: EditText
    private lateinit var tunAddr: EditText
    private lateinit var config: EditText
    private lateinit var status: TextView

    private val reqConnect = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 56, 40, 40)
        }

        fun label(text: String) = TextView(this).apply {
            this.text = text
            setPadding(0, 28, 0, 6)
        }

        root.addView(TextView(this).apply {
            text = "Bifrost VPN — test client"
            textSize = 20f
        })

        root.addView(label("Exit node public key (64 hex chars)"))
        exitKey = EditText(this).apply { hint = "deadbeef…" }
        root.addView(exitKey)

        root.addView(label("TUN address (the IPv4 the exit leases you)"))
        tunAddr = EditText(this).apply { setText(BifrostVpnService.DEFAULT_TUN_ADDR) }
        root.addView(tunAddr)

        root.addView(label("Node config (JSON)"))
        config = EditText(this).apply {
            setText(DEFAULT_CONFIG)
            minLines = 5
        }
        root.addView(config)

        root.addView(Button(this).apply {
            text = "Connect"
            setOnClickListener { onConnect() }
        })
        root.addView(Button(this).apply {
            text = "Disconnect"
            setOnClickListener { onDisconnect() }
        })

        status = TextView(this).apply { setPadding(0, 32, 0, 0) }
        root.addView(status)

        setContentView(ScrollView(this).apply { addView(root) })

        // Surface an ABI mismatch immediately rather than at tunnel time.
        val abi = NativeBridge.nativeAbiVersion()
        status.text = if (abi == NativeBridge.EXPECTED_ABI_VERSION) {
            "native library OK (ABI $abi)"
        } else {
            "WARNING: native ABI $abi, app expects ${NativeBridge.EXPECTED_ABI_VERSION}"
        }
    }

    private fun onConnect() {
        // VpnService.prepare returns an Intent the first time (consent
        // dialog); null once the user has already granted consent.
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, reqConnect)
        } else {
            onActivityResult(reqConnect, RESULT_OK, null)
        }
    }

    @Deprecated("startActivityForResult — fine for a single-screen test app")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != reqConnect) return
        if (resultCode != RESULT_OK) {
            status.text = "VPN consent denied"
            return
        }
        val svc = Intent(this, BifrostVpnService::class.java).apply {
            putExtra(BifrostVpnService.EXTRA_CONFIG, config.text.toString())
            putExtra(BifrostVpnService.EXTRA_EXIT_KEY, exitKey.text.toString().trim())
            putExtra(BifrostVpnService.EXTRA_TUN_ADDR, tunAddr.text.toString().trim())
        }
        startService(svc)
        status.text = "VPN service started — see logcat tag BifrostVpn"
    }

    private fun onDisconnect() {
        startService(Intent(this, BifrostVpnService::class.java).apply {
            action = BifrostVpnService.ACTION_STOP
        })
        status.text = "VPN service stopping"
    }

    private companion object {
        // The host owns the single TUN fd; norn-rs must not open its own.
        // Replace the placeholders before connecting — see README.
        val DEFAULT_CONFIG = """
            {
              "private_key": "<64-hex ed25519 private key>",
              "listen": [],
              "peers": ["tcp://EXIT_HOST:9000"],
              "tun_name": null
            }
        """.trimIndent()
    }
}
