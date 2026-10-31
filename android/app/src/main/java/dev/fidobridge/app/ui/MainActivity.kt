package dev.fidobridge.app.ui

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.zxing.integration.android.IntentIntegrator
import dev.fidobridge.app.databinding.ActivityMainBinding
import dev.fidobridge.app.net.BridgeService
import dev.fidobridge.app.net.PairClient
import dev.fidobridge.app.pair.PairingStore
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val store by lazy { PairingStore(this) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { /* no-op */ }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val status = intent?.getStringExtra(BridgeService.EXTRA_STATUS) ?: return
            appendLog(status)
            binding.statusText.text = status
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        requestPerms()

        val daemon = store.loadDaemon()
        binding.detailText.text = if (daemon != null) {
            "Paired with ${daemon.name}\n${daemon.host}:${daemon.port}\nfp=${daemon.fingerprint.take(16)}…"
        } else {
            "Not paired. Scan the QR from `fido-bridged pair`."
        }

        binding.pairButton.setOnClickListener {
            IntentIntegrator(this)
                .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                .setPrompt("Scan FIDO Bridge pairing QR")
                .setBeepEnabled(false)
                .initiateScan()
        }
        binding.discoverButton.setOnClickListener {
            startSvc(BridgeService.ACTION_DISCOVER)
        }
        binding.disconnectButton.setOnClickListener {
            startSvc(BridgeService.ACTION_DISCONNECT)
        }
        binding.revokeButton.setOnClickListener {
            store.clear()
            dev.fidobridge.app.crypto.CredentialStore(this).deleteAll()
            binding.detailText.text = "Pairing cleared."
            Toast.makeText(this, "Forgot pairing", Toast.LENGTH_SHORT).show()
        }

        if (daemon != null) {
            startSvc(BridgeService.ACTION_CONNECT)
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(BridgeService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(statusReceiver) }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            if (result.contents != null) {
                lifecycleScope.launch {
                    try {
                        val qr = PairingStore.parseQr(result.contents)
                        appendLog("Pairing with ${qr.name} @ ${qr.host}:${qr.port}")
                        val daemon = PairClient.pair(qr, store)
                        binding.detailText.text =
                            "Paired with ${daemon.name}\n${daemon.host}:${daemon.port}"
                        startSvc(BridgeService.ACTION_CONNECT)
                        Toast.makeText(this@MainActivity, "Paired", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        appendLog("pair error: ${e.message}")
                        Toast.makeText(this@MainActivity, e.message, Toast.LENGTH_LONG).show()
                    }
                }
            }
        } else {
            @Suppress("DEPRECATION")
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun startSvc(action: String) {
        val i = Intent(this, BridgeService::class.java).setAction(action)
        ContextCompat.startForegroundService(this, i)
    }

    private fun appendLog(line: String) {
        binding.logText.append(line + "\n")
    }

    private fun requestPerms() {
        val need = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            need += Manifest.permission.POST_NOTIFICATIONS
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            need += Manifest.permission.CAMERA
        }
        if (need.isNotEmpty()) permissionLauncher.launch(need.toTypedArray())
    }
}
