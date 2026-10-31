package dev.fidobridge.app.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import dev.fidobridge.app.crypto.CredentialStore
import dev.fidobridge.app.ctap.Authenticator
import dev.fidobridge.app.ctap.signBytes
import dev.fidobridge.app.databinding.ActivityPromptBinding
import dev.fidobridge.app.net.BridgeService
import java.util.concurrent.Executor

class PromptActivity : AppCompatActivity() {
    private lateinit var binding: ActivityPromptBinding
    private lateinit var requestId: String
    private lateinit var cmd: ByteArray
    private lateinit var rpId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPromptBinding.inflate(layoutInflater)
        setContentView(binding.root)

        requestId = intent.getStringExtra(BridgeService.EXTRA_ID) ?: run {
            finish(); return
        }
        cmd = intent.getByteArrayExtra(BridgeService.EXTRA_CMD) ?: run {
            finish(); return
        }
        rpId = intent.getStringExtra(BridgeService.EXTRA_RP) ?: "unknown"

        val auth = Authenticator(CredentialStore(this))
        val meta = auth.parseMeta(cmd)
        binding.rpText.text = getString(dev.fidobridge.app.R.string.prompt_message, rpId)
        binding.opText.text = meta.opName

        binding.denyButton.setOnClickListener {
            sendResult(null, "user_cancelled")
            finish()
        }
        binding.approveButton.setOnClickListener {
            runCatching { startBiometric(auth) }
                .onFailure {
                    Toast.makeText(this, it.message, Toast.LENGTH_LONG).show()
                    sendResult(null, it.message)
                    finish()
                }
        }
    }

    private fun startBiometric(auth: Authenticator) {
        val store = CredentialStore(this)
        val cmdType = cmd[0].toInt() and 0xff
        val executor: Executor = ContextCompat.getMainExecutor(this)

        when (cmdType) {
            Authenticator.CMD_MAKE_CREDENTIAL -> {
                val pending = auth.beginMakeCredential(cmd)
                val signature = store.signature(pending.alias)
                val crypto = BiometricPrompt.CryptoObject(signature)
                val prompt = BiometricPrompt(
                    this,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val sig = result.cryptoObject?.signature
                                ?: run {
                                    sendResult(null, "no_signature"); finish(); return
                                }
                            val der = sig.signBytes(pending.toBeSigned())
                            val resp = auth.finishMakeCredential(pending, der)
                            sendResult(resp, null)
                            finish()
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            sendResult(null, errString.toString())
                            finish()
                        }

                        override fun onAuthenticationFailed() {
                            Toast.makeText(this@PromptActivity, "Not recognized", Toast.LENGTH_SHORT).show()
                        }
                    },
                )
                prompt.authenticate(promptInfo(rpId), crypto)
            }
            Authenticator.CMD_GET_ASSERTION -> {
                val pending = auth.beginGetAssertion(cmd)
                val signature = store.signature(pending.alias)
                val crypto = BiometricPrompt.CryptoObject(signature)
                val prompt = BiometricPrompt(
                    this,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val sig = result.cryptoObject?.signature
                                ?: run {
                                    sendResult(null, "no_signature"); finish(); return
                                }
                            val der = sig.signBytes(pending.toBeSigned())
                            val resp = auth.finishGetAssertion(pending, der)
                            sendResult(resp, null)
                            finish()
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            sendResult(null, errString.toString())
                            finish()
                        }
                    },
                )
                prompt.authenticate(promptInfo(rpId), crypto)
            }
            else -> {
                sendResult(auth.denied(), null)
                finish()
            }
        }
    }

    private fun promptInfo(rp: String) = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm for $rp")
        .setSubtitle("FIDO Bridge WebAuthn")
        .setNegativeButtonText("Cancel")
        .build()

    private fun sendResult(data: ByteArray?, error: String?) {
        val i = Intent(this, BridgeService::class.java)
            .setAction(BridgeService.ACTION_CTAP_RESULT)
            .putExtra(BridgeService.EXTRA_ID, requestId)
            .putExtra(BridgeService.EXTRA_DATA, data)
            .putExtra(BridgeService.EXTRA_ERROR, error)
        ContextCompat.startForegroundService(this, i)
    }
}
