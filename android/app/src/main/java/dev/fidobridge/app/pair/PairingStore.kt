package dev.fidobridge.app.pair

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

data class PairingQr(
    val v: Int,
    val host: String,
    val port: Int,
    val fp: String,
    val secret: String,
    val name: String,
)

data class PairedDaemon(
    val name: String,
    val host: String,
    val port: Int,
    val fingerprint: String,
)

class PairingStore(context: Context) {
    private val prefs = context.getSharedPreferences("pairing", Context.MODE_PRIVATE)
    private val alias = "fidobridge-client"

    fun ensureClientCert(): Pair<String, String> {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        if (!ks.containsAlias(alias)) {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setCertificateSubject(X500Principal("CN=FIDO Bridge Phone"))
                .setCertificateSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                .setCertificateNotBefore(Date(System.currentTimeMillis() - 86_400_000))
                .setCertificateNotAfter(Date(System.currentTimeMillis() + 10L * 365 * 86_400_000))
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
        val cert = ks.getCertificate(alias) as X509Certificate
        val pem = toPem("CERTIFICATE", cert.encoded)
        val fp = sha256Hex(cert.encoded)
        return pem to fp
    }

    fun clientKeyAlias(): String = alias

    fun saveDaemon(d: PairedDaemon) {
        prefs.edit()
            .putString(
                "daemon",
                JSONObject()
                    .put("name", d.name)
                    .put("host", d.host)
                    .put("port", d.port)
                    .put("fp", d.fingerprint)
                    .toString(),
            )
            .apply()
    }

    fun loadDaemon(): PairedDaemon? {
        val raw = prefs.getString("daemon", null) ?: return null
        val o = JSONObject(raw)
        return PairedDaemon(
            name = o.getString("name"),
            host = o.getString("host"),
            port = o.getInt("port"),
            fingerprint = o.getString("fp"),
        )
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        fun parseQr(json: String): PairingQr {
            val o = JSONObject(json)
            return PairingQr(
                v = o.optInt("v", 1),
                host = o.getString("host"),
                port = o.getInt("port"),
                fp = o.getString("fp"),
                secret = o.getString("secret"),
                name = o.optString("name", "pc"),
            )
        }

        fun sha256Hex(data: ByteArray): String {
            val d = MessageDigest.getInstance("SHA-256").digest(data)
            return d.joinToString("") { "%02x".format(it) }
        }

        fun toPem(type: String, der: ByteArray): String {
            val b64 = Base64.encodeToString(der, Base64.DEFAULT).trim()
            return "-----BEGIN $type-----\n$b64\n-----END $type-----\n"
        }
    }
}
