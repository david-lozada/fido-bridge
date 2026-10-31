package dev.fidobridge.app.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

data class StoredCredential(
    val credentialId: ByteArray,
    val rpId: String,
    val userId: ByteArray,
    val userName: String,
    val keyAlias: String,
    var signCount: Int,
) {
    override fun equals(other: Any?) =
        other is StoredCredential && credentialId.contentEquals(other.credentialId)
    override fun hashCode() = credentialId.contentHashCode()
}

class CredentialStore(private val context: Context) {
    private val prefs = context.getSharedPreferences("credentials", Context.MODE_PRIVATE)
    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

    fun list(): List<StoredCredential> {
        val raw = prefs.getString("list", "[]") ?: "[]"
        val arr = JSONArray(raw)
        val out = mutableListOf<StoredCredential>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += StoredCredential(
                credentialId = Base64.decode(o.getString("id"), Base64.NO_WRAP),
                rpId = o.getString("rpId"),
                userId = Base64.decode(o.getString("userId"), Base64.NO_WRAP),
                userName = o.optString("userName", ""),
                keyAlias = o.getString("alias"),
                signCount = o.optInt("signCount", 0),
            )
        }
        return out
    }

    private fun save(list: List<StoredCredential>) {
        val arr = JSONArray()
        for (c in list) {
            arr.put(
                JSONObject()
                    .put("id", Base64.encodeToString(c.credentialId, Base64.NO_WRAP))
                    .put("rpId", c.rpId)
                    .put("userId", Base64.encodeToString(c.userId, Base64.NO_WRAP))
                    .put("userName", c.userName)
                    .put("alias", c.keyAlias)
                    .put("signCount", c.signCount),
            )
        }
        prefs.edit().putString("list", arr.toString()).apply()
    }

    fun createKey(alias: String) {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    fun add(cred: StoredCredential) {
        val list = list().toMutableList()
        list.removeAll { it.rpId == cred.rpId && it.userId.contentEquals(cred.userId) }
        list += cred
        save(list)
    }

    fun updateCounter(credentialId: ByteArray, signCount: Int) {
        val list = list().toMutableList()
        val idx = list.indexOfFirst { it.credentialId.contentEquals(credentialId) }
        if (idx >= 0) {
            list[idx] = list[idx].copy(signCount = signCount)
            save(list)
        }
    }

    fun findForRp(rpId: String, allowList: List<ByteArray>?): StoredCredential? {
        val candidates = list().filter { it.rpId == rpId }
        if (allowList.isNullOrEmpty()) return candidates.firstOrNull()
        return candidates.firstOrNull { c -> allowList.any { it.contentEquals(c.credentialId) } }
    }

    fun signature(alias: String): Signature {
        val sig = Signature.getInstance("SHA256withECDSA")
        val key = (ks.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey
        sig.initSign(key)
        return sig
    }

    fun publicKeyUncompressed(alias: String): ByteArray {
        val pub = (ks.getEntry(alias, null) as KeyStore.PrivateKeyEntry).certificate.publicKey as ECPublicKey
        val point = pub.w
        val x = point.affineX.toByteArray().toFixed(32)
        val y = point.affineY.toByteArray().toFixed(32)
        return byteArrayOf(0x04) + x + y
    }

    fun deleteAll() {
        for (c in list()) {
            runCatching { ks.deleteEntry(c.keyAlias) }
        }
        prefs.edit().clear().apply()
    }

    companion object {
        fun randomId(size: Int = 32): ByteArray {
            val b = ByteArray(size)
            java.security.SecureRandom().nextBytes(b)
            return b
        }

        fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)
    }
}

private fun ByteArray.toFixed(len: Int): ByteArray {
    return when {
        size == len -> this
        size > len -> copyOfRange(size - len, size)
        else -> ByteArray(len - size) + this
    }
}
