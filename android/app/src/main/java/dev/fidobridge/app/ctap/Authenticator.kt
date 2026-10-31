package dev.fidobridge.app.ctap

import android.util.Log
import dev.fidobridge.app.crypto.CredentialStore
import dev.fidobridge.app.crypto.StoredCredential
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Signature

/**
 * CTAP2 authenticator logic. Signing must be performed with a Signature unlocked
 * via BiometricPrompt CryptoObject (passed in by the UI layer).
 */
class Authenticator(
    private val store: CredentialStore,
    private val aaguid: ByteArray = AAGUID,
) {
    data class ParsedRequest(
        val command: Int,
        val rpId: String?,
        val opName: String,
        val raw: ByteArray,
    )

    fun parseMeta(payload: ByteArray): ParsedRequest {
        if (payload.isEmpty()) {
            return ParsedRequest(0, null, "empty", payload)
        }
        val cmd = payload[0].toInt() and 0xff
        val rp = extractRpId(payload)
        val name = when (cmd) {
            CMD_MAKE_CREDENTIAL -> "makeCredential"
            CMD_GET_ASSERTION -> "getAssertion"
            CMD_GET_INFO -> "getInfo"
            else -> "cmd_$cmd"
        }
        return ParsedRequest(cmd, rp, name, payload)
    }

    fun getInfo(): ByteArray {
        val options = cborMap(
            CborValue.Text("rk") to CborValue.Bool(true),
            CborValue.Text("up") to CborValue.Bool(true),
            CborValue.Text("uv") to CborValue.Bool(true),
            CborValue.Text("plat") to CborValue.Bool(false),
        )
        val alg = cborMap(
            CborValue.Text("type") to CborValue.Text("public-key"),
            CborValue.Text("alg") to CborValue.Integer(-7),
        )
        val map = cborMap(
            CborValue.Integer(1) to CborValue.Array(
                listOf(CborValue.Text("FIDO_2_0"), CborValue.Text("FIDO_2_1_PRE")),
            ),
            CborValue.Integer(2) to CborValue.Array(emptyList()),
            CborValue.Integer(3) to CborValue.Bytes(aaguid),
            CborValue.Integer(4) to CborValue.Map(options),
            CborValue.Integer(5) to CborValue.Integer(1200),
            CborValue.Integer(9) to CborValue.Array(listOf(CborValue.Map(alg))),
        )
        return statusOk(Cbor.encode(CborValue.Map(map)))
    }

    /**
     * Prepare makeCredential: creates key material. Caller must obtain biometric
     * signature over (authData || clientDataHash) using [finishMakeCredential].
     */
    fun beginMakeCredential(payload: ByteArray): MakeCredPending {
        require(payload[0].toInt() and 0xff == CMD_MAKE_CREDENTIAL)
        val map = Cbor.decode(payload.copyOfRange(1, payload.size)).asMap()
            ?: error("bad cbor")
        val cborMap = CborValue.Map(map)
        val clientDataHash = cborMap.getBytes(1) ?: error("missing clientDataHash")
        val rp = cborMap.getMap(2) ?: error("missing rp")
        val rpId = (rp.getTextKey("id") as? CborValue.Text)?.value ?: error("missing rp.id")
        val user = cborMap.getMap(3) ?: error("missing user")
        val userId = (user.getTextKey("id") as? CborValue.Bytes)?.value ?: error("missing user.id")
        val userName = (user.getTextKey("name") as? CborValue.Text)?.value ?: ""

        val credId = CredentialStore.randomId(32)
        val alias = "fido-" + credId.joinToString("") { "%02x".format(it) }.take(32)
        store.createKey(alias)
        val pub = store.publicKeyUncompressed(alias)
        val coseKey = coseEcP256(pub)
        val credData = credentialData(aaguid, credId, coseKey)
        val rpHash = CredentialStore.sha256(rpId.toByteArray(Charsets.UTF_8))
        val flags = (FLAGS_UP or FLAGS_UV or FLAGS_AT).toByte()
        val authData = authenticatorData(rpHash, flags, 0, credData)
        val cred = StoredCredential(credId, rpId, userId, userName, alias, 0)
        return MakeCredPending(cred, authData, clientDataHash, alias)
    }

    fun finishMakeCredential(pending: MakeCredPending, signature: ByteArray): ByteArray {
        store.add(pending.cred)
        // Signature proves UV via Keystore; "none" attestation omits attStmt contents.
        Log.d(TAG, "makeCredential done rp=${pending.cred.rpId} sigLen=${signature.size}")
        val resp = cborMap(
            CborValue.Integer(1) to CborValue.Text("none"),
            CborValue.Integer(2) to CborValue.Bytes(pending.authData),
            CborValue.Integer(3) to CborValue.Map(cborMap()),
        )
        return statusOk(Cbor.encode(CborValue.Map(resp)))
    }

    fun beginGetAssertion(payload: ByteArray): AssertPending {
        require(payload[0].toInt() and 0xff == CMD_GET_ASSERTION)
        val map = Cbor.decode(payload.copyOfRange(1, payload.size)).asMap()
            ?: error("bad cbor")
        val cborMap = CborValue.Map(map)
        val rpId = cborMap.getText(1) ?: error("missing rpId")
        val clientDataHash = cborMap.getBytes(2) ?: error("missing clientDataHash")
        val allow = cborMap.getArray(3)?.mapNotNull { v ->
            val m = (v as? CborValue.Map)?.value ?: return@mapNotNull null
            (m[CborValue.Text("id")] as? CborValue.Bytes)?.value
        }
        val cred = store.findForRp(rpId, allow) ?: error("no credentials")
        val nextCount = cred.signCount + 1
        val rpHash = CredentialStore.sha256(rpId.toByteArray(Charsets.UTF_8))
        val flags = (FLAGS_UP or FLAGS_UV).toByte()
        val authData = authenticatorData(rpHash, flags, nextCount, null)
        return AssertPending(cred, authData, clientDataHash, nextCount)
    }

    fun finishGetAssertion(pending: AssertPending, signature: ByteArray): ByteArray {
        store.updateCounter(pending.cred.credentialId, pending.nextCount)
        val resp = cborMap(
            CborValue.Integer(1) to CborValue.Map(
                cborMap(
                    CborValue.Text("type") to CborValue.Text("public-key"),
                    CborValue.Text("id") to CborValue.Bytes(pending.cred.credentialId),
                ),
            ),
            CborValue.Integer(2) to CborValue.Bytes(pending.authData),
            CborValue.Integer(3) to CborValue.Bytes(signature),
            CborValue.Integer(4) to CborValue.Integer(pending.nextCount.toLong()),
            CborValue.Integer(5) to CborValue.Bytes(pending.cred.userId),
        )
        return statusOk(Cbor.encode(CborValue.Map(resp)))
    }

    fun processLocal(payload: ByteArray): ByteArray? {
        if (payload.isEmpty()) return byteArrayOf(CTAP2_ERR_INVALID_CMD)
        return when (payload[0].toInt() and 0xff) {
            CMD_GET_INFO -> getInfo()
            CMD_SELECTION -> byteArrayOf(CTAP2_OK)
            else -> null
        }
    }

    fun denied(code: Byte = CTAP2_ERR_OPERATION_DENIED): ByteArray = byteArrayOf(code)

    data class MakeCredPending(
        val cred: StoredCredential,
        val authData: ByteArray,
        val clientDataHash: ByteArray,
        val alias: String,
    ) {
        fun toBeSigned(): ByteArray = authData + clientDataHash
    }

    data class AssertPending(
        val cred: StoredCredential,
        val authData: ByteArray,
        val clientDataHash: ByteArray,
        val nextCount: Int,
    ) {
        fun toBeSigned(): ByteArray = authData + clientDataHash
        val alias: String get() = cred.keyAlias
    }

    companion object {
        private const val TAG = "Authenticator"
        val AAGUID = byteArrayOf(
            0xf1.toByte(), 0xd0.toByte(), 0xb7.toByte(), 0x1d,
            0x00, 0x00, 0x40, 0x00, 0x80.toByte(), 0x00, 0x00, 0x00,
            0xf1.toByte(), 0xd0.toByte(), 0xb7.toByte(), 0x1d,
        )
        const val CMD_MAKE_CREDENTIAL = 0x01
        const val CMD_GET_ASSERTION = 0x02
        const val CMD_GET_INFO = 0x04
        const val CMD_SELECTION = 0x0b
        const val CTAP2_OK: Byte = 0x00
        const val CTAP2_ERR_INVALID_CMD: Byte = 0x01
        const val CTAP2_ERR_OPERATION_DENIED: Byte = 0x27
        const val FLAGS_UP = 0x01
        const val FLAGS_UV = 0x04
        const val FLAGS_AT = 0x40

        fun extractRpId(payload: ByteArray): String? {
            if (payload.size < 2) return null
            return try {
                val map = Cbor.decode(payload.copyOfRange(1, payload.size)).asMap() ?: return null
                val m = CborValue.Map(map)
                when (payload[0].toInt() and 0xff) {
                    CMD_MAKE_CREDENTIAL -> {
                        val rp = m.getMap(2) ?: return null
                        (rp.getTextKey("id") as? CborValue.Text)?.value
                    }
                    CMD_GET_ASSERTION -> m.getText(1)
                    else -> null
                }
            } catch (_: Exception) {
                null
            }
        }

        private fun statusOk(body: ByteArray): ByteArray = byteArrayOf(CTAP2_OK) + body

        private fun authenticatorData(
            rpIdHash: ByteArray,
            flags: Byte,
            signCount: Int,
            attested: ByteArray?,
        ): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(rpIdHash)
            out.write(flags.toInt())
            val sc = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(signCount).array()
            out.write(sc)
            if (attested != null) out.write(attested)
            return out.toByteArray()
        }

        private fun credentialData(aaguid: ByteArray, credId: ByteArray, coseKey: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(aaguid)
            out.write(ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(credId.size.toShort()).array())
            out.write(credId)
            out.write(coseKey)
            return out.toByteArray()
        }

        private fun coseEcP256(uncompressed: ByteArray): ByteArray {
            // 0x04 || X(32) || Y(32)
            require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte())
            val x = uncompressed.copyOfRange(1, 33)
            val y = uncompressed.copyOfRange(33, 65)
            val map = cborMap(
                CborValue.Integer(1) to CborValue.Integer(2), // kty EC2
                CborValue.Integer(3) to CborValue.Integer(-7), // alg ES256
                CborValue.Integer(-1) to CborValue.Integer(1), // crv P-256
                CborValue.Integer(-2) to CborValue.Bytes(x),
                CborValue.Integer(-3) to CborValue.Bytes(y),
            )
            return Cbor.encode(CborValue.Map(map))
        }
    }
}

private fun cborMap(vararg pairs: Pair<CborValue, CborValue>): LinkedHashMap<CborValue, CborValue> =
    linkedMapOf(*pairs)

fun Signature.signBytes(data: ByteArray): ByteArray {
    update(data)
    return sign()
}
