package dev.fidobridge.app.net

import dev.fidobridge.app.pair.PairedDaemon
import dev.fidobridge.app.pair.PairingQr
import dev.fidobridge.app.pair.PairingStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

object PairClient {
    suspend fun pair(qr: PairingQr, store: PairingStore): PairedDaemon = withContext(Dispatchers.IO) {
        val (certPem, _) = store.ensureClientCert()
        val client = TlsHelper.pairingClient(qr.fp)
        val bodyJson = JSONObject()
            .put("name", android.os.Build.MODEL)
            .put("cert_pem", certPem)
            .toString()
        val req = Request.Builder()
            .url("https://${qr.host}:${qr.port}/pair")
            .header("X-Pairing-Secret", qr.secret)
            .post(bodyJson.toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(req).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) error("pair failed ${resp.code}: $text")
            val start = text.indexOf('{')
            if (start < 0) error("no json in $text")
            val o = JSONObject(text.substring(start))
            if (!o.optBoolean("ok", false)) error("pair not ok: $text")
            val daemon = PairedDaemon(
                name = o.optString("daemon_name", qr.name),
                host = qr.host,
                port = qr.port,
                fingerprint = o.getString("daemon_fp"),
            )
            store.saveDaemon(daemon)
            daemon
        }
    }
}
