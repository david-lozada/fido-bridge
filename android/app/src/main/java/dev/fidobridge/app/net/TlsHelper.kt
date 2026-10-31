package dev.fidobridge.app.net

import android.util.Base64
import dev.fidobridge.app.pair.PairingStore
import okhttp3.OkHttpClient
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object TlsHelper {
    fun clientPinnedTo(daemonFp: String, clientAlias: String): OkHttpClient {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                val cert = chain?.firstOrNull() ?: throw javax.net.ssl.SSLException("no server cert")
                val fp = PairingStore.sha256Hex(cert.encoded)
                if (!fp.equals(daemonFp, ignoreCase = true)) {
                    throw javax.net.ssl.SSLException("server fingerprint mismatch: $fp != $daemonFp")
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val aks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        // Export entry into a temporary KeyStore for KeyManager
        val tmp = KeyStore.getInstance("PKCS12")
        tmp.load(null, null)
        val entry = aks.getEntry(clientAlias, null) as KeyStore.PrivateKeyEntry
        tmp.setKeyEntry("client", entry.privateKey, null, arrayOf(entry.certificate))
        kmf.init(tmp, null)

        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, arrayOf<TrustManager>(trustAll), null)

        return OkHttpClient.Builder()
            .sslSocketFactory(ctx.socketFactory, trustAll)
            .hostnameVerifier(HostnameVerifier { _, _ -> true })
            .pingInterval(30, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()
    }

    fun pairingClient(daemonFp: String): OkHttpClient {
        val trust = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                val cert = chain?.firstOrNull() ?: throw javax.net.ssl.SSLException("no server cert")
                val fp = PairingStore.sha256Hex(cert.encoded)
                if (!fp.equals(daemonFp, ignoreCase = true)) {
                    throw javax.net.ssl.SSLException("server fingerprint mismatch")
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(trust), null)
        return OkHttpClient.Builder()
            .sslSocketFactory(ctx.socketFactory, trust)
            .hostnameVerifier { _, _ -> true }
            .build()
    }

    fun parsePemCert(pem: String): X509Certificate {
        val cleaned = pem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")
        val der = Base64.decode(cleaned, Base64.DEFAULT)
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }
}
