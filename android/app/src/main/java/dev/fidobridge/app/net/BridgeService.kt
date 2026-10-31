package dev.fidobridge.app.net

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.fidobridge.app.R
import dev.fidobridge.app.ctap.Authenticator
import dev.fidobridge.app.pair.PairedDaemon
import dev.fidobridge.app.pair.PairingStore
import dev.fidobridge.app.ui.MainActivity
import dev.fidobridge.app.ui.PromptActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class BridgeService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var ws: WebSocket? = null
    private var nsd: NsdManager? = null
    private val pending = ConcurrentHashMap<String, ByteArray>()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIF_ID, buildNotification(getString(R.string.status_disconnected)))
        PendingHolder.service = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> connectSaved()
            ACTION_DISCONNECT -> disconnect()
            ACTION_DISCOVER -> discover()
            ACTION_CTAP_RESULT -> {
                val id = intent.getStringExtra(EXTRA_ID) ?: return START_STICKY
                val data = intent.getByteArrayExtra(EXTRA_DATA)
                val error = intent.getStringExtra(EXTRA_ERROR)
                scope.launch { sendCtapResult(id, data, error) }
            }
        }
        return START_STICKY
    }

    private fun connectSaved() {
        val daemon = PairingStore(this).loadDaemon()
        if (daemon == null) {
            Log.w(TAG, "no paired daemon")
            return
        }
        connect(daemon)
    }

    fun connect(daemon: PairedDaemon) {
        disconnect()
        val store = PairingStore(this)
        store.ensureClientCert()
        val client = TlsHelper.clientPinnedTo(daemon.fingerprint, store.clientKeyAlias())
        val url = "wss://${daemon.host}:${daemon.port}/ws"
        val req = Request.Builder().url(url).build()
        ws = client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "ws open")
                val hello = BridgeMessage.Hello(
                    id = UUID.randomUUID().toString(),
                    name = Build.MODEL,
                    aaguid = Authenticator.AAGUID.joinToString("") { "%02x".format(it) },
                    versions = listOf("FIDO_2_0"),
                )
                webSocket.send(bridgeJson.encodeToString(BridgeMessage.serializer(), hello))
                updateNotification(getString(R.string.status_connected, daemon.name))
                broadcastStatus("connected:${daemon.name}")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                updateNotification(getString(R.string.status_disconnected))
                broadcastStatus("disconnected")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "ws failure", t)
                updateNotification(getString(R.string.status_disconnected))
                broadcastStatus("error:${t.message}")
            }
        })
    }

    private fun handleMessage(text: String) {
        val msg = try {
            bridgeJson.decodeFromString(BridgeMessage.serializer(), text)
        } catch (e: Exception) {
            Log.w(TAG, "bad msg $text", e)
            return
        }
        when (msg) {
            is BridgeMessage.Ping -> {
                ws?.send(
                    bridgeJson.encodeToString(
                        BridgeMessage.serializer(),
                        BridgeMessage.Pong(msg.id, msg.ts),
                    ),
                )
            }
            is BridgeMessage.CtapCancel -> {
                pending.remove(msg.id)
                broadcastStatus("cancel:${msg.id}")
            }
            is BridgeMessage.CtapRequest -> {
                val cmd = Base64.decode(msg.cmd, Base64.DEFAULT)
                val auth = Authenticator(dev.fidobridge.app.crypto.CredentialStore(this))
                val local = auth.processLocal(cmd)
                if (local != null) {
                    scope.launch { sendCtapResult(msg.id, local, null) }
                    return
                }
                pending[msg.id] = cmd
                val i = Intent(this, PromptActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    .putExtra(EXTRA_ID, msg.id)
                    .putExtra(EXTRA_RP, msg.rpId ?: Authenticator.extractRpId(cmd) ?: "unknown")
                    .putExtra(EXTRA_CMD, cmd)
                startActivity(i)
            }
            else -> Log.d(TAG, "ignore $msg")
        }
    }

    private fun sendCtapResult(id: String, data: ByteArray?, error: String?) {
        val resp = if (data != null) {
            BridgeMessage.CtapResponse(
                id = id,
                status = "ok",
                data = Base64.encodeToString(data, Base64.NO_WRAP),
            )
        } else {
            BridgeMessage.CtapResponse(
                id = id,
                status = "error",
                error = error ?: "user_cancelled",
                ctapStatus = 0x27,
            )
        }
        ws?.send(bridgeJson.encodeToString(BridgeMessage.serializer(), resp))
        pending.remove(id)
    }

    private fun disconnect() {
        ws?.close(1000, "bye")
        ws = null
        updateNotification(getString(R.string.status_disconnected))
    }

    private fun discover() {
        nsd = getSystemService(NSD_SERVICE) as NsdManager
        nsd?.discoverServices("_fidobridge._tcp.", NsdManager.PROTOCOL_DNS_SD, object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                broadcastStatus("discover_fail:$errorCode")
            }
            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {}
            override fun onDiscoveryStarted(serviceType: String?) {
                broadcastStatus("discovering")
            }
            override fun onDiscoveryStopped(serviceType: String?) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsd?.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {}
                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        val host = serviceInfo.host?.hostAddress ?: return
                        val port = serviceInfo.port
                        broadcastStatus("found:${serviceInfo.serviceName}@$host:$port")
                        val daemon = PairingStore(this@BridgeService).loadDaemon()
                        if (daemon != null) {
                            connect(daemon.copy(host = host, port = port))
                        }
                    }
                })
            }
            override fun onServiceLost(serviceInfo: NsdServiceInfo?) {}
        })
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(
                CHANNEL,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(text))
    }

    private fun broadcastStatus(msg: String) {
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, msg))
    }

    override fun onDestroy() {
        disconnect()
        scope.cancel()
        PendingHolder.service = null
        super.onDestroy()
    }

    object PendingHolder {
        @Volatile
        var service: BridgeService? = null
    }

    companion object {
        private const val TAG = "BridgeService"
        const val CHANNEL = "fidobridge"
        const val NOTIF_ID = 42
        const val ACTION_CONNECT = "dev.fidobridge.CONNECT"
        const val ACTION_DISCONNECT = "dev.fidobridge.DISCONNECT"
        const val ACTION_DISCOVER = "dev.fidobridge.DISCOVER"
        const val ACTION_CTAP_RESULT = "dev.fidobridge.CTAP_RESULT"
        const val ACTION_STATUS = "dev.fidobridge.STATUS"
        const val EXTRA_ID = "id"
        const val EXTRA_DATA = "data"
        const val EXTRA_ERROR = "error"
        const val EXTRA_RP = "rp"
        const val EXTRA_CMD = "cmd"
        const val EXTRA_STATUS = "status"
    }
}
