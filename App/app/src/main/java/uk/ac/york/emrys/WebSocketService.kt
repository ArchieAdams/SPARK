package uk.ac.york.emrys

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okio.ByteString.Companion.toByteString
import java.lang.Thread.sleep
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

class WebSocketService(
    private val connectionListener: ConnectionListener? = null,
    private val setupConfig: SetupService.SetupConfig? = null
) : ConnectionService() {
    companion object {
        private const val TAG = "WebSocketService"
        private const val WEBSOCKET_PORT = 8080
        private const val WS_PROTOCOL = "authapp"
    }

    @Volatile
    private var webSocket: okhttp3.WebSocket? = null

    @Volatile
    private var isConnecting = false
    private val webSocketLock = Any()

    @Volatile
    private var httpClient: OkHttpClient? = null
    private var connectionThread: Thread? = null

    private var udpListener: UDPBroadcastListener? = null

    fun connectToIPAddress(serverIpAddress: String) {
        if (connectionThread != null && connectionThread?.isAlive == true) {
            Log.d(TAG, "Connection attempt already in progress, ignoring new request")
            return
        }
        connectionThread = thread {
            val ipAddress = serverIpAddress.trim().removePrefix("/")
            Log.d(TAG, "Starting connection to wss://$ipAddress:$WEBSOCKET_PORT")

            // Ensure only one connection attempt at a time
            if (!startConnect()) return@thread

            try {
                connectToWebSocket(ipAddress)
            } catch (e: Exception) {
                e.printStackTrace()
                clearConnectionState()
            } finally {
                finishConnect()
            }
        }
    }

    private fun connectToWebSocket(ipAddress: String) {
        // Create SSL context that trusts all certificates
        val (trustAllCerts, sslContext) = createSslContext()

        // Build OkHttpClient if not already created
        val client = synchronized(webSocketLock) {
            if (httpClient == null && sslContext != null) {
                httpClient = buildHttpClient(sslContext, trustAllCerts)
            } else {
                Log.d(TAG, "WebSocket: Reusing existing OkHttpClient")
            }
            httpClient
        }

        val request = Request.Builder().url("wss://$ipAddress:$WEBSOCKET_PORT/")
            .header("Sec-WebSocket-Protocol", WS_PROTOCOL).build()

        val listener = CustomWebSocketListener(
            webSocketService = this,
            connectionListener = connectionListener,
            onBytes = { bytes -> onBytes?.invoke(bytes) },
            onSocketClosed = {
                clearConnectionState()
            },
            onSocketFailure = {
                clearConnectionState()
            }
        )
        // Create a new WebSocket connection
        webSocket = client?.newWebSocket(request, listener)
    }

    override fun sendBytes(data: ByteArray): Boolean =
        webSocket?.send(data.toByteString()) ?: false

    override fun disconnect() {
        try {
            udpListener?.stopListener()
            udpListener = null
        } catch (e: Exception) {
            Log.d(TAG, "Error stopping UDP listener", e)
        }

        clearConnectionState()

        synchronized(webSocketLock) {
            try {
                httpClient?.dispatcher?.executorService?.shutdown()
            } catch (e: Exception) {
                Log.d(TAG, "Error shutting down executor", e)
            }
            httpClient = null
        }

        try {
            connectionThread?.interrupt()
        } catch (e: Exception) {
            Log.d(TAG, "Error interrupting connection thread", e)
        }
        connectionThread = null

        Log.d(TAG, "WebSocket disconnected and cleaned up")
    }

    override fun connect() {
        udpListener?.stopListener() // Stop any existing listener before creating a new one
        udpListener = UDPBroadcastListener(
            onServerDiscovered = { serverIp ->
                sleep(500)
                connectToIPAddress(serverIp)
                udpListener?.stopListener()
            },
            broadcastPort = setupConfig?.devicePort
        )
        udpListener?.startUdpListener()
    }

    override fun isConnected(): Boolean {
        return webSocket != null
    }

    private fun buildHttpClient(
        sslContext: SSLContext, trustAllCerts: Array<X509TrustManager>
    ): OkHttpClient =
        OkHttpClient.Builder().sslSocketFactory(sslContext.socketFactory, trustAllCerts[0])
            .hostnameVerifier { _, _ -> true }.connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS).writeTimeout(30, TimeUnit.SECONDS)
            .pingInterval(30, TimeUnit.SECONDS).build()

    private fun createSslContext(): Pair<Array<X509TrustManager>, SSLContext?> {
        val trustAllCerts = arrayOf<X509TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, trustAllCerts, SecureRandom())
        return Pair(trustAllCerts, sslContext)
    }

    private inline fun <T> withWebSocketLock(action: () -> T): T =
        synchronized(webSocketLock) { action() }

    private fun startConnect(): Boolean = withWebSocketLock {
        if (isConnecting || webSocket != null) return@withWebSocketLock false
        isConnecting = true
        true
    }

    private fun finishConnect() = withWebSocketLock {
        if (webSocket == null) {
            isConnecting = false
        }
    }

    private fun clearConnectionState() = withWebSocketLock {
        webSocket = null
        isConnecting = false
    }
}
