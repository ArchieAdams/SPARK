package uk.ac.york.emrys


import android.util.Log
import java.io.EOFException
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

class CustomWebSocketListener(
    private val webSocketService: WebSocketService,
    private val connectionListener: ConnectionListener? = null,
    private val messageListener: MessageListener? = null,
    private val onSocketOpen: (() -> Unit)? = null,
    private val onSocketClosed: (() -> Unit)? = null,
    private val onSocketFailure: ((Throwable) -> Unit)? = null
) : WebSocketListener() {

    companion object {
        private const val TAG = "CustomWebSocketListener"
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        Log.d(TAG, "WebSocket Connected successfully")
        webSocketService.setConnected(true)
        onSocketOpen?.invoke()
        connectionListener?.onConnected(webSocketService)
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        Log.d(TAG, "onMessage: Received: $text")
        messageListener?.onMessage(text)
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        Log.d(TAG, "onClosing called! code=$code reason=$reason")
        webSocket.close(1000, null)
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        Log.d(TAG, "onClosed: code=$code reason=$reason")
        webSocketService.setConnected(false)
        connectionListener?.onDisconnected(webSocketService)
        onSocketClosed?.invoke()
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        if (t is EOFException) {
            Log.d(TAG, "WebSocket closed by server (EOFException)")
            webSocketService.setConnected(false)
            connectionListener?.onDisconnected(webSocketService)
            onSocketClosed?.invoke()
            return
        }

        Log.e(TAG, "onFailure called!", t)
        webSocketService.setConnected(false)
        messageListener?.onError("${t.javaClass.simpleName}: ${t.message}")
        connectionListener?.onDisconnected(webSocketService)
        onSocketFailure?.invoke(t)
    }
}