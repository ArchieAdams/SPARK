package uk.ac.york.emrys

import android.util.Log

class SetupClient(
    private val webSocketService: WebSocketService,
    private var privateKeyAlias: String?,
    private var deviceId: String?
) {
    companion object {
        private const val TAG = "SetupClient"
    }

    fun setPrivateKeyAlias(alias: String) {
        privateKeyAlias = alias
    }

    fun setDeviceId(id: String) {
        deviceId = id
    }

    fun getPrivateKeyAlias(): String? = privateKeyAlias

    fun getDeviceId(): String? = deviceId

    fun getWebSocketService(): WebSocketService = webSocketService

    fun disconnect() {
        try {
            webSocketService.disconnect()
            Log.d(TAG, "Setup connection disconnected")
        } catch (e: Exception) {
            Log.e(TAG, "Error disconnecting", e)
        }
    }
}