package uk.ac.york.emrys

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import kotlin.concurrent.thread

class SetupService(
    private val context: Context,
    private val onSetupComplete: ((SetupConfig) -> Unit)? = null,
    private val onSetupError: ((String) -> Unit)? = null,
    private val onSasGenerated: ((String) -> Unit)? = null
) {
    companion object {
        private const val TAG = "SetupService"
        private const val PREFS_NAME = "setup_config"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_PORT = "device_port"
        private const val KEY_IS_PAIRED = "is_paired"
        private const val KEY_PRIVATE_KEY_ALIAS = "private_key_alias"
        private const val KEY_PUBLIC_KEY = "public_key"
        private const val KEY_PC_PUBLIC_KEY = "pc_public_key"
        private const val BT_SERVICE_NAME = "EmrysSetup"
        private const val BT_DISCOVERABLE_DURATION = 120
    }

    private val secureKeyStore = SecureKeyStore(context)
    private var setupClient: SetupClient? = null
    private var devicePort: Int = 0
    private var pendingPcCert: String? = null

    data class SetupConfig(
        val deviceId: String,
        val privateKeyAlias: String,
        val publicKey: String,
        val pcPublicKey: String,
        val devicePort: Int
    )

    fun isPaired(): Boolean = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getBoolean(KEY_IS_PAIRED, false)

    fun getStoredConfig(): SetupConfig? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_IS_PAIRED, false)) return null

        return SetupConfig(
            deviceId = prefs.getString(KEY_DEVICE_ID, "") ?: return null,
            privateKeyAlias = prefs.getString(KEY_PRIVATE_KEY_ALIAS, "") ?: return null,
            publicKey = prefs.getString(KEY_PUBLIC_KEY, "") ?: return null,
            pcPublicKey = prefs.getString(KEY_PC_PUBLIC_KEY, "") ?: return null,
            devicePort = prefs.getInt(KEY_PORT, 0)
        )
    }

    fun startSetup() {
        if (isPaired()) {
            getStoredConfig()?.let { onSetupComplete?.invoke(it) }
            return
        }

        thread {
            try {
                val deviceId = UUID.randomUUID().toString()
                devicePort = (10000..60000).random()
                val alias = "auth_$deviceId"

                KeyManager.deleteAlias(alias)
                val publicKey =
                    KeyManager.publicKeyToPEM(KeyManager.generateOrGetKeystorePublicKey(alias))

                initiatePairing(deviceId, publicKey, alias)
            } catch (e: Exception) {
                Log.e(TAG, "Setup failed", e)
                onSetupError?.invoke("Setup failed: ${e.message}")
            }
        }
    }

    private fun initiatePairing(deviceId: String, publicKey: String, alias: String) {
        val webSocketService = WebSocketService(
            connectionListener = object : ConnectionListener {
                override fun onConnected(connectionService: ConnectionService) {
                    val json = JSONObject().apply {
                        put("device_id", deviceId)
                        put("public_key", publicKey)
                        put("port", devicePort)
                    }
                    connectionService.sendMessage(json.toString())
                    setupClient?.apply {
                        setPrivateKeyAlias(alias)
                        setDeviceId(deviceId)
                    }
                }

                override fun onDisconnected(connectionService: ConnectionService) {}
            },
            messageListener = object : MessageListener {
                override fun onMessage(msg: String) {
                    if (msg != "ACK") handleResponse(msg, deviceId, alias, publicKey)
                }

                override fun onError(error: String) {
                    onSetupError?.invoke(error)
                }
            }
        )

        setupClient = SetupClient(webSocketService, null, null)
        webSocketService.connect()
    }

    private fun handleResponse(text: String, deviceId: String, alias: String, publicKey: String) {
        try {
            val json = JSONObject(text)
            when (json.optString("status")) {
                "pc_public_key" -> {
                    pendingPcCert = json.optString("pc_public_key")
                }

                "nonce_challenge" -> {
                    val serverNonce = json.optString("server_nonce")
                    val pcPub = pendingPcCert ?: return
                    val sas = computeSas(serverNonce, pcPub, publicKey)
                    onSasGenerated?.invoke(sas)

                    setupClient?.getWebSocketService()
                        ?.sendMessage(JSONObject().put("type", "nonce_response").toString())
                    startBtBinding(deviceId)
                }

                "ok" -> {
                    val pcPub = pendingPcCert ?: return
                    val config = SetupConfig(deviceId, alias, publicKey, pcPub, devicePort)
                    saveConfig(config)
                    setupClient?.disconnect()
                    onSetupComplete?.invoke(config)
                }

                else -> onSetupError?.invoke(json.optString("message", "Unknown error"))
            }
        } catch (e: Exception) {
            onSetupError?.invoke("Protocol error")
        }
    }

    private fun computeSas(nonce: String, pcKey: String, deviceKey: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        listOf(nonce, pcKey, deviceKey).forEach {
            val bytes = it.toByteArray()
            md.update(ByteBuffer.allocate(4).putInt(bytes.size).array())
            md.update(bytes)
        }
        val hash = md.digest()
        val code = ByteBuffer.wrap(hash).int and 0x7FFFFFFF
        return String.format(Locale.US, "%06d", code % 1_000_000)
    }

    private fun saveConfig(config: SetupConfig) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit {
            putString(KEY_DEVICE_ID, config.deviceId)
            putString(KEY_PRIVATE_KEY_ALIAS, config.privateKeyAlias)
            putString(KEY_PUBLIC_KEY, config.publicKey)
            putString(KEY_PC_PUBLIC_KEY, config.pcPublicKey)
            putInt(KEY_PORT, config.devicePort)
            putBoolean(KEY_IS_PAIRED, true)
        }
    }

    fun clearConfig() {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(KEY_PRIVATE_KEY_ALIAS, null)?.let { KeyManager.deleteAlias(it) }
        prefs.edit().clear().apply()
        secureKeyStore.clear()
    }

    fun stop() {
        setupClient?.disconnect()
        setupClient = null
    }

    private fun startBtBinding(deviceId: String) {
        thread(isDaemon = true) {
            val adapter = BluetoothAdapter.getDefaultAdapter() ?: return@thread
            if (!adapter.isEnabled) return@thread

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.BLUETOOTH_CONNECT
                ) != PackageManager.PERMISSION_GRANTED
            ) return@thread

            try {
                // Request discoverability so the PC can find the MAC address
                (context as? Activity)?.startActivity(Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
                    putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, BT_DISCOVERABLE_DURATION)
                })

                val uuid = UUID.fromString(deviceId)
                val server = adapter.listenUsingRfcommWithServiceRecord(BT_SERVICE_NAME, uuid)
                server.accept(90000)?.close() // Wait for PC to verify visibility
                server.close()
            } catch (e: Exception) {
                Log.w(TAG, "BT binding closed")
            }
        }
    }
}
