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
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
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
        private const val KEY_AUTH_COUNTER = "auth_counter"
        private const val BT_SERVICE_NAME = "EmrysSetup"
        private const val BT_DISCOVERABLE_DURATION = 120
    }

    private val secureKeyStore = SecureKeyStore(context)
    private var devicePort: Int = 0
    private var ws: WebSocketService? = null
    private var channel: Channel? = null
    private var alias = ""
    private var deviceId = ""
    private var pkADer: ByteArray? = null
    @Volatile private var pkVDer: ByteArray? = null
    @Volatile private var commitC: ByteArray? = null
    @Volatile private var userAccepted = false
    @Volatile private var peerAccepted: Boolean? = null
    private val lock = Any()

    data class SetupConfig(
        val deviceId: String,
        val privateKeyAlias: String,
        val publicKey: String,
        val pcPublicKey: String,
        val devicePort: Int
    )

    fun isPaired(): Boolean = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getBoolean(KEY_IS_PAIRED, false)

    // Last counter (ctr_A) accepted from the verifier.
    fun getAuthCounter(): Long = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getLong(KEY_AUTH_COUNTER, 0L)

    fun setAuthCounter(value: Long) = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit { putLong(KEY_AUTH_COUNTER, value) }

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
                deviceId = UUID.randomUUID().toString()
                devicePort = (10000..60000).random()
                alias = "auth_$deviceId"

                KeyManager.deleteAlias(alias)
                pkADer = KeyManager.generateOrGetKeystorePublicKey(alias).encoded  // DER (X.509 SPKI)

                startPairing()
            } catch (e: Exception) {
                Log.e(TAG, "Setup failed", e)
                onSetupError?.invoke("Setup failed: ${e.message}")
            }
        }
    }

    private fun startPairing() {
        ws = WebSocketService(
            connectionListener = object : ConnectionListener {
                override fun onConnected(connectionService: ConnectionService) {
                    channel?.send(
                        MsgType.MSG_SETUP_REQ,
                        Messages.setupReq(UUID.fromString(deviceId), pkADer!!, devicePort)
                    )
                }
                override fun onDisconnected(connectionService: ConnectionService) {}
            }
        )
        channel = Channel(ws!!) { m -> handleMessage(m) }
        ws!!.connect()
    }

    private fun handleMessage(m: Message) {
        try {
            when (m.type) {
                MsgType.MSG_COMMIT -> {
                    val c = Messages.parseCommit(m.payload)
                    pkVDer = c.pkV
                    commitC = c.c
                }

                MsgType.MSG_REVEAL -> {
                    val rv = Messages.parseReveal(m.payload)
                    val expected = sha256(rv.n + rv.r)
                    if (!expected.contentEquals(commitC)) {
                        abort(AbortReason.COMMITMENT_MISMATCH, "Commitment mismatch")
                        return
                    }
                    val sas = Messages.sas(rv.n, pkVDer!!, pkADer!!)
                    onSasGenerated?.invoke(sas)
                }

                MsgType.MSG_SAS_CONFIRM -> {
                    peerAccepted = Messages.parseSasConfirm(m.payload)
                    maybeComplete()
                }

                MsgType.MSG_ABORT -> {
                    onSetupError?.invoke("Pairing aborted: ${Messages.parseAbort(m.payload)}")
                    cleanup()
                }

                else -> Log.d(TAG, "Ignoring ${m.type} during pairing")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Pairing message error", e)
            abort(AbortReason.PROTOCOL_ERROR, "Protocol error")
        }
    }

    fun confirmSas(accept: Boolean) {
        userAccepted = accept
        channel?.send(MsgType.MSG_SAS_CONFIRM, Messages.sasConfirm(accept))
        if (!accept) {
            onSetupError?.invoke("Pairing rejected by user")
            cleanup()
            return
        }
        maybeComplete()
    }

    private fun maybeComplete() = synchronized(lock) {
        when {
            peerAccepted == false -> {
                onSetupError?.invoke("Peer rejected pairing")
                cleanup()
            }
            userAccepted && peerAccepted == true -> {
                val config = SetupConfig(
                    deviceId = deviceId,
                    privateKeyAlias = alias,
                    publicKey = derToPem(pkADer!!),
                    pcPublicKey = derToPem(pkVDer!!),
                    devicePort = devicePort
                )
                saveConfig(config)
                startBtBinding(deviceId)
                onSetupComplete?.invoke(config)
                cleanup()
            }
        }
    }

    private fun abort(reason: AbortReason, msg: String) {
        channel?.send(MsgType.MSG_ABORT, Messages.abort(reason))
        onSetupError?.invoke(msg)
        cleanup()
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun derToPem(der: ByteArray): String {
        val pub = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
        return KeyManager.publicKeyToPEM(pub)
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

    private fun cleanup() {
        channel?.close()
        channel = null
        ws?.disconnect()
        ws = null
    }

    fun stop() = cleanup()

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
