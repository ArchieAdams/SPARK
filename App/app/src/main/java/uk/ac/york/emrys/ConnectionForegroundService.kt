package uk.ac.york.emrys

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

class ConnectionForegroundService : Service(), ConnectionListener, MessageListener {

    companion object {
        private const val TAG = "ConnectionService"
        private const val CHANNEL_ID = "connection_service_channel"
        private const val CHANNEL_AUTH = "auth_request_channel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_START_CONNECTION = "uk.ac.york.emrys.START_CONNECTION"
        const val ACTION_STOP_CONNECTION  = "uk.ac.york.emrys.STOP_CONNECTION"

        private const val PREFS_NAME = "pending_auth_state"
        private const val KEY_PENDING_CHALLENGE = "pending_challenge"
        private const val KEY_PENDING_DEVICE_LABEL = "pending_device_label"
    }

    private var connectionManager: ConnectionManager? = null
    private var setupConfig: SetupService.SetupConfig? = null
    private var isConnected = false
    private var currentConnectionType: String = "Initializing"

    private var uiListener: ConnectionListener? = null
    private var uiMessageListener: MessageListener? = null

    private var pendingChallenge: String? = null
    private var pendingDeviceLabel: String? = null

    private val binder = LocalBinder()
    private val prefs by lazy { getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) }

    inner class LocalBinder : Binder() {
        fun getService(): ConnectionForegroundService = this@ConnectionForegroundService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    fun setUIListeners(connectionListener: ConnectionListener?, messageListener: MessageListener?) {
        uiListener = connectionListener
        uiMessageListener = messageListener
    }

    fun getPendingAuthChallenge(): String? = pendingChallenge ?: prefs.getString(KEY_PENDING_CHALLENGE, null)
    fun getPendingAuthDeviceLabel(): String? = pendingDeviceLabel ?: prefs.getString(KEY_PENDING_DEVICE_LABEL, null)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        
        val filter = IntentFilter().apply {
            addAction(LoginApprovalActivity.ACTION_APPROVED)
            addAction(LoginApprovalActivity.ACTION_DENIED)
        }
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) RECEIVER_NOT_EXPORTED else 0
        registerReceiver(approvalReceiver, filter, flags)
    }

    private val approvalReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                LoginApprovalActivity.ACTION_APPROVED -> {
                    val challenge = intent.getStringExtra(LoginApprovalActivity.EXTRA_RESULT_CHALLENGE) ?: pendingChallenge
                    clearPendingAuth()
                    challenge?.let { processApprovedChallenge(it) }
                }
                LoginApprovalActivity.ACTION_DENIED -> {
                    clearPendingAuth()
                    uiMessageListener?.onMessage("✗ Login request denied")
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: return START_STICKY

        when (action) {
            ACTION_START_CONNECTION -> {
                val stored = SetupService(this).getStoredConfig()
                if (stored == null) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                setupConfig = stored
                
                startForeground(NOTIFICATION_ID, createNotification("Connecting", "Initializing connection..."))
                
                // Re-initialize connections if config changes or after new pairing
                stopConnections()
                startConnections()
            }
            ACTION_STOP_CONNECTION -> {
                stopConnections()
                clearPendingAuth()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun startConnections() {
        val adapter = (getSystemService(BLUETOOTH_SERVICE) as BluetoothManager).adapter
        connectionManager = ConnectionManager(this, setupConfig).apply {
            startConnection(adapter, this@ConnectionForegroundService)
        }
    }

    private fun stopConnections() {
        connectionManager?.destroy()
        connectionManager = null
    }

    override fun onMessage(msg: String) {
        if (msg in listOf("PING", "PONG", "ACK")) return

        if (setupConfig != null && msg.length > 100 && msg.matches(Regex("[0-9a-fA-F]+"))) {
            storePendingAuth(msg, pendingDeviceLabel ?: "Linked PC")
            showLoginApprovalScreen(msg)
            uiMessageListener?.onMessage("⏳ Login request received")
            return
        }
        uiMessageListener?.onMessage(msg)
    }

    override fun onError(error: String) {
        if (error.startsWith("EOFException")) return
        uiMessageListener?.onError(error)
    }

    override fun onConnected(connectionService: ConnectionService) {
        isConnected = true
        currentConnectionType = connectionService.javaClass.simpleName
        uiListener?.onConnected(connectionService)
        updateNotification("Connected", "Active: $currentConnectionType")
    }

    override fun onDisconnected(connectionService: ConnectionService) {
        isConnected = false
        uiListener?.onDisconnected(connectionService)
        updateNotification("Reconnecting", "Connection lost")
    }

    private fun showLoginApprovalScreen(challenge: String) {
        val intent = Intent(this, LoginApprovalActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(LoginApprovalActivity.EXTRA_CHALLENGE, challenge)
            putExtra(LoginApprovalActivity.EXTRA_DEVICE_LABEL, pendingDeviceLabel ?: "Linked PC")
        }

        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, CHANNEL_AUTH)
            .setContentTitle("🔐 Login Attempt")
            .setContentText("Tap to approve login on your PC")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setFullScreenIntent(pendingIntent, true)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .build()

        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(2, notification)
        startActivity(intent)
    }

    private fun processApprovedChallenge(challenge: String) {
        try {
            val handler = CryptoMessageHandler(this)
            handler.processAuthenticationChallenge(challenge)?.let {
                connectionManager?.sendMessage(it)
                uiMessageListener?.onMessage("✓ Login approved")
            } ?: run {
                uiMessageListener?.onMessage("✗ ${handler.lastUserErrorMessage ?: "Auth failed"}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Auth processing error", e)
        }
    }

    private fun storePendingAuth(challenge: String, label: String) {
        pendingChallenge = challenge
        pendingDeviceLabel = label
        prefs.edit().putString(KEY_PENDING_CHALLENGE, challenge).putString(KEY_PENDING_DEVICE_LABEL, label).apply()
    }

    private fun clearPendingAuth() {
        pendingChallenge = null
        pendingDeviceLabel = null
        prefs.edit().remove(KEY_PENDING_CHALLENGE).remove(KEY_PENDING_DEVICE_LABEL).apply()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Connection", NotificationManager.IMPORTANCE_LOW))
            nm.createNotificationChannel(NotificationChannel(CHANNEL_AUTH, "Login Requests", NotificationManager.IMPORTANCE_HIGH))
        }
    }

    private fun updateNotification(title: String, text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, createNotification(title, text))
    }

    private fun createNotification(title: String, text: String): android.app.Notification {
        val pendingIntent = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(approvalReceiver)
        stopConnections()
    }
}
