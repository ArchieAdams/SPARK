package uk.ac.york.emrys

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.ViewFlipper
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity(), MessageListener, ConnectionListener {

    private lateinit var headerStatus: TextView
    private lateinit var viewFlipper: ViewFlipper

    // Welcome screen (Index 0)
    private lateinit var getStartedButton: Button

    // Pairing screen (Index 1)
    private lateinit var pairingProgressBar: ProgressBar
    private lateinit var pairingStatusText: TextView
    private lateinit var pairingSasText: TextView
    private lateinit var pairingDetailText: TextView
    private lateinit var retryPairingButton: Button
    private lateinit var sasButtonRow: View
    private lateinit var confirmSasButton: Button
    private lateinit var rejectSasButton: Button

    // Connected screen (Index 2)
    private lateinit var deviceIdText: TextView
    private lateinit var unpairButton: Button

    private var foregroundService: ConnectionForegroundService? = null
    private var serviceBound = false

    private var setupService: SetupService? = null
    private var setupConfig: SetupService.SetupConfig? = null
    private var biometricLocked = true

    companion object {
        private const val WELCOME_SCREEN = 0
        private const val PAIRING_SCREEN = 1
        private const val CONNECTED_SCREEN = 2
        private const val PERMISSION_REQUEST_BLUETOOTH = 1
        private const val PERMISSION_REQUEST_NOTIFICATION = 2
        private const val PENDING_AUTH_PREFS = "pending_auth_state"
        private const val KEY_PENDING_CHALLENGE = "pending_challenge"
        private const val KEY_PENDING_DEVICE_LABEL = "pending_device_label"
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as ConnectionForegroundService.LocalBinder
            foregroundService = binder.getService()
            serviceBound = true
            Log.d("MainActivity", "Service bound")
            foregroundService?.setUIListeners(this@MainActivity, this@MainActivity)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            foregroundService = null
            serviceBound = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        setupButtonListeners()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN),
                PERMISSION_REQUEST_BLUETOOTH
            )
        } else {
            requestNotificationPermissionIfNeeded()
        }
    }

    override fun onResume() {
        super.onResume()
        if (setupService?.isPaired() == true && biometricLocked) {
            promptBiometricUnlock()
        }
        openPendingAuthIfNeeded()
    }

    private fun initViews() {
        headerStatus = findViewById(R.id.headerStatus)
        viewFlipper = findViewById(R.id.viewFlipper)

        // Welcome screen
        getStartedButton = findViewById(R.id.getStartedButton)

        // Pairing screen
        pairingProgressBar = findViewById(R.id.pairingProgressBar)
        pairingStatusText = findViewById(R.id.pairingStatusText)
        pairingSasText = findViewById(R.id.pairingSasText)
        pairingDetailText = findViewById(R.id.pairingDetailText)
        retryPairingButton = findViewById(R.id.retryPairingButton)
        sasButtonRow = findViewById(R.id.sasButtonRow)
        confirmSasButton = findViewById(R.id.confirmSasButton)
        rejectSasButton = findViewById(R.id.rejectSasButton)

        // Connected screen
        deviceIdText = findViewById(R.id.deviceIdText)
        unpairButton = findViewById(R.id.unpairButton)

        applySafeAreaPadding()
    }

    private fun promptBiometricUnlock() {
        val biometricManager = BiometricManager.from(this)
        val canAuth = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        )

        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            biometricLocked = false
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                biometricLocked = false
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                finishAffinity()
            }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Emrys")
            .setSubtitle("Authenticate to open Emrys")
            .setNegativeButtonText("Cancel")
            .build()

        BiometricPrompt(this, executor, callback).authenticate(promptInfo)
    }

    private fun applySafeAreaPadding() {
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    private fun setupButtonListeners() {
        getStartedButton.setOnClickListener {
            if (setupService == null) checkInitialState()
            showPairingScreen()
            setupService?.startSetup()
        }

        retryPairingButton.setOnClickListener {
            if (setupService == null) checkInitialState()
            retryPairing()
        }

        confirmSasButton.setOnClickListener {
            sasButtonRow.visibility = View.GONE
            pairingStatusText.text = "Finishing pairing..."
            pairingProgressBar.visibility = View.VISIBLE
            setupService?.confirmSas(true)
        }

        rejectSasButton.setOnClickListener {
            sasButtonRow.visibility = View.GONE
            setupService?.confirmSas(false)
        }

        unpairButton.setOnClickListener {
            unpairDevice()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            PERMISSION_REQUEST_BLUETOOTH -> {
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    requestNotificationPermissionIfNeeded()
                }
            }
            PERMISSION_REQUEST_NOTIFICATION -> {
                checkInitialState()
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    PERMISSION_REQUEST_NOTIFICATION
                )
            } else {
                checkInitialState()
            }
        } else {
            checkInitialState()
        }
    }

    private fun checkInitialState() {
        setupService = SetupService(
            context = this,
            onSetupComplete = { config ->
                runOnUiThread {
                    showConnectedScreen(config)
                    startConnections()
                    openPendingAuthIfNeeded()
                }
            },
            onSetupError = { error ->
                runOnUiThread { showPairingError(error) }
            },
            onSasGenerated = { sas ->
                runOnUiThread { showSasCode(sas) }
            }
        )

        if (setupService?.isPaired() == true) {
            val config = setupService?.getStoredConfig()
            if (config != null) {
                showConnectedScreen(config)
                startConnections()
                openPendingAuthIfNeeded()
                return
            }
        }
        showWelcomeScreen()
    }

    private fun showWelcomeScreen() {
        runOnUiThread {
            viewFlipper.displayedChild = WELCOME_SCREEN
            headerStatus.text = "Welcome"
        }
    }

    private fun showPairingScreen() {
        runOnUiThread {
            viewFlipper.displayedChild = PAIRING_SCREEN
            headerStatus.text = "Pairing..."
            pairingProgressBar.visibility = View.VISIBLE
            pairingStatusText.text = "Initializing pairing..."
            pairingSasText.visibility = View.GONE
            pairingDetailText.visibility = View.GONE
            retryPairingButton.visibility = View.GONE
            sasButtonRow.visibility = View.GONE
        }
    }

    private fun showPairingError(error: String) {
        runOnUiThread {
            viewFlipper.displayedChild = PAIRING_SCREEN
            headerStatus.text = "Pairing Failed"
            pairingProgressBar.visibility = View.GONE
            pairingStatusText.text = "Pairing failed"
            pairingDetailText.text = error
            pairingDetailText.visibility = View.VISIBLE
            retryPairingButton.visibility = View.VISIBLE
            sasButtonRow.visibility = View.GONE
        }
    }

    private fun retryPairing() {
        showPairingScreen()
        setupService?.startSetup()
    }

    private fun showConnectedScreen(config: SetupService.SetupConfig) {
        setupConfig = config
        runOnUiThread {
            viewFlipper.displayedChild = CONNECTED_SCREEN
            headerStatus.text = "Linked"
            deviceIdText.text = "Device ID: ${config.deviceId.take(8)}"
        }
    }

    private fun showSasCode(sas: String) {
        runOnUiThread {
            pairingProgressBar.visibility = View.GONE
            pairingStatusText.text = "Confirm code on both devices"
            pairingSasText.text = sas
            pairingSasText.visibility = View.VISIBLE
            pairingDetailText.text = "Verify the SAS code matches the one shown on your PC."
            pairingDetailText.visibility = View.VISIBLE
            sasButtonRow.visibility = View.VISIBLE
        }
    }

    private fun unpairDevice() {
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        val serviceIntent = Intent(this, ConnectionForegroundService::class.java)
        serviceIntent.action = ConnectionForegroundService.ACTION_STOP_CONNECTION
        startService(serviceIntent)

        setupService?.clearConfig()
        showWelcomeScreen()
        Toast.makeText(this, "Device unlinked", Toast.LENGTH_SHORT).show()
    }

    private fun startConnections() {
        val serviceIntent = Intent(this, ConnectionForegroundService::class.java).apply {
            action = ConnectionForegroundService.ACTION_START_CONNECTION
            setupConfig?.let { config ->
                putExtra("deviceId", config.deviceId)
                putExtra("publicKey", config.publicKey)
                putExtra("pcPublicKey", config.pcPublicKey)
                putExtra("devicePort", config.devicePort)
            }
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
        bindService(
            Intent(this, ConnectionForegroundService::class.java),
            serviceConnection,
            Context.BIND_AUTO_CREATE
        )
    }

    private fun openPendingAuthIfNeeded() {
        val pendingChallenge = foregroundService?.getPendingAuthChallenge()
            ?: getSharedPreferences("pending_auth_state", Context.MODE_PRIVATE)
                .getString("pending_challenge", null)
        if (pendingChallenge.isNullOrBlank()) return

        val deviceLabel = foregroundService?.getPendingAuthDeviceLabel()
            ?: getSharedPreferences("pending_auth_state", Context.MODE_PRIVATE)
                .getString("pending_device_label", null)
            ?: "Linked PC"

        val intent = Intent(this, LoginApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(LoginApprovalActivity.EXTRA_CHALLENGE, pendingChallenge)
            putExtra(LoginApprovalActivity.EXTRA_DEVICE_LABEL, deviceLabel)
        }
        startActivity(intent)
    }

    override fun onMessage(msg: String) {}
    override fun onError(error: String) {}
    override fun onConnected(connectionService: ConnectionService) {}
    override fun onDisconnected(connectionService: ConnectionService) {}

    override fun onStop() {
        super.onStop()
        if (setupService?.isPaired() == true) biometricLocked = true
    }

    override fun onDestroy() {
        super.onDestroy()
        setupService?.stop()
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
    }
}
