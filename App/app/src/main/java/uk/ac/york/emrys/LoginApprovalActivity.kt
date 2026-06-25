package uk.ac.york.emrys

import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LoginApprovalActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_CHALLENGE = "extra_challenge"
        const val EXTRA_DEVICE_LABEL = "extra_device_label"
        const val ACTION_APPROVED = "uk.ac.york.emrys.LOGIN_APPROVED"
        const val ACTION_DENIED  = "uk.ac.york.emrys.LOGIN_DENIED"
        const val EXTRA_RESULT_CHALLENGE = "extra_result_challenge"
        private const val COUNTDOWN_MS = 30_000L
    }

    private lateinit var subtitleText: TextView
    private lateinit var deviceText: TextView
    private lateinit var timeText: TextView
    private lateinit var biometricHint: TextView
    private lateinit var countdownText: TextView
    private lateinit var approveButton: Button
    private lateinit var denyButton: Button

    private var challengePayload: String? = null
    private var deviceLabel: String = "Linked Laptop"
    private var countDownTimer: CountDownTimer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login_approval)

        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        subtitleText   = findViewById(R.id.approvalSubtitle)
        deviceText     = findViewById(R.id.approvalDeviceText)
        timeText       = findViewById(R.id.approvalTimeText)
        biometricHint  = findViewById(R.id.biometricHintText)
        countdownText  = findViewById(R.id.countdownText)
        approveButton  = findViewById(R.id.approveButton)
        denyButton     = findViewById(R.id.denyButton)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                denyLogin()
            }
        })

        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        countDownTimer?.cancel()
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        challengePayload = intent.getStringExtra(EXTRA_CHALLENGE)
        deviceLabel = intent.getStringExtra(EXTRA_DEVICE_LABEL) ?: "Linked Laptop"

        if (challengePayload == null) {
            finish()
            return
        }

        timeText.text = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        deviceText.text = deviceLabel
        subtitleText.text = "Login attempt detected"

        val biometricManager = BiometricManager.from(this)
        val canAuth = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        )
        
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            biometricHint.text = "Tap Approve to confirm"
        }

        approveButton.setOnClickListener { launchBiometricPrompt() }
        denyButton.setOnClickListener { denyLogin() }

        startCountdown()
    }

    private fun startCountdown() {
        countDownTimer?.cancel()
        countDownTimer = object : CountDownTimer(COUNTDOWN_MS, 1000L) {
            override fun onTick(millisUntilFinished: Long) {
                countdownText.text = "Expires in ${millisUntilFinished / 1000}s"
            }
            override fun onFinish() {
                denyLogin()
            }
        }.start()
    }

    private fun launchBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(this)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                approveLogin()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                denyLogin()
            }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm Login")
            .setSubtitle("Authenticate to approve access")
            .setNegativeButtonText("Deny")
            .setConfirmationRequired(true)
            .build()

        BiometricPrompt(this, executor, callback).authenticate(promptInfo)
    }

    private fun approveLogin() {
        countDownTimer?.cancel()
        val intent = Intent(ACTION_APPROVED).apply {
            putExtra(EXTRA_RESULT_CHALLENGE, challengePayload)
            setPackage(packageName)
        }
        sendBroadcast(intent)
        Toast.makeText(this, "Login approved", Toast.LENGTH_SHORT).show()
        finish()
    }

    private fun denyLogin() {
        countDownTimer?.cancel()
        val intent = Intent(ACTION_DENIED).apply {
            setPackage(packageName)
        }
        sendBroadcast(intent)
        finish()
    }

    override fun onDestroy() {
        countDownTimer?.cancel()
        super.onDestroy()
    }
}
