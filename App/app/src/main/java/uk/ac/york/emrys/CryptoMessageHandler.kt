package uk.ac.york.emrys

import android.content.Context
import android.util.Log
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.StringReader
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class CryptoMessageHandler(private val context: Context) {
    companion object {
        private const val TAG = "CryptoHandler"
        private const val RSA_KEY_SIZE_BYTES = 384 // 3072 bits
        private const val CHALLENGE_PAYLOAD_SIZE = 40
    }

    private val setup = SetupService(context)
    var lastUserErrorMessage: String? = null

    init {
        // Ensure BouncyCastle is available for PEM parsing and specific structure support
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private fun getPrivateKey(): PrivateKey {
        val config = setup.getStoredConfig() ?: throw IllegalStateException("Missing setup config")
        return KeyManager.getPrivateKey(config.privateKeyAlias) ?: throw IllegalStateException("Private key missing")
    }

    private fun getPcPublicKey(): PublicKey {
        val pem = setup.getStoredConfig()?.pcPublicKey ?: throw IllegalStateException("PC public key missing")
        val reader = StringReader(pem)
        val pemParser = PEMParser(reader)
        val pemObject = pemParser.readObject()
        pemParser.close()
        val converter = JcaPEMKeyConverter()
        return when (pemObject) {
            is SubjectPublicKeyInfo -> converter.getPublicKey(pemObject)
            else -> throw IllegalArgumentException("Unsupported PEM type: ${pemObject?.javaClass?.simpleName}")
        }
    }

    private fun decrypt(data: ByteArray): ByteArray {
        // RSA OAEP-SHA256 with MGF1-SHA1 padding
        val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(), spec)
        return cipher.doFinal(data)
    }

    private fun encrypt(data: ByteArray): ByteArray {
        // RSA OAEP-SHA256 with MGF1-SHA1 padding
        val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getPcPublicKey(), spec)
        return cipher.doFinal(data)
    }

    fun processAuthenticationChallenge(challenge: ByteArray): ByteArray? {
        return try {
            val raw = challenge
            if (raw.size < 4) return null

            val sigLen = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
            val cipherLen = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)

            if (raw.size != 4 + sigLen + cipherLen) return null

            val signature = raw.copyOfRange(4, 4 + sigLen)
            val ciphertext = raw.copyOfRange(4 + sigLen, raw.size)

            val plaintext = decrypt(ciphertext)

            // Verify using SHA384withRSA/PSS
            // Use the default platform provider as it supports PSS better than the restricted BC on Android
            val verifier = Signature.getInstance("SHA384withRSA/PSS")
            verifier.initVerify(getPcPublicKey())
            verifier.update(plaintext)
            if (!verifier.verify(signature)) {
                lastUserErrorMessage = "Signature verification failed"
                return null
            }

            if (plaintext.size < CHALLENGE_PAYLOAD_SIZE) return null

            // Validate timestamp
            val timestamp = plaintext.copyOfRange(32, 40).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xFF) }
            if (timestamp < System.currentTimeMillis() / 1000) {
                lastUserErrorMessage = "Challenge expired"
                return null
            }

            // Create signed and encrypted response
            val response = plaintext.copyOfRange(0, CHALLENGE_PAYLOAD_SIZE)
            val finalCiphertext = encrypt(response)

            val signer = Signature.getInstance("SHA384withRSA/PSS")
            signer.initSign(getPrivateKey())
            signer.update(response)
            val finalSignature = signer.sign()

            val output = ByteArray(4 + finalSignature.size + finalCiphertext.size)
            output[0] = ((finalSignature.size shr 8) and 0xFF).toByte()
            output[1] = (finalSignature.size and 0xFF).toByte()
            output[2] = ((finalCiphertext.size shr 8) and 0xFF).toByte()
            output[3] = (finalCiphertext.size and 0xFF).toByte()
            System.arraycopy(finalSignature, 0, output, 4, finalSignature.size)
            System.arraycopy(finalCiphertext, 0, output, 4 + finalSignature.size, finalCiphertext.size)

            output
        } catch (e: Exception) {
            Log.e(TAG, "Process challenge failed", e)
            null
        }
    }
}
