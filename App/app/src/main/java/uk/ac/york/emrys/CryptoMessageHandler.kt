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
        private const val MAX_PLAINTEXT_BYTES = RSA_KEY_SIZE_BYTES - 66 // OAEP-SHA256 max = 318
        private const val N_LEN = 32
        private const val CTR_LEN = 8
        private const val M_LEN = N_LEN + CTR_LEN // M = N || ctr = 40
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

    private fun getPcPublicKey(): PublicKey =
        pemToPublicKey(setup.getStoredConfig()?.pcPublicKey ?: throw IllegalStateException("PC public key missing"))

    private fun getOwnPublicKey(): PublicKey =
        pemToPublicKey(setup.getStoredConfig()?.publicKey ?: throw IllegalStateException("Own public key missing"))

    private fun pemToPublicKey(pem: String): PublicKey {
        val pemParser = PEMParser(StringReader(pem))
        val pemObject = pemParser.readObject()
        pemParser.close()
        val converter = JcaPEMKeyConverter()
        return when (pemObject) {
            is SubjectPublicKeyInfo -> converter.getPublicKey(pemObject)
            else -> throw IllegalArgumentException("Unsupported PEM type: ${pemObject?.javaClass?.simpleName}")
        }
    }

    // Decrypt one or more RSA-OAEP blocks (input must be a multiple of key size).
    private fun chunkedDecrypt(data: ByteArray): ByteArray {
        require(data.isNotEmpty() && data.size % RSA_KEY_SIZE_BYTES == 0) { "bad ciphertext length" }
        val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(), spec)
        val out = java.io.ByteArrayOutputStream()
        var off = 0
        while (off < data.size) {
            out.write(cipher.doFinal(data, off, RSA_KEY_SIZE_BYTES))
            off += RSA_KEY_SIZE_BYTES
        }
        return out.toByteArray()
    }

    // Encrypt a blob to the PC across as many OAEP blocks as needed.
    private fun chunkedEncrypt(blob: ByteArray): ByteArray {
        val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getPcPublicKey(), spec)
        val out = java.io.ByteArrayOutputStream()
        var off = 0
        while (off < blob.size) {
            val len = minOf(MAX_PLAINTEXT_BYTES, blob.size - off)
            out.write(cipher.doFinal(blob, off, len))
            off += len
        }
        return out.toByteArray()
    }

    data class Verified(val m: ByteArray, val ctr: Long)

    // Decrypt, verify sign(M||pk_V||pk_A), and gate on the monotonic counter.
    fun verifyChallenge(challenge: ByteArray): Verified? {
        return try {
            val blob = chunkedDecrypt(challenge)
            if (blob.size <= RSA_KEY_SIZE_BYTES) return null
            val mLen = blob.size - RSA_KEY_SIZE_BYTES
            if (mLen != M_LEN) return null
            val m = blob.copyOfRange(0, mLen)
            val signature = blob.copyOfRange(mLen, blob.size)

            // signed input = M || pk_V || pk_A (reconstructed from keys we hold)
            val signedInput = m + getPcPublicKey().encoded + getOwnPublicKey().encoded
            val verifier = Signature.getInstance("SHA384withRSA/PSS")
            verifier.initVerify(getPcPublicKey())
            verifier.update(signedInput)
            if (!verifier.verify(signature)) {
                lastUserErrorMessage = "Signature verification failed"
                return null
            }

            val ctr = m.copyOfRange(N_LEN, M_LEN).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xFF) }
            if (ctr <= setup.getAuthCounter()) {
                lastUserErrorMessage = "Stale challenge (replay)"
                return null
            }
            Verified(m, ctr)
        } catch (e: Exception) {
            Log.e(TAG, "Verify challenge failed", e)
            null
        }
    }

    // On approval: update counter, sign M||pk_A||pk_V (swapped) and encrypt to PC.
    private fun buildResponse(v: Verified): ByteArray {
        setup.setAuthCounter(v.ctr)
        val signedInput = v.m + getOwnPublicKey().encoded + getPcPublicKey().encoded
        val signer = Signature.getInstance("SHA384withRSA/PSS")
        signer.initSign(getPrivateKey())
        signer.update(signedInput)
        val signature = signer.sign()
        return chunkedEncrypt(v.m + signature)
    }

    fun processAuthenticationChallenge(challenge: ByteArray): ByteArray? {
        return try {
            val v = verifyChallenge(challenge) ?: return null
            buildResponse(v)
        } catch (e: Exception) {
            Log.e(TAG, "Process challenge failed", e)
            null
        }
    }
}
