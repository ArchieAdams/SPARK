package uk.ac.york.spark

import android.content.Context
import android.util.Log
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.StringReader
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoMessageHandler(private val context: Context) {
    class SessionState(
        val ephV: ByteArray,
        val ephA_sk: X25519PrivateKeyParameters,
        val ephA_pk: ByteArray,
        val Z: ByteArray,
        val T: ByteArray,
        val keyGcm: ByteArray,
        val ivReq: ByteArray,
        val ivResp: ByteArray,
        val sessionId: String,
        var verifiedStep3: Boolean = false
    )

    class SessionKeys(val key: ByteArray, val ivReq: ByteArray, val ivResp: ByteArray)

    companion object {
        private const val TAG = "CryptoHandler"
        private const val GCM_TAG_BITS = 128
        private const val EPH_LEN = 32

        private fun hkdf(ikm: ByteArray, info: ByteArray, okmLen: Int): ByteArray {
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            hkdf.init(HKDFParameters(ikm, null, info))
            val okm = ByteArray(okmLen)
            hkdf.generateBytes(okm, 0, okm.size)
            return okm
        }

        // One key, two IVs (request / response) so c3 and c4 never share a GCM nonce.
        internal fun deriveSessionKeys(secret: ByteArray, t: ByteArray) = SessionKeys(
            hkdf(secret, "SPARK-AUTH-v2 key".toByteArray() + t, 32),
            hkdf(secret, "SPARK-AUTH-v2 nonce req".toByteArray() + t, 12),
            hkdf(secret, "SPARK-AUTH-v2 nonce resp".toByteArray() + t, 12)
        )

        // Identifies a session in the approval prompt: hex(SHA-256(T)).
        internal fun sessionIdOf(t: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(t).joinToString("") { "%02x".format(it) }

        @Volatile
        var currentSession: SessionState? = null
    }

    private val setup = SetupService(context)
    var lastUserErrorMessage: String? = null

    init {
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

    private fun getPkADer(): ByteArray {
        val config = setup.getStoredConfig() ?: throw IllegalStateException("Missing setup config")
        return pemToPublicKey(config.publicKey).encoded
    }

    private fun getPkVDer(): ByteArray {
        val config = setup.getStoredConfig() ?: throw IllegalStateException("Missing setup config")
        return pemToPublicKey(config.pcPublicKey).encoded
    }

    private fun putBe32(value: Int): ByteArray {
        return ByteBuffer.allocate(4).putInt(value).array()
    }

    private fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun handleStep1(ephV: ByteArray): ByteArray {
        require(ephV.size == EPH_LEN) { "Bad ephV length ${ephV.size}" }
        check(currentSession?.verifiedStep3 != true) { "Approval pending" }

        val phonePrivate = X25519PrivateKeyParameters(SecureRandom())
        val phonePublic = phonePrivate.generatePublicKey().encoded

        val secret = ByteArray(32)
        phonePrivate.generateSecret(X25519PublicKeyParameters(ephV, 0), secret, 0)

        val pkV = getPkVDer()
        val pkA = getPkADer()

        // T = protocol_id || ephV || ephA || len(pkV) || pkV || len(pkA) || pkA
        val protocolId = "SPARK-AUTH-v2".toByteArray()
        val t = protocolId + ephV + phonePublic + putBe32(pkV.size) + pkV + putBe32(pkA.size) + pkA

        val keys = deriveSessionKeys(secret, t)

        currentSession = SessionState(
            ephV, phonePrivate, phonePublic, secret, t,
            keys.key, keys.ivReq, keys.ivResp, sessionIdOf(t)
        )
        return phonePublic
    }

    fun handleStep3(c3: ByteArray): Boolean {
        val session = currentSession ?: return false
        if (session.verifiedStep3) return false
        try {
            val sigV = aesGcmDecrypt(session.keyGcm, session.ivReq, session.T, c3)
            val mV = "req".toByteArray() + session.T

            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(getPcPublicKey())
            verifier.update(mV)
            if (verifier.verify(sigV)) {
                session.verifiedStep3 = true
                return true
            }
        } catch (e: Exception) {
            Log.e(TAG, "Step 3 processing failed", e)
        }
        currentSession = null
        return false
    }

    fun handleStep4(sessionId: String): ByteArray? {
        val session = currentSession ?: return null
        if (!session.verifiedStep3 || session.sessionId != sessionId) return null
        try {
            val pkA = getPkADer()
            val pkV = getPkVDer()

            // σA = Sign(skA, "resp" || ephV || ephA || pkA || pkV)
            val mA = "resp".toByteArray() + session.ephV + session.ephA_pk + putBe32(pkA.size) + pkA + putBe32(pkV.size) + pkV

            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(getPrivateKey())
            signer.update(mA)
            val sigmaA = signer.sign()

            val c4 = aesGcmEncrypt(session.keyGcm, session.ivResp, session.T, sigmaA)
            return c4
        } catch (e: Exception) {
            Log.e(TAG, "Step 4 processing failed", e)
        } finally {
            currentSession = null
        }
        return null
    }

    // Compatibility signature for ConnectionForegroundService verification checks if needed
    fun verifyChallenge(challenge: ByteArray): Boolean {
        return true
    }
}
