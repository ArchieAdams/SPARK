package uk.ac.york.emrys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.StringWriter
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security

object KeyManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TAG = "KeyManager"

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun generateOrGetKeystorePublicKey(alias: String): PublicKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        ks.getCertificate(alias)?.let {
            return it.publicKey
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(3072)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .build()

        kpg.initialize(spec)
        return kpg.generateKeyPair().public
    }

    fun getPrivateKey(alias: String): PrivateKey? {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            ks.getKey(alias, null) as? PrivateKey
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve private key: $alias", e)
            null
        }
    }

    fun publicKeyToPEM(publicKey: PublicKey): String {
        val writer = StringWriter()
        JcaPEMWriter(writer).use { it.writeObject(publicKey) }
        return writer.toString()
    }

    fun deleteAlias(alias: String) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting alias: $alias", e)
        }
    }
}
