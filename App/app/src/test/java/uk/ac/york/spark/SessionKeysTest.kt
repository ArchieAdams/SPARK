package uk.ac.york.spark

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class SessionKeysTest {
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test
    fun derivationMatchesFixedVector() {
        val secret = ByteArray(32) { it.toByte() }
        val t = "SPARK-AUTH-v2-test-transcript".toByteArray()
        val k = CryptoMessageHandler.deriveSessionKeys(secret, t)
        assertEquals("ca4e4ee73b127e36bd95ad6ed8e0be61ce0d562dba598a9c3585771f10c683b9", k.key.hex())
        assertEquals("e46e025fd6e05368ef8ea3ea", k.ivReq.hex())
        assertEquals("c728509f567da7c1ee1ed86c", k.ivResp.hex())
        assertNotEquals(k.ivReq.hex(), k.ivResp.hex())
    }

    @Test
    fun sessionIdIsSha256HexOfTranscript() {
        val id = CryptoMessageHandler.sessionIdOf("abc".toByteArray())
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", id)
    }
}
