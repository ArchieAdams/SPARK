package uk.ac.york.emrys

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class MessagesTest {

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test fun setupReqRoundTrip() {
        val id = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val pkA = ByteArray(8) { (it + 1).toByte() }   // stand-in DER
        val p = Messages.setupReq(id, pkA, port = 8080)
        val out = Messages.parseSetupReq(p)
        assertEquals(id, out.deviceId)
        assertEquals(8080, out.port)
        assertArrayEquals(pkA, out.pkA)
        println("VECTOR SETUP_REQ = ${p.hex()}")
    }

    @Test fun commitRoundTrip() {
        val pkV = ByteArray(6) { (0x10 + it).toByte() }
        val c = ByteArray(32) { it.toByte() }
        val out = Messages.parseCommit(Messages.commit(pkV, c))
        assertArrayEquals(pkV, out.pkV)
        assertArrayEquals(c, out.c)
        println("VECTOR COMMIT = ${Messages.commit(pkV, c).hex()}")
    }

    @Test fun revealRoundTrip() {
        val n = ByteArray(32) { it.toByte() }
        val r = ByteArray(32) { (32 + it).toByte() }
        val out = Messages.parseReveal(Messages.reveal(n, r))
        assertArrayEquals(n, out.n)
        assertArrayEquals(r, out.r)
        println("VECTOR REVEAL = ${Messages.reveal(n, r).hex()}")
    }

    @Test fun sasConfirmRoundTrip() {
        assertTrue(Messages.parseSasConfirm(Messages.sasConfirm(true)))
        assertEquals(false, Messages.parseSasConfirm(Messages.sasConfirm(false)))
    }

    @Test fun abortRoundTrip() {
        AbortReason.entries.forEach {
            assertEquals(it, Messages.parseAbort(Messages.abort(it)))
        }
    }

    @Test fun sasVector() {
        val n = ByteArray(32) { it.toByte() }
        val pkV = byteArrayOf(0x10, 0x11, 0x12, 0x13, 0x14, 0x15)
        val pkA = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        println("VECTOR SAS = ${Messages.sas(n, pkV, pkA)}")
    }

    @Test fun revealRejectsWrongSize() {
        assertThrows(IllegalArgumentException::class.java) {
            Messages.reveal(ByteArray(31), ByteArray(32))
        }
    }

    @Test fun parserRejectsTruncatedInput() {
        // valid SETUP_REQ then chop a byte -> reader must throw, not read past the buffer
        val full = Messages.setupReq(UUID.randomUUID(), ByteArray(4) { 1 }, 1)
        assertThrows(IllegalArgumentException::class.java) {
            Messages.parseSetupReq(full.copyOf(full.size - 1))
        }
    }
}
