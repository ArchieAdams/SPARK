package uk.ac.york.spark

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingFlowTest {
    private fun atConfirm() = PairingFlow().apply { onCommit(); onReveal() }

    @Test
    fun happyPathUserFirst() {
        val f = PairingFlow()
        assertTrue(f.onCommit())
        assertTrue(f.onReveal())
        assertTrue(f.onUserConfirm())
        assertTrue(f.onPeerConfirm())
    }

    @Test
    fun happyPathPeerFirst() {
        val f = atConfirm()
        assertTrue(f.onPeerConfirm())
        assertTrue(f.onUserConfirm())
    }

    @Test
    fun revealBeforeCommitRejected() = assertFalse(PairingFlow().onReveal())

    @Test
    fun duplicateCommitRejected() {
        val f = PairingFlow()
        assertTrue(f.onCommit())
        assertFalse(f.onCommit())
    }

    @Test
    fun duplicateRevealRejected() {
        val f = atConfirm()
        assertFalse(f.onReveal())
    }

    @Test
    fun commitAfterRevealRejected() = assertFalse(atConfirm().onCommit())

    @Test
    fun confirmsBeforeSasRejected() {
        val f = PairingFlow()
        assertFalse(f.onPeerConfirm())
        assertFalse(f.onUserConfirm())
        f.onCommit()
        assertFalse(f.onPeerConfirm())
        assertFalse(f.onUserConfirm())
    }

    @Test
    fun duplicateConfirmsRejected() {
        val f = atConfirm()
        assertTrue(f.onPeerConfirm())
        assertFalse(f.onPeerConfirm())
        assertTrue(f.onUserConfirm())
        assertFalse(f.onUserConfirm())
    }

    @Test
    fun nothingAllowedAfterFinish() {
        val f = atConfirm()
        f.finish()
        assertEquals(PairingFlow.State.DONE, f.state)
        assertFalse(f.onPeerConfirm())
        assertFalse(f.onUserConfirm())
    }
}
