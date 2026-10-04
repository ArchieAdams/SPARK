package uk.ac.york.spark

// Pure ordering rules for the pairing handshake; each call returns false if the event is not allowed now.
class PairingFlow {
    enum class State { AWAIT_COMMIT, AWAIT_REVEAL, AWAIT_CONFIRM, DONE }

    var state = State.AWAIT_COMMIT
        private set
    private var peerConfirmed = false
    private var userConfirmed = false

    fun onCommit(): Boolean {
        if (state != State.AWAIT_COMMIT) return false
        state = State.AWAIT_REVEAL
        return true
    }

    fun onReveal(): Boolean {
        if (state != State.AWAIT_REVEAL) return false
        state = State.AWAIT_CONFIRM
        return true
    }

    // The PC may confirm before or after the user taps, but only once the SAS exists.
    fun onPeerConfirm(): Boolean {
        if (state != State.AWAIT_CONFIRM || peerConfirmed) return false
        peerConfirmed = true
        return true
    }

    fun onUserConfirm(): Boolean {
        if (state != State.AWAIT_CONFIRM || userConfirmed) return false
        userConfirmed = true
        return true
    }

    fun finish() {
        state = State.DONE
    }
}
