package uk.ac.york.emrys

abstract class ConnectionService {
    private var isConnected: Boolean = false

    abstract fun sendMessage(msg: String)
    abstract fun disconnect()
    abstract fun connect()
    fun setConnected(connected: Boolean) {
        isConnected = connected
    }
    open fun isConnected()= isConnected

    open fun shutdown() {
        disconnect()
    }
}