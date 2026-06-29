package uk.ac.york.emrys

abstract class ConnectionService : ByteTransport {
    private var isConnected: Boolean = false
    override var onBytes: ((ByteArray) -> Unit)? = null
    abstract override fun sendBytes(data: ByteArray): Boolean
    abstract fun connect()
    abstract fun disconnect()
    fun setConnected(connected: Boolean) {
        isConnected = connected
    }
    open fun isConnected()= isConnected
    open fun shutdown() = disconnect()
}