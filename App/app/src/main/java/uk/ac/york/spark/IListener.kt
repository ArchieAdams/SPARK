package uk.ac.york.spark


interface MessageListener {
    fun onMessage(msg: String)
    fun onError(error: String)
}

interface ConnectionListener {
    fun onConnected(connectionService: ConnectionService)
    fun onDisconnected(connectionService: ConnectionService)
}
