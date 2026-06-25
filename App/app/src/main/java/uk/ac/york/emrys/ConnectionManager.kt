package uk.ac.york.emrys

import android.bluetooth.BluetoothAdapter
import android.util.Log
import java.util.UUID

class ConnectionManager(private val connectionListener: ConnectionListener, private val setupConfig: SetupService.SetupConfig? = null) : ConnectionListener {
    private var currentConnection: ConnectionService? = null
    private val connections = mutableListOf<ConnectionService>()

    fun startConnection(adapter: BluetoothAdapter, messageListener: MessageListener) {
        val serviceUUID = setupConfig?.deviceId?.let { deviceId ->
            try {
                Log.d("ConnectionManager", "Parsing Bluetooth UUID from deviceId: $deviceId")
                UUID.fromString(deviceId)
            } catch (e: Exception) {
                Log.e("ConnectionManager", "Invalid Bluetooth UUID in deviceId: $deviceId", e)
                null
            }
        } ?: run {
            Log.e("ConnectionManager", "Missing Bluetooth UUID; Bluetooth service will not start")
            null
        }

        if (serviceUUID != null) {
            val bluetoothService = BluetoothService(adapter, this, messageListener, serviceUUID)
            bluetoothService.let {
                connections.add(it)
                it.connect()
            }
        }

        val webSocketService = WebSocketService(this, messageListener, setupConfig)
        webSocketService.let {
            connections.add(it)
            it.connect()
        }
    }

    override fun onConnected(connectionService: ConnectionService) {
        setCurrentConnection(connectionService)
        connectionListener.onConnected(connectionService)
    }

    private fun setCurrentConnection(connectionService: ConnectionService) {
        Log.d("ConnectionManager", "Setting current connection: ${connectionService.javaClass.simpleName}")
        currentConnection = connectionService
        connections
            .filter { it != connectionService }
            .forEach { it.disconnect() }
    }

    private fun restartConnections() {
        currentConnection = null
        for (connection in connections) {
            connection.connect()
        }
    }

    override fun onDisconnected(connectionService: ConnectionService) {
        Log.d("ConnectionManager", "Disconnected: ${connectionService.javaClass.simpleName}")
        connectionListener.onDisconnected(connectionService)
        if (currentConnection == connectionService) {
            restartConnections()
        }
    }

    fun sendMessage(message: String) {
        currentConnection?.sendMessage(message) ?: run {
            Log.w("ConnectionManager", "Cannot send message - no active connection")
        }
    }

    fun destroy() {
        Log.d("ConnectionManager", "Destroying ConnectionManager")
        // First disconnect all connections
        for (connection in connections) {
            try {
                connection.disconnect()
            } catch (e: Exception) {
                Log.e("ConnectionManager", "Error disconnecting ${connection.javaClass.simpleName}", e)
            }
        }
        // Then shutdown resources
        for (connection in connections) {
            try {
                connection.shutdown()
            } catch (e: Exception) {
                Log.e("ConnectionManager", "Error shutting down ${connection.javaClass.simpleName}", e)
            }
        }
        connections.clear()
        currentConnection = null
        Log.d("ConnectionManager", "ConnectionManager destroyed")
    }

}