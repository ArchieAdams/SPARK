package uk.ac.york.emrys

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.util.UUID
import kotlin.concurrent.thread

class BluetoothService(
    adapter: BluetoothAdapter,
    private val connectionListener: ConnectionListener? = null,
    private val messageListener: MessageListener? = null,
    private val serviceUuid: UUID
) : ConnectionService() {

    companion object {
        private const val TAG = "BluetoothService"
        private const val NAME = "EmrysAuth"
        private const val HEARTBEAT_MS = 5000L
        private const val MAX_FRAME_SIZE = 1024 * 1024
    }

    private val adapterRef = adapter
    private val socketLock = Any()
    private var serverSocket: BluetoothServerSocket? = null
    private var currentSocket: BluetoothSocket? = null

    private var acceptThread: Thread? = null

    @Volatile
    private var isRunning = false

    private fun createServerSocket(): BluetoothServerSocket? {
        return try {
            @Suppress("MissingPermission")
            adapterRef.listenUsingRfcommWithServiceRecord(NAME, serviceUuid)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to create RFCOMM server socket", e)
            null
        }
    }

    override fun connect() {
        if (isRunning) return
        isRunning = true

        serverSocket = createServerSocket() ?: return

        acceptThread = thread(name = "bt-accept") {
            try {
                while (isRunning) {
                    val socket = serverSocket?.accept() ?: break
                    handleConnection(socket)
                }
            } catch (e: IOException) {
                if (isRunning) Log.e(TAG, "Accept loop error", e)
            } finally {
                isRunning = false
            }
        }
    }

    private fun handleConnection(socket: BluetoothSocket) {
        synchronized(socketLock) {
            closeCurrentSocket()
            currentSocket = socket
        }

        setConnected(true)
        connectionListener?.onConnected(this)

        thread(name = "bt-read") {
            val input = DataInputStream(BufferedInputStream(socket.inputStream))
            try {
                while (isConnected()) {
                    val message = readFramedMessage(input) ?: break
                    if (message != "PING" && message != "PONG") {
                        messageListener?.onMessage(message)
                    }
                }
            } catch (e: Exception) {
                if (isConnected()) Log.e(TAG, "Read error", e)
            } finally {
                setConnected(false)
                connectionListener?.onDisconnected(this)
                closeCurrentSocket()
            }
        }

        thread(name = "bt-ping") {
            val output = DataOutputStream(BufferedOutputStream(socket.outputStream))
            try {
                while (isConnected()) {
                    Thread.sleep(HEARTBEAT_MS)
                    writeFramedMessage(output, "PING")
                }
            } catch (e: Exception) {
                // Connection likely closed
            }
        }
    }

    override fun sendMessage(msg: String) {
        val socket = synchronized(socketLock) { currentSocket }
        if (socket == null || !isConnected()) return

        thread {
            try {
                val output = DataOutputStream(BufferedOutputStream(socket.outputStream))
                writeFramedMessage(output, msg)
            } catch (e: IOException) {
                setConnected(false)
                connectionListener?.onDisconnected(this)
                closeCurrentSocket()
            }
        }
    }

    override fun disconnect() {
        isRunning = false
        setConnected(false)
        closeServerSocket()
        closeCurrentSocket()
    }

    override fun shutdown() {
        disconnect()
    }

    private fun closeCurrentSocket() {
        synchronized(socketLock) {
            try {
                currentSocket?.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing client socket", e)
            }
            currentSocket = null
        }
    }

    private fun closeServerSocket() {
        try {
            serverSocket?.close()
        } catch (e: IOException) {
            Log.e(TAG, "Error closing server socket", e)
        }
        serverSocket = null
    }

    private fun writeFramedMessage(output: DataOutputStream, msg: String) {
        val payload = msg.toByteArray(Charsets.UTF_8)
        output.writeInt(payload.size)
        output.write(payload)
        output.flush()
    }

    private fun readFramedMessage(input: DataInputStream): String? {
        return try {
            val length = input.readInt()
            if (length <= 0 || length > MAX_FRAME_SIZE) return null
            val payload = ByteArray(length)
            input.readFully(payload)
            payload.toString(Charsets.UTF_8)
        } catch (e: EOFException) {
            null
        }
    }
}
