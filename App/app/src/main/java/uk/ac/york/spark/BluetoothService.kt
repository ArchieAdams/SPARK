package uk.ac.york.spark

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
    private val adapter: BluetoothAdapter,
    private val connectionListener: ConnectionListener? = null,
    private val serviceUuid: UUID
) : ConnectionService() {

    companion object {
        private const val TAG = "BluetoothService"
        private const val NAME = "SparkAuth"
        private const val MAX_FRAME_SIZE = 1024 * 1024

        private val serverLock = Any()
        @Volatile private var serverSocket: BluetoothServerSocket? = null
        @Volatile private var acceptRunning = false
        @Volatile private var activeInstance: BluetoothService? = null

        private fun ensureServerSocket(adapter: BluetoothAdapter, serviceUuid: UUID): Boolean =
            synchronized(serverLock) {
                if (serverSocket != null) return true
                serverSocket = try {
                    @Suppress("MissingPermission")
                    adapter.listenUsingRfcommWithServiceRecord(NAME, serviceUuid)
                } catch (e: IOException) {
                    Log.e(TAG, "Failed to open server socket", e)
                    return false
                }
                acceptRunning = true
                thread(name = "bt-accept") {
                    try {
                        while (acceptRunning) {
                            val socket = serverSocket?.accept() ?: break   // blocks until a phone connects
                            val target = activeInstance
                            if (target != null) target.handleConnection(socket)
                            else try { socket.close() } catch (e: IOException) {}
                        }
                    } catch (e: IOException) {
                        if (acceptRunning) Log.e(TAG, "Accept loop error", e)
                    }
                }
                true
            }
    }

    private val socketLock = Any()
    private var currentSocket: BluetoothSocket? = null
    @Volatile private var isRunning = false

    override fun connect() {
        if (isRunning) return
        isRunning = true
        activeInstance = this
        if (!ensureServerSocket(adapter, serviceUuid)) {
            isRunning = false
            activeInstance = null
        }
    }

    private fun handleConnection(socket: BluetoothSocket) {
        synchronized(socketLock) { closeCurrentSocket(); currentSocket = socket }
        setConnected(true)
        connectionListener?.onConnected(this)

        thread(name = "bt-read") {
            val input = DataInputStream(BufferedInputStream(socket.inputStream))
            try {
                while (isConnected()) {
                    val bytes = readFrame(input) ?: break
                    onBytes?.invoke(bytes)
                }
            } catch (e: Exception) {
                if (isConnected()) Log.e(TAG, "Read error", e)
            } finally {
                setConnected(false)
                connectionListener?.onDisconnected(this)
                closeCurrentSocket()
            }
        }
    }

    override fun sendBytes(data: ByteArray): Boolean {
        val socket = synchronized(socketLock) { currentSocket }
        if (socket == null || !isConnected()) return false
        return try {
            val out = DataOutputStream(BufferedOutputStream(socket.outputStream))
            writeFrame(out, data)
            true
        } catch (e: IOException) {
            Log.e(TAG, "Send failed", e)
            setConnected(false)
            connectionListener?.onDisconnected(this)
            closeCurrentSocket()
            false
        }
    }

    override fun disconnect() {
        isRunning = false
        setConnected(false)
        if (activeInstance === this) activeInstance = null
        closeCurrentSocket()
    }

    private fun writeFrame(out: DataOutputStream, payload: ByteArray) {
        out.writeInt(payload.size)   // 4-byte length so the reader knows where the message ends
        out.write(payload)
        out.flush()
    }

    private fun readFrame(input: DataInputStream): ByteArray? = try {
        val len = input.readInt()
        if (len <= 0 || len > MAX_FRAME_SIZE) null
        else ByteArray(len).also { input.readFully(it) }
    } catch (e: EOFException) { null }


    private fun closeCurrentSocket() = synchronized(socketLock) {
        try { currentSocket?.close() } catch (e: IOException) {}
        currentSocket = null
    }
}
