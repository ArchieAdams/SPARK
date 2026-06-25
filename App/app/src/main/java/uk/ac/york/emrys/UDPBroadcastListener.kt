package uk.ac.york.emrys

import android.util.Log
import java.net.*
import kotlin.concurrent.thread

class UDPBroadcastListener(
    private val onServerDiscovered: ((String) -> Unit)? = null,
    private val broadcastPort: Int? = null
) {


    companion object {
        private const val TAG = "UDPBroadcastListener"
        private const val DEFAULT_BROADCAST_PORT = 5555
        private const val AUTHAPP_FIND_MESSAGE = "AUTHAPP_FIND"
    }

    private val BROADCAST_PORT: Int = broadcastPort ?: DEFAULT_BROADCAST_PORT

    private var udpListener: Thread? = null

    private var isListening: Boolean = false
    private var socket: DatagramSocket? = null

    private fun readPacket(buffer: ByteArray) {
        try {
            val packet = DatagramPacket(buffer, buffer.size)
            socket?.receive(packet)

            extractIp(packet)
        } catch (_: SocketTimeoutException) {
            // Timeout is expected, continue listening
        } catch (e: SocketException) {
            // Socket closed - this is expected when stopListener is called
            if (isListening) {
                Log.e(TAG, "Socket error while listening", e)
            }
        } catch (e: Exception) {
            if (isListening) {
                Log.e(TAG, "Error receiving UDP packet", e)
            }
        }
    }

    private fun extractIp(packet: DatagramPacket) {
        val message = String(packet.data, 0, packet.length).trim()
        val serverIp = packet.address.toString()
        Log.d(TAG, "Received broadcast message: $message from $serverIp")

        // Check if it's the AUTHAPP_FIND message
        if (message.equals(AUTHAPP_FIND_MESSAGE, ignoreCase = true)) {
            onServerDiscovered?.invoke(serverIp)
        }
    }

    fun startUdpListener() {
        if (isListening) {
            Log.w(TAG, "UDP Listener already running, stopping old instance")
            stopListener()
            Thread.sleep(500) // Wait for socket to close
        }

        isListening = true
        udpListener = thread {
            try {
                // Close any existing socket first
                try {
                    socket?.close()
                } catch (e: Exception) {
                    Log.d(TAG, "Closed stale socket", e)
                }
                socket = null

                // Create a new UDP socket on the broadcast port
                socket = DatagramSocket(null).apply {
                    reuseAddress = true  // Allow reuse of the port
                    broadcast = true
                    soTimeout = 2000  // Timeout to allow checking isListening flag
                    bind(InetSocketAddress(BROADCAST_PORT))
                }
                Log.d(TAG, "UDP Listener started on port $BROADCAST_PORT")

                val buffer = ByteArray(1024)

                while (isListening) {
                    readPacket(buffer)
                }
            } catch (e: Exception) {
                if (isListening) {
                    Log.e(TAG, "UDP Listener error", e)
                }
            } finally {
                try {
                    socket?.close()
                } catch (e: Exception) {
                    Log.d(TAG, "Error closing socket", e)
                }
                socket = null
                Log.d(TAG, "UDP Listener stopped")
            }
        }
    }

    fun stopListener() {
        isListening = false
        try {
            socket?.close()
        } catch (e: Exception) {
            Log.d(TAG, "Error closing socket", e)
        }
        socket = null
        udpListener?.interrupt()
        udpListener = null
    }
}
