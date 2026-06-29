package uk.ac.york.emrys;

import android.util.Log
import java.util.Timer
import kotlin.concurrent.scheduleAtFixedRate

fun interface OnMessage { fun onMessage(m: Message) }

class Channel(private val conn: ByteTransport, private val listener: OnMessage) {
    private var seq = 0
    private val pinger = Timer()

    init {
        conn.onBytes = { raw -> handle(raw) }
        pinger.scheduleAtFixedRate(0L, 5000L) {
            send(MsgType.MSG_PING, ByteArray(0))
        }
    }

    private fun handle(raw: ByteArray) {
        val m = try {
            Frame().frameDecoder(raw)
        }
        catch (e: Exception) {
            Log.w("Channel", "Failed to decode frame: ${e.message}")
            return
        }
        if (m.type == MsgType.MSG_PING) {
            Log.d("Channel", "Received PING message")
            return
        }
        listener.onMessage(m)
    }

    fun send(type: MsgType, payload: ByteArray): Boolean =
        conn.sendBytes(Frame().frameEncoder(Message(type, seq++.toUInt(), payload)))

    fun close() = pinger.cancel()
}