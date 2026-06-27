package uk.ac.york.emrys

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class FrameTest {
    private val frameCodec = Frame()

    @Test
    fun testEncodeDecode() {
        val payload = "Hello, SPARK!".toByteArray()
        val originalMessage = Message(
            type = MsgType.MSG_PING,
            seq = 1234u,
            payload = payload,
            payloadLen = payload.size.toUInt()
        )

        val encoded = frameCodec.frameEncoder(originalMessage)
        val decoded = frameCodec.frameDecoder(encoded)

        assertEquals(originalMessage.type, decoded.type)
        assertEquals(originalMessage.seq, decoded.seq)
        assertEquals(originalMessage.payloadLen, decoded.payloadLen)
        assertArrayEquals(originalMessage.payload, decoded.payload)
    }

    @Test
    fun testEncodeEmptyPayload() {
        val originalMessage = Message(
            type = MsgType.MSG_ABORT,
            seq = 0u,
            payload = ByteArray(0),
            payloadLen = 0u
        )

        val encoded = frameCodec.frameEncoder(originalMessage)
        val decoded = frameCodec.frameDecoder(encoded)

        assertEquals(12, encoded.size) // Header only
        assertEquals(originalMessage.type, decoded.type)
        assertEquals(0u, decoded.payloadLen)
        assertEquals(0, decoded.payload.size)
    }

    @Test
    fun testDecodeInvalidMagic() {
        val invalidFrame = ByteArray(12) { 0 }
        assertThrows(FrameCodecException.InvalidMagicBits::class.java) {
            frameCodec.frameDecoder(invalidFrame)
        }
    }

    @Test
    fun testDecodeFrameTooSmall() {
        val smallFrame = ByteArray(11)
        assertThrows(FrameCodecException.FrameTooSmall::class.java) {
            frameCodec.frameDecoder(smallFrame)
        }
    }

    @Test
    fun testDecodeVersionMismatch() {
        val frame = ByteArray(12)
        frame[0] = 0x53 // 'S'
        frame[1] = 0x50 // 'P'
        frame[2] = 0x02 // Wrong version
        assertThrows(FrameCodecException.VersionMismatch::class.java) {
            frameCodec.frameDecoder(frame)
        }
    }

    @Test
    fun testEncodeOutputTooSmall() {
        val message = Message(MsgType.MSG_PING, 1u, "test".toByteArray())
        assertThrows(FrameCodecException.OutputTooSmall::class.java) {
            frameCodec.frameEncoder(message, outputCapacity = 10)
        }
    }

    @Test
    fun testDecodePayloadTooBig() {
        val message = Message(MsgType.MSG_PING, 1u, "test".toByteArray())
        val encoded = frameCodec.frameEncoder(message)
        assertThrows(FrameCodecException.PayloadTooBig::class.java) {
            frameCodec.frameDecoder(encoded, payloadCapacity = 2)
        }
    }

    @Test
    fun decodesCVector() {
        // exact bytes emitted by frame.c: CHALLENGE, seq=0x01020304, payload "hi"
        val hex = "5350010501020304000000026869"
        val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val m = Frame().frameDecoder(bytes)
        assertEquals(MsgType.MSG_CHALLENGE, m.type)
        assertEquals(0x01020304u, m.seq)
        assertArrayEquals(byteArrayOf(0x68, 0x69), m.payload)
    }
}
