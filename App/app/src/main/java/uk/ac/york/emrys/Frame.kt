package uk.ac.york.emrys

sealed class FrameCodecException(message: String) : IllegalArgumentException(message) {
    class FrameTooSmall : FrameCodecException("Frame is too small")
    class InvalidMagicBits : FrameCodecException("Invalid magic bits")
    class VersionMismatch : FrameCodecException("Version mismatch")
    class OutputTooSmall : FrameCodecException("Output buffer is too small")
    class PayloadTooBig : FrameCodecException("Payload is too big")
    class InvalidMessageType : FrameCodecException("Invalid message type")
    class PayloadLengthMismatch : FrameCodecException("Payload length does not match payload data")
}

class Frame {
    companion object {
        private const val FRAME_HEADER_LEN = 12
        private const val FRAME_MAGIC0: Byte = 0x53  // 'S'
        private const val FRAME_MAGIC1: Byte = 0x50  // 'P'
        private const val FRAME_VERSION: Byte = 0x01

        private fun putU32Be(dst: ByteArray, offset: Int, value: UInt) {
            dst[offset] = ((value shr 24) and 0xFFu).toByte()
            dst[offset + 1] = ((value shr 16) and 0xFFu).toByte()
            dst[offset + 2] = ((value shr 8) and 0xFFu).toByte()
            dst[offset + 3] = (value and 0xFFu).toByte()
        }

        private fun getU32Be(src: ByteArray, offset: Int): UInt {
            return ((src[offset].toUInt() and 0xFFu) shl 24) or
                    ((src[offset + 1].toUInt() and 0xFFu) shl 16) or
                    ((src[offset + 2].toUInt() and 0xFFu) shl 8) or
                    (src[offset + 3].toUInt() and 0xFFu)
        }

        private fun UInt.toIntOrThrow() =
            if (this <= Int.MAX_VALUE.toUInt()) toInt() else throw FrameCodecException.PayloadTooBig()
    }

    fun frameEncoder(message: Message, outputCapacity: Int = Int.MAX_VALUE): ByteArray {
        val payloadLength = message.payloadLen.toIntOrThrow()
        if (payloadLength > message.payload.size) {
            throw FrameCodecException.PayloadLengthMismatch()
        }

        val frameLength = FRAME_HEADER_LEN + payloadLength
        if (outputCapacity < frameLength) {
            throw FrameCodecException.OutputTooSmall()
        }

        val frame = ByteArray(frameLength)
        frame[0] = FRAME_MAGIC0
        frame[1] = FRAME_MAGIC1
        frame[2] = FRAME_VERSION
        frame[3] = message.type.value
        putU32Be(frame, 4, message.seq)
        putU32Be(frame, 8, message.payloadLen)

        if (payloadLength > 0) {
            System.arraycopy(message.payload, 0, frame, FRAME_HEADER_LEN, payloadLength)
        }

        return frame
    }

    fun frameDecoder(frame: ByteArray, payloadCapacity: Int = Int.MAX_VALUE): Message {
        if (frame.size < FRAME_HEADER_LEN) throw FrameCodecException.FrameTooSmall()
        if (frame[0] != FRAME_MAGIC0 || frame[1] != FRAME_MAGIC1) {
            throw FrameCodecException.InvalidMagicBits()
        }
        if (frame[2] != FRAME_VERSION) throw FrameCodecException.VersionMismatch()

        val type = MsgType.fromByte(frame[3])
            ?: throw FrameCodecException.InvalidMessageType()

        val seq = getU32Be(frame, 4)
        val payloadLen = getU32Be(frame, 8)
        val payloadLenInt = payloadLen.toIntOrThrow()

        if (payloadLenInt > frame.size - FRAME_HEADER_LEN) {
            throw FrameCodecException.OutputTooSmall()
        }
        if (payloadLenInt > payloadCapacity) {
            throw FrameCodecException.PayloadTooBig()
        }

        val payload = frame.copyOfRange(FRAME_HEADER_LEN, FRAME_HEADER_LEN + payloadLenInt)

        return Message(type, seq, payload, payloadLen)
    }
}
