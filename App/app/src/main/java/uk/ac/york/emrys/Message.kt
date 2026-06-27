package uk.ac.york.emrys

class Message(
    val type: MsgType,
    val seq: UInt,
    val payload: ByteArray = ByteArray(0),
    val payloadLen: UInt = payload.size.toUInt(),
)

enum class MsgType(val value: Byte) {
    MSG_SETUP_REQ(0x01.toByte()),
    MSG_COMMIT(0x02.toByte()),
    MSG_REVEAL(0x03.toByte()),
    MSG_SAS_CONFIRM(0x04.toByte()),
    MSG_CHALLENGE(0x05.toByte()),
    MSG_RESPONSE(0x06.toByte()),
    MSG_PING(0x07.toByte()),
    MSG_ABORT(0x08.toByte());

    companion object {
        fun fromByte(value: Byte): MsgType? = entries.find { it.value == value }
    }
}
