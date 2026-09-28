package uk.ac.york.spark

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID


class PayloadWriter {
    private val out = java.io.ByteArrayOutputStream()
    fun bytes(b: ByteArray) = apply { out.write(b) }
    fun int(v: Int) = apply { out.write(ByteBuffer.allocate(4).putInt(v).array()) }
    fun lenBytes(b: ByteArray) = apply { int(b.size); out.write(b) }
    fun build(): ByteArray = out.toByteArray()
}

class PayloadReader(private val buf: ByteArray) {
    private var pos = 0
    fun bytes(n: Int): ByteArray {
        require(n >= 0 && pos + n <= buf.size) { "payload underrun: need $n at $pos of ${buf.size}" }
        return buf.copyOfRange(pos, pos + n).also { pos += n }
    }
    fun int(): Int {
        require(pos + 4 <= buf.size) { "payload underrun reading int at $pos of ${buf.size}" }
        return ByteBuffer.wrap(buf, pos, 4).int.also { pos += 4 }
    }
    fun lenBytes(): ByteArray = bytes(int())
    fun remaining(): Int = buf.size - pos
}

fun UUID.toBytes16(): ByteArray =
    ByteBuffer.allocate(16).putLong(mostSignificantBits).putLong(leastSignificantBits).array()

fun bytesToUuid(b: ByteArray): UUID = ByteBuffer.wrap(b).let { UUID(it.long, it.long) }


object Messages {
    const val X25519_PUBLIC_KEY_BYTES = 32
    const val AUTH_NONCE_BYTES = 32
    const val NONCE = 32
    const val R = 32
    const val COMMIT_HASH = 32  // SHA-256


    // SETUP_REQ (A->V): deviceId[16] ‖ port[4]
    fun setupReq(deviceId: UUID, port: Int): ByteArray =
        PayloadWriter().bytes(deviceId.toBytes16()).int(port).build()

    data class SetupReq(val deviceId: UUID, val port: Int)

    fun parseSetupReq(p: ByteArray): SetupReq = PayloadReader(p).let {
        SetupReq(bytesToUuid(it.bytes(16)), it.int())
    }

    // COMMIT (V->A): len(pkV) ‖ pkV(DER) ‖ c[32]   (c = SHA-256(N‖r))
    fun commit(pkV: ByteArray, c: ByteArray): ByteArray =
        PayloadWriter().lenBytes(pkV).bytes(c).build()

    data class Commit(val pkV: ByteArray, val c: ByteArray)

    fun parseCommit(p: ByteArray): Commit = PayloadReader(p).let {
        Commit(it.lenBytes(), it.bytes(COMMIT_HASH))
    }

    // SAS_NONCE (A->V): len(pkA) ‖ pkA(DER) ‖ nA[32]
    fun sasNonce(pkA: ByteArray, nA: ByteArray): ByteArray =
        PayloadWriter().lenBytes(pkA).bytes(nA).build()

    data class SasNonce(val pkA: ByteArray, val nA: ByteArray)

    fun parseSasNonce(p: ByteArray): SasNonce = PayloadReader(p).let {
        SasNonce(it.lenBytes(), it.bytes(NONCE))
    }

    // REVEAL (V->A): nV[32] ‖ r[32]
    fun reveal(nV: ByteArray, r: ByteArray): ByteArray {
        require(nV.size == NONCE && r.size == R) { "reveal: nV and r must be $NONCE/$R bytes" }
        return PayloadWriter().bytes(nV).bytes(r).build()
    }

    data class Reveal(val nV: ByteArray, val r: ByteArray)

    fun parseReveal(p: ByteArray): Reveal = PayloadReader(p).let {
        Reveal(it.bytes(NONCE), it.bytes(R))
    }

    // SAS_CONFIRM (both): result[1]  (1 = accept, 0 = reject)
    fun sasConfirm(accept: Boolean): ByteArray = byteArrayOf(if (accept) 1 else 0)
    fun parseSasConfirm(p: ByteArray): Boolean = p.isNotEmpty() && p[0].toInt() == 1

    // ABORT (either): reason[1]
    fun abort(reason: AbortReason): ByteArray = byteArrayOf(reason.code.toByte())
    fun parseAbort(p: ByteArray): AbortReason =
        AbortReason.fromCode(if (p.isEmpty()) -1 else p[0].toInt())

    // SAS code = SHA-256( lp(pkV) ‖ lp(pkA) ‖ lp(nV) ‖ lp(r) ‖ lp(nA) ), first 4 bytes BE, masked to 31 bits.
    fun sasCode(pkV: ByteArray, pkA: ByteArray, nV: ByteArray, r: ByteArray, nA: ByteArray): Int {
        val md = MessageDigest.getInstance("SHA-256")
        listOf(pkV, pkA, nV, r, nA).forEach {
            md.update(ByteBuffer.allocate(4).putInt(it.size).array())
            md.update(it)
        }
        return ByteBuffer.wrap(md.digest()).int and 0x7FFFFFFF
    }

    fun sasToEmoji(code: Int): String =
        (25 downTo 0 step 5).joinToString(" ") { EMOJI[(code shr it) and 0x1F] }

    private val EMOJI = arrayOf(
        "🎉", "🎱", "🤖", "👻", "🐶", "📱", "🦊", "🐼",
        "🦁", "🐸", "🐙", "🦄", "🌵", "🌳", "🍎", "🍌",
        "🍕", "🚗", "🚀", "🌈", "🧲", "🔥", "❄️", "🐷",
        "🌙", "☀️", "🎈", "🎁", "🔑", "🍄", "💎", "🎯"
    )
}

enum class AbortReason(val code: Int) {
    USER_REJECTED(0), COMMITMENT_MISMATCH(1), TIMEOUT(2), PROTOCOL_ERROR(3), UNKNOWN(-1);
    companion object {
        fun fromCode(code: Int): AbortReason = entries.find { it.code == code } ?: UNKNOWN
    }
}
