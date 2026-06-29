package uk.ac.york.emrys

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

    // SETUP_REQ (A->V): deviceId[16] ‖ port[4] ‖ len(pkA) ‖ pkA(DER)
    fun setupReq(deviceId: UUID, pkA: ByteArray, port: Int): ByteArray =
        PayloadWriter().bytes(deviceId.toBytes16()).int(port).lenBytes(pkA).build()

    data class SetupReq(val deviceId: UUID, val port: Int, val pkA: ByteArray)

    fun parseSetupReq(p: ByteArray): SetupReq = PayloadReader(p).let {
        SetupReq(bytesToUuid(it.bytes(16)), it.int(), it.lenBytes())
    }

    // COMMIT (V->A): len(pkV) ‖ pkV(DER) ‖ c[32]   (c = SHA-256(N‖r))
    fun commit(pkV: ByteArray, c: ByteArray): ByteArray =
        PayloadWriter().lenBytes(pkV).bytes(c).build()

    data class Commit(val pkV: ByteArray, val c: ByteArray)

    fun parseCommit(p: ByteArray): Commit = PayloadReader(p).let {
        Commit(it.lenBytes(), it.bytes(COMMIT_HASH))
    }

    // REVEAL (V->A): N[32] ‖ r[32]
    fun reveal(n: ByteArray, r: ByteArray): ByteArray {
        require(n.size == NONCE && r.size == R) { "reveal: N and r must be $NONCE/$R bytes" }
        return PayloadWriter().bytes(n).bytes(r).build()
    }

    data class Reveal(val n: ByteArray, val r: ByteArray)

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

    // SAS = SHA-256( lp(N) ‖ lp(pkV) ‖ lp(pkA) ), first 4 bytes BE masked, mod 1e6.
    fun sas(n: ByteArray, pkV: ByteArray, pkA: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        listOf(n, pkV, pkA).forEach {
            md.update(ByteBuffer.allocate(4).putInt(it.size).array())
            md.update(it)
        }
        val code = ByteBuffer.wrap(md.digest()).int and 0x7FFFFFFF
        return String.format(Locale.US, "%06d", code % 1_000_000)
    }

    const val NONCE = 32
    const val R = 32
    const val COMMIT_HASH = 32  // SHA-256
}

enum class AbortReason(val code: Int) {
    USER_REJECTED(0), COMMITMENT_MISMATCH(1), TIMEOUT(2), PROTOCOL_ERROR(3), UNKNOWN(-1);
    companion object {
        fun fromCode(code: Int): AbortReason = entries.find { it.code == code } ?: UNKNOWN
    }
}
