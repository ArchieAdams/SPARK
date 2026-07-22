package uk.ac.york.spark


interface ByteTransport {
    var onBytes: ((ByteArray) -> Unit)?
    fun sendBytes(data: ByteArray): Boolean
}
