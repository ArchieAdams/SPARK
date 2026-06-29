package uk.ac.york.emrys


interface ByteTransport {
    var onBytes: ((ByteArray) -> Unit)?
    fun sendBytes(data: ByteArray): Boolean
}
