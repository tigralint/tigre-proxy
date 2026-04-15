package tigralint.tgproxy.proxy

/**
 * Splits a TCP byte stream into individual MTProto transport packets.
 * This ensures each WS frame contains exactly one transport packet.
 *
 * It uses flat pre-allocated internal buffers to reduce garbage collection 
 * pressure during packet analysis, though it still returns allocated 
 * ByteArrays to simplify the bridge logic.
 *
 * Port of MsgSplitter from bridge.py.
 */
class MsgSplitter(relayInit: ByteArray, private val protoInt: Int) {
    private val dec: AesCtrCipher
    private var disabled = false

    // Flat pre-allocated buffers (128 KB) to prevent object scaling issues
    private val cipherBuf = ByteArray(131072)
    private val plainBuf = ByteArray(131072)
    
    private var readPos = 0
    private var writePos = 0
    private val size: Int get() = writePos - readPos

    init {
        // Key from relay_init[8..40], IV from relay_init[40..56]
        val key = relayInit.copyOfRange(8, 40)
        val iv = relayInit.copyOfRange(40, 56)
        dec = AesCtrCipher(key, iv)
        // Fast-forward past the 64-byte init
        dec.skip(64)
    }

    /**
     * Feed a chunk of ciphertext and return a list of complete transport packets.
     * Each returned ByteArray is still encrypted — we only decrypt internally
     * to find packet boundaries.
     */
    fun split(chunk: ByteArray): List<ByteArray> {
        if (chunk.isEmpty()) return emptyList()
        if (disabled) return listOf(chunk)

        // Ensure capacity and compact buffers if necessary
        if (writePos + chunk.size > cipherBuf.size) {
            if (readPos > 0) {
                val currentSize = size
                System.arraycopy(cipherBuf, readPos, cipherBuf, 0, currentSize)
                System.arraycopy(plainBuf, readPos, plainBuf, 0, currentSize)
                writePos = currentSize
                readPos = 0
            } else {
                // Buffer overflow (protocol desync or chunk too large), disable splitter safely
                val tail = cipherBuf.copyOfRange(readPos, writePos)
                val remaining = ByteArray(tail.size + chunk.size)
                System.arraycopy(tail, 0, remaining, 0, tail.size)
                System.arraycopy(chunk, 0, remaining, tail.size, chunk.size)
                
                readPos = 0
                writePos = 0
                disabled = true
                return listOf(remaining)
            }
        }

        // Write directly into internal buffers WITHOUT intermediate allocation
        System.arraycopy(chunk, 0, cipherBuf, writePos, chunk.size)
        dec.update(chunk, 0, chunk.size, plainBuf, writePos)
        writePos += chunk.size

        val parts = mutableListOf<ByteArray>()

        while (size > 0) {
            val packetLen = nextPacketLen() ?: break

            if (packetLen <= 0) {
                // Protocol error or unknown protocol — flush everything
                parts.add(cipherBuf.copyOfRange(readPos, writePos))
                readPos = 0
                writePos = 0
                disabled = true
                break
            }

            parts.add(cipherBuf.copyOfRange(readPos, readPos + packetLen))
            readPos += packetLen
        }

        return parts
    }

    /** Flush any remaining buffered data. */
    fun flush(): List<ByteArray> {
        if (size <= 0) return emptyList()
        val tail = cipherBuf.copyOfRange(readPos, writePos)
        readPos = 0
        writePos = 0
        return listOf(tail)
    }

    private fun nextPacketLen(): Int? {
        if (size == 0) return null
        return when (protoInt) {
            Constants.PROTO_ABRIDGED_INT -> nextAbridgedLen()
            Constants.PROTO_INTERMEDIATE_INT,
            Constants.PROTO_PADDED_INTERMEDIATE_INT -> nextIntermediateLen()
            else -> 0  // Unknown protocol — disable splitting
        }
    }

    private fun nextAbridgedLen(): Int? {
        val first = plainBuf[readPos].toInt() and 0xFF
        return if (first == 0x7F || first == 0xFF) {
            if (size < 4) return null
            val payloadLen = ((plainBuf[readPos + 1].toInt() and 0xFF) or
                    ((plainBuf[readPos + 2].toInt() and 0xFF) shl 8) or
                    ((plainBuf[readPos + 3].toInt() and 0xFF) shl 16)) * 4
            if (payloadLen <= 0) return 0
            val packetLen = 4 + payloadLen
            if (size < packetLen) null else packetLen
        } else {
            val payloadLen = (first and 0x7F) * 4
            if (payloadLen <= 0) return 0
            val packetLen = 1 + payloadLen
            if (size < packetLen) null else packetLen
        }
    }

    private fun nextIntermediateLen(): Int? {
        if (size < 4) return null
        val payloadLen = ((plainBuf[readPos].toInt() and 0xFF) or
                ((plainBuf[readPos + 1].toInt() and 0xFF) shl 8) or
                ((plainBuf[readPos + 2].toInt() and 0xFF) shl 16) or
                ((plainBuf[readPos + 3].toInt() and 0xFF) shl 24)) and 0x7FFFFFFF
        if (payloadLen <= 0) return 0
        val packetLen = 4 + payloadLen
        return if (size < packetLen) null else packetLen
    }
}
