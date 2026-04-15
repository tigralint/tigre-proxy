package tigralint.tgproxy.proxy

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

/**
 * Wraps a raw TCP stream to transparently handle TLS record framing.
 * On read: strips TLS record headers, skips CCS records, returns app data payloads.
 * On write: wraps data into TLS Application Data records.
 *
 * Port of FakeTlsStream from fake_tls.py.
 */
class FakeTlsStream(
    private val input: InputStream,
    private val output: OutputStream
) {
    private val readBuf = ByteArrayBuffer()
    private var readLeft = 0

    /**
     * Read exactly [n] bytes, unwrapping TLS records as needed.
     * @throws java.io.EOFException if stream ends before n bytes are available
     */
    fun readExactly(n: Int): ByteArray {
        while (readBuf.size < n) {
            val payload = readTlsPayload()
            if (payload.isEmpty()) {
                throw java.io.EOFException("Stream ended, needed $n bytes, got ${readBuf.size}")
            }
            readBuf.append(payload)
        }
        return readBuf.consume(n)
    }

    /**
     * Read up to [n] bytes, unwrapping TLS records.
     * Returns empty array on EOF.
     */
    fun read(n: Int): ByteArray {
        if (readBuf.size > 0) {
            return readBuf.consume(minOf(n, readBuf.size))
        }
        val payload = readTlsPayload()
        if (payload.isEmpty()) return ByteArray(0)
        if (payload.size <= n) {
            return payload // Fits — no copy needed
        }
        // Payload too large: return first n bytes, buffer the rest
        readBuf.append(payload, n, payload.size - n)
        return payload.copyOfRange(0, n)
    }

    /**
     * Read one TLS record payload from the underlying stream.
     * Skips CCS records. Returns empty on non-appdata or EOF.
     */
    private fun readTlsPayload(): ByteArray {
        // If we have leftover data from a previous partial read
        if (readLeft > 0) {
            val data = readFromStream(input, minOf(readLeft, 65536))
            if (data.isEmpty()) return ByteArray(0)
            readLeft -= data.size
            return data
        }

        while (true) {
            // Read 5-byte TLS record header
            val hdr = readExactlyFromStream(input, 5) ?: return ByteArray(0)
            val rtype = hdr[0]
            val recLen = ByteBuffer.wrap(hdr, 3, 2).short.toInt() and 0xFFFF

            // Skip CCS records
            if (rtype == FakeTls.TLS_RECORD_CCS) {
                if (recLen > 0) {
                    readExactlyFromStream(input, recLen) // discard
                }
                continue
            }

            // Only process Application Data records
            if (rtype != FakeTls.TLS_RECORD_APPDATA) {
                return ByteArray(0)
            }

            val data = readFromStream(input, minOf(recLen, 65536))
            if (data.isEmpty()) return ByteArray(0)
            val remaining = recLen - data.size
            if (remaining > 0) {
                readLeft = remaining
            }
            return data
        }
    }

    /**
     * Write data, wrapping it in TLS Application Data records.
     */
    fun write(data: ByteArray) {
        output.write(FakeTls.wrapTlsRecord(data))
    }

    fun flush() {
        output.flush()
    }

    fun close() {
        try { input.close() } catch (_: Exception) {}
        try { output.close() } catch (_: Exception) {}
    }

    companion object {
        /** Read exactly n bytes from stream, or return null on EOF. */
        fun readExactlyFromStream(input: InputStream, n: Int): ByteArray? {
            val buf = ByteArray(n)
            var offset = 0
            while (offset < n) {
                val read = input.read(buf, offset, n - offset)
                if (read == -1) return if (offset == 0) null else buf.copyOfRange(0, offset)
                offset += read
            }
            return buf
        }

        /** Read up to n bytes from stream. Returns empty on EOF. */
        fun readFromStream(input: InputStream, n: Int): ByteArray {
            val buf = ByteArray(n)
            val read = input.read(buf, 0, n)
            if (read == -1) return ByteArray(0)
            return buf.copyOfRange(0, read)
        }
    }
}

/**
 * Simple growable byte buffer for internal buffering.
 */
class ByteArrayBuffer {
    private var data = ByteArray(4096)
    private var writePos = 0
    private var readPos = 0

    val size: Int get() = writePos - readPos

    fun append(bytes: ByteArray) {
        append(bytes, 0, bytes.size)
    }

    fun append(bytes: ByteArray, offset: Int, length: Int) {
        ensureCapacity(length)
        System.arraycopy(bytes, offset, data, writePos, length)
        writePos += length
    }

    fun consume(n: Int): ByteArray {
        val count = minOf(n, size)
        val result = data.copyOfRange(readPos, readPos + count)
        readPos += count
        if (readPos == writePos) {
            readPos = 0
            writePos = 0
        }
        return result
    }

    private fun ensureCapacity(additional: Int) {
        if (writePos + additional > data.size) {
            // Compact first
            if (readPos > 0) {
                System.arraycopy(data, readPos, data, 0, size)
                writePos = size
                readPos = 0
            }
            // Grow if still not enough
            if (writePos + additional > data.size) {
                val newSize = maxOf(data.size * 2, writePos + additional)
                data = data.copyOf(newSize)
            }
        }
    }
}
