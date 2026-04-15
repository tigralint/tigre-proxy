package tigralint.tgproxy.proxy

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import io.ktor.utils.io.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive

/**
 * FakeTLS masking for DPI evasion.
 * Full port of fake_tls.py — ClientHello verification, ServerHello construction,
 * and TLS record wrapping.
 *
 * Performance notes:
 * - wrapTlsRecord() now writes directly into a pre-sized ByteArray (zero intermediate copies)
 * - unwrapFakeTls/wrapFakeTls use structured concurrency (no GlobalScope leaks)
 * - Hot-path wrap writes TLS headers directly into ByteWriteChannel (zero-alloc steady state)
 */
object FakeTls {

    const val TLS_RECORD_HANDSHAKE: Byte = 0x16
    const val TLS_RECORD_CCS: Byte = 0x14
    const val TLS_RECORD_APPDATA: Byte = 0x17

    private const val CLIENT_RANDOM_OFFSET = 11
    private const val CLIENT_RANDOM_LEN = 32
    private const val SESSION_ID_OFFSET = 44
    private const val SESSION_ID_LEN = 32
    private const val TIMESTAMP_TOLERANCE = 120
    const val TLS_APPDATA_MAX = 16384

    /** Pre-allocated 5-byte TLS record header template [0x17, 0x03, 0x03, 0x00, 0x00] */
    private val TLS_APPDATA_HEADER = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x00)

    data class ClientHelloResult(
        val clientRandom: ByteArray,
        val sessionId: ByteArray,
        val timestamp: Int
    )

    /**
     * Verify a TLS ClientHello from a Telegram client using FakeTLS.
     * The client_random embeds an HMAC of the entire message (with random zeroed)
     * plus a timestamp XORed into the last 4 bytes.
     *
     * @return ClientHelloResult if valid, null if verification fails
     */
    fun verifyClientHello(data: ByteArray, secret: ByteArray): ClientHelloResult? {
        val n = data.size
        // Minimum: 5 (record hdr) + 6 (hs type+len+version) + 32 (random) = 43
        if (n < 43) return null
        if (data[0] != TLS_RECORD_HANDSHAKE) return null
        if (data[5] != 0x01.toByte()) return null  // ClientHello type

        val clientRandom = data.copyOfRange(CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN)

        // Zero out client_random in the message for HMAC computation
        val zeroed = data.copyOf()
        for (i in CLIENT_RANDOM_OFFSET until CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN) {
            zeroed[i] = 0
        }

        // Compute expected HMAC-SHA256
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        val expected = mac.doFinal(zeroed)

        // Compare first 28 bytes
        for (i in 0 until 28) {
            if (expected[i] != clientRandom[i]) return null
        }

        // Extract timestamp from last 4 bytes (XORed with expected)
        val tsXor = ByteArray(4)
        for (i in 0 until 4) {
            tsXor[i] = (clientRandom[28 + i].toInt() xor expected[28 + i].toInt()).toByte()
        }
        val timestamp = ByteBuffer.wrap(tsXor).order(ByteOrder.LITTLE_ENDIAN).int

        val now = (System.currentTimeMillis() / 1000).toInt()
        if (kotlin.math.abs(now - timestamp) > TIMESTAMP_TOLERANCE) return null

        // Extract session ID (32 bytes at offset 44)
        val sessionId = if (n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20.toByte()) {
            data.copyOfRange(SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LEN)
        } else {
            ByteArray(SESSION_ID_LEN)
        }

        return ClientHelloResult(clientRandom, sessionId, timestamp)
    }

    // Server Hello template — same as Python _SERVER_HELLO_TEMPLATE
    private val SERVER_HELLO_TEMPLATE = byteArrayOf(
        0x16, 0x03, 0x03, 0x00, 0x7a,
        0x02, 0x00, 0x00, 0x76,
        0x03, 0x03
    ) + ByteArray(32) +  // server_random placeholder
        byteArrayOf(0x20) +
        ByteArray(32) +  // session_id placeholder
        byteArrayOf(0x13, 0x01, 0x00) +
        byteArrayOf(0x00, 0x2e) +
        byteArrayOf(0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20) +
        ByteArray(32) +  // public_key placeholder
        byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

    private const val SH_RANDOM_OFF = 11
    private const val SH_SESSID_OFF = 44
    private const val SH_PUBKEY_OFF = 89

    private val CCS_FRAME = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

    /**
     * Build a full ServerHello response (ServerHello + CCS + fake app data).
     * The server_random is an HMAC of (client_random + response_without_random).
     */
    fun buildServerHello(secret: ByteArray, clientRandom: ByteArray, sessionId: ByteArray): ByteArray {
        val sh = SERVER_HELLO_TEMPLATE.copyOf()

        // Fill session_id
        System.arraycopy(sessionId, 0, sh, SH_SESSID_OFF, 32)

        // Fill random public key
        val rng = SecureRandom()
        val pubkey = ByteArray(32)
        rng.nextBytes(pubkey)
        System.arraycopy(pubkey, 0, sh, SH_PUBKEY_OFF, 32)

        // Build encrypted app data record
        val encryptedSize = 1900 + rng.nextInt(201) // 1900..2100
        val encryptedData = ByteArray(encryptedSize)
        rng.nextBytes(encryptedData)

        val appRecordHeader = ByteBuffer.allocate(5)
            .put(0x17.toByte())
            .put(0x03.toByte())
            .put(0x03.toByte())
            .putShort(encryptedSize.toShort())
            .array()

        // Assemble: SH + CCS + AppData — single allocation
        val totalSize = sh.size + CCS_FRAME.size + appRecordHeader.size + encryptedData.size
        val response = ByteArray(totalSize)
        var offset = 0
        System.arraycopy(sh, 0, response, offset, sh.size); offset += sh.size
        System.arraycopy(CCS_FRAME, 0, response, offset, CCS_FRAME.size); offset += CCS_FRAME.size
        System.arraycopy(appRecordHeader, 0, response, offset, appRecordHeader.size); offset += appRecordHeader.size
        System.arraycopy(encryptedData, 0, response, offset, encryptedData.size)

        // Compute HMAC of (client_random + response)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        mac.update(clientRandom)
        val serverRandom = mac.doFinal(response)

        // Place computed server_random
        System.arraycopy(serverRandom, 0, response, SH_RANDOM_OFF, 32)

        return response
    }

    /**
     * Wrap arbitrary data into TLS Application Data records (type 0x17).
     * Splits into chunks of max 16384 bytes.
     *
     * OPTIMIZED: Single pre-calculated allocation instead of O(N²) fold.
     */
    fun wrapTlsRecord(data: ByteArray): ByteArray {
        if (data.isEmpty()) return ByteArray(0)

        // Calculate exact total size upfront
        val numFullChunks = data.size / TLS_APPDATA_MAX
        val lastChunkSize = data.size % TLS_APPDATA_MAX
        val numChunks = numFullChunks + if (lastChunkSize > 0) 1 else 0
        val totalSize = numChunks * 5 + data.size // 5 bytes header per chunk + all data

        val result = ByteArray(totalSize)
        var srcOffset = 0
        var dstOffset = 0

        while (srcOffset < data.size) {
            val chunkLen = minOf(TLS_APPDATA_MAX, data.size - srcOffset)

            // Write TLS record header directly
            result[dstOffset] = 0x17
            result[dstOffset + 1] = 0x03
            result[dstOffset + 2] = 0x03
            result[dstOffset + 3] = (chunkLen shr 8).toByte()
            result[dstOffset + 4] = (chunkLen and 0xFF).toByte()
            dstOffset += 5

            // Copy payload
            System.arraycopy(data, srcOffset, result, dstOffset, chunkLen)
            dstOffset += chunkLen
            srcOffset += chunkLen
        }

        return result
    }

    /**
     * Creates an async Ktor pipe that unwraps TLS Application Data records
     * from the raw [source] and pushes the plaintext MTProto data to the returned channel.
     *
     * FIXED: Uses structured concurrency via [scope] parameter instead of GlobalScope.
     */
    fun unwrapFakeTls(source: ByteReadChannel, scope: CoroutineScope): ByteReadChannel {
        return scope.writer(Dispatchers.IO, autoFlush = true) {
            val dest = channel
            // Reusable header buffer — zero allocation in the loop
            val hdr = ByteArray(5)
            // Reusable copy buffer — zero allocation in the loop
            val copyBuf = ByteArray(TLS_APPDATA_MAX)
            try {
                while (isActive && !source.isClosedForRead) {
                    try {
                        source.readFully(hdr)
                    } catch (e: Exception) {
                        break // EOF or closed
                    }
                    val rtype = hdr[0]
                    val recLen = ((hdr[3].toInt() and 0xFF) shl 8) or (hdr[4].toInt() and 0xFF)

                    if (rtype == TLS_RECORD_CCS) {
                        source.discardExact(recLen.toLong())
                        continue
                    }

                    if (rtype != TLS_RECORD_APPDATA) {
                        break
                    }

                    // Copy EXACTLY recLen bytes from source to dest using shared buffer
                    var left = recLen
                    while (left > 0 && !source.isClosedForRead) {
                        val toRead = minOf(left, copyBuf.size)
                        val n = source.readAvailable(copyBuf, 0, toRead)
                        if (n == -1) break
                        dest.writeFully(copyBuf, 0, n)
                        left -= n
                    }
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
            } catch (_: Exception) {}
        }.channel
    }

    /**
     * Creates an async Ktor pipe that wraps any raw MTProto data written to the
     * returned channel into FakeTLS Application Data records and writes them to [destination].
     *
     * FIXED: Uses structured concurrency via [scope] parameter instead of GlobalScope.
     * OPTIMIZED: Writes TLS headers directly into ByteWriteChannel — TRUE zero-allocation
     *            in the steady-state loop (no intermediate ByteArray copies).
     */
    fun wrapFakeTls(destination: ByteWriteChannel, scope: CoroutineScope): ByteWriteChannel {
        return scope.reader(Dispatchers.IO) {
            val source = channel
            // Pre-allocated read buffer — reused every iteration
            val buf = ByteArray(TLS_APPDATA_MAX)
            // Pre-allocated 5-byte TLS header — reused every iteration
            val hdr = ByteArray(5)
            hdr[0] = 0x17
            hdr[1] = 0x03
            hdr[2] = 0x03

            // TCP Slow Start simulation: first records use progressively larger sizes
            // to mimic Chrome's congestion window growth pattern.
            // This prevents DPI from detecting constant 16KB records as proxy traffic.
            val SLOW_START_SIZES = intArrayOf(517, 1024, 2048, 4096, 8192)
            var recordIndex = 0

            try {
                while (isActive && !source.isClosedForRead) {
                    // Limit read size based on slow-start phase
                    val maxRead = if (recordIndex < SLOW_START_SIZES.size) {
                        SLOW_START_SIZES[recordIndex]
                    } else {
                        TLS_APPDATA_MAX
                    }
                    val n = source.readAvailable(buf, 0, maxRead)
                    if (n == -1) break

                    // Write TLS record header directly (zero-alloc)
                    hdr[3] = (n shr 8).toByte()
                    hdr[4] = (n and 0xFF).toByte()
                    destination.writeFully(hdr)

                    // Write payload directly from our reused buffer (zero-alloc)
                    destination.writeFully(buf, 0, n)
                    destination.flush()
                    recordIndex++
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
            } catch (_: Exception) {}
        }.channel
    }

    // ===== Legacy unwrap/wrap (old API without scope — DEPRECATED) =====
    // Kept temporarily for backward compatibility. Callers should migrate to scoped versions.

    /**
     * @deprecated Use unwrapFakeTls(source, scope) instead for structured concurrency.
     */
    @Deprecated("Use unwrapFakeTls(source, scope) for structured concurrency", ReplaceWith("unwrapFakeTls(source, scope)"))
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun unwrapFakeTls(source: ByteReadChannel): ByteReadChannel {
        return unwrapFakeTls(source, kotlinx.coroutines.GlobalScope)
    }

    /**
     * @deprecated Use wrapFakeTls(destination, scope) instead for structured concurrency.
     */
    @Deprecated("Use wrapFakeTls(destination, scope) for structured concurrency", ReplaceWith("wrapFakeTls(destination, scope)"))
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun wrapFakeTls(destination: ByteWriteChannel): ByteWriteChannel {
        return wrapFakeTls(destination, kotlinx.coroutines.GlobalScope)
    }
}
