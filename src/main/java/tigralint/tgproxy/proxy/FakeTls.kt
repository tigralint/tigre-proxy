package tigralint.tgproxy.proxy

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import io.ktor.utils.io.*
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope

/**
 * FakeTLS masking for DPI evasion.
 * Full port of fake_tls.py — ClientHello verification, ServerHello construction,
 * and TLS record wrapping.
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

        // Assemble: SH + CCS + AppData
        val response = sh + CCS_FRAME + appRecordHeader + encryptedData

        // Compute HMAC of (client_random + response)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        mac.update(clientRandom)
        val serverRandom = mac.doFinal(response)

        // Place computed server_random
        val final = response.copyOf()
        System.arraycopy(serverRandom, 0, final, SH_RANDOM_OFF, 32)

        return final
    }

    /**
     * Wrap arbitrary data into TLS Application Data records (type 0x17).
     * Splits into chunks of max 16384 bytes.
     */
    fun wrapTlsRecord(data: ByteArray): ByteArray {
        val parts = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val chunkLen = minOf(TLS_APPDATA_MAX, data.size - offset)
            val header = ByteBuffer.allocate(5)
                .put(0x17.toByte())
                .put(0x03.toByte())
                .put(0x03.toByte())
                .putShort(chunkLen.toShort())
                .array()
            parts.add(header + data.copyOfRange(offset, offset + chunkLen))
            offset += chunkLen
        }
        return parts.fold(ByteArray(0)) { acc, arr -> acc + arr }
    }

    /**
     * Creates an async Ktor pipe that unwraps TLS Application Data records
     * from the raw [source] and pushes the plaintext MTProto data to the returned channel.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun unwrapFakeTls(source: ByteReadChannel): ByteReadChannel {
        return kotlinx.coroutines.GlobalScope.writer(kotlinx.coroutines.Dispatchers.IO, autoFlush = true) {
            val dest = channel
            try {
                while (!source.isClosedForRead) {
                    val hdr = ByteArray(5)
                    try {
                        source.readFully(hdr)
                    } catch (e: Exception) {
                        break // EOF or closed
                    }
                    val rtype = hdr[0]
                    val recLen = ByteBuffer.wrap(hdr, 3, 2).short.toInt() and 0xFFFF

                    if (rtype == TLS_RECORD_CCS) {
                        source.discardExact(recLen.toLong())
                        continue
                    }

                    if (rtype != TLS_RECORD_APPDATA) {
                        break
                    }

                    // Copy EXACTLY recLen bytes from source to dest
                    var left = recLen.toLong()
                    val copyBuf = ByteArray(8192)
                    while (left > 0 && !source.isClosedForRead) {
                        val toRead = minOf(left.toInt(), copyBuf.size)
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
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun wrapFakeTls(destination: ByteWriteChannel): ByteWriteChannel {
        return kotlinx.coroutines.GlobalScope.reader(kotlinx.coroutines.Dispatchers.IO) {
            val source = channel
            try {
                val buf = ByteArray(16384)
                while (!source.isClosedForRead) {
                    val n = source.readAvailable(buf)
                    if (n == -1) break
                    val tlsRec = wrapTlsRecord(buf.copyOfRange(0, n))
                    destination.writeFully(tlsRec)
                    destination.flush()
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
            } catch (_: Exception) {}
        }.channel
    }
}
