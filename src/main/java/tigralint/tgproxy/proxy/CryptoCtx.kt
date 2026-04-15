package tigralint.tgproxy.proxy

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-CTR cipher wrapper.
 * CTR mode is symmetric — the same operation encrypts and decrypts.
 * This mirrors Python's `Cipher(AES, CTR).encryptor()` usage.
 */
class AesCtrCipher(key: ByteArray, iv: ByteArray) {
    private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }

    companion object {
        /**
         * Shared zero buffer for skip() operations.
         * Since AES-CTR XORs input with keystream, feeding zeros just produces the
         * keystream itself — which we discard. The input buffer is never mutated,
         * so sharing it across all cipher instances is thread-safe.
         *
         * 256 bytes covers any realistic skip (typically 64 bytes).
         */
        private val SKIP_BUF = ByteArray(256)

        /**
         * Thread-local discard buffer for skip() output.
         * Each thread gets its own buffer — eliminates data race if two
         * skip() calls run on different coroutine dispatchers simultaneously.
         */
        private val skipOutLocal = ThreadLocal.withInitial { ByteArray(256) }
    }

    /**
     * Process data through the cipher stream. In CTR mode this is the same
     * operation for both encryption and decryption.
     */
    fun update(data: ByteArray): ByteArray {
        return cipher.update(data)
    }

    /**
     * Process a slice of the buffer without copying. Returns a newly allocated array.
     */
    fun update(data: ByteArray, offset: Int, len: Int): ByteArray {
        return cipher.update(data, offset, len)
    }

    /**
     * ULTRA ZERO-ALLOCATION PATH.
     * Process data directly into the provided output buffer. 
     */
    fun update(input: ByteArray, inOff: Int, len: Int, output: ByteArray, outOff: Int): Int {
        return cipher.update(input, inOff, len, output, outOff)
    }

    /**
     * Advance the cipher keystream by [n] zero bytes (fast-forward).
     *
     * ZERO-ALLOCATION: Uses shared static input buffer + thread-local output buffer.
     * For typical skip(64) this means 0 GC pressure per connection handshake.
     */
    fun skip(n: Int) {
        val skipOut = skipOutLocal.get()!!
        var remaining = n
        while (remaining > 0) {
            val chunk = minOf(remaining, SKIP_BUF.size)
            cipher.update(SKIP_BUF, 0, chunk, skipOut, 0)
            remaining -= chunk
        }
    }
}

/**
 * Holds the four AES-CTR cipher contexts needed for bidirectional re-encryption.
 *
 * Data flow:
 *   Client ciphertext → cltDec → plaintext → tgEnc → Telegram ciphertext
 *   Telegram ciphertext → tgDec → plaintext → cltEnc → Client ciphertext
 *
 * Port of Python CryptoCtx from bridge.py.
 */
data class CryptoCtx(
    val cltDec: AesCtrCipher,  // decrypt data FROM client
    val cltEnc: AesCtrCipher,  // encrypt data TO client
    val tgEnc: AesCtrCipher,   // encrypt data TO telegram
    val tgDec: AesCtrCipher    // decrypt data FROM telegram
)
