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

    /** Advance the cipher keystream by [n] zero bytes (fast-forward). */
    fun skip(n: Int) {
        cipher.update(ByteArray(n))
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
