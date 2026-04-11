package tigralint.tgproxy.proxy

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * MTProto obfuscated handshake logic.
 * Port of _try_handshake and _generate_relay_init from tg_ws_proxy.py.
 */
object MtProtoHandshake {

    data class HandshakeResult(
        val dcId: Int,
        val isMedia: Boolean,
        val protoTag: ByteArray,
        val decPrekeyAndIv: ByteArray
    )

    /**
     * Attempt to parse and verify a 64-byte MTProto obfuscated handshake.
     *
     * @param handshake 64 bytes from the client
     * @param secret 16-byte proxy secret
     * @return HandshakeResult if valid, null if bad secret or unknown protocol
     */
    fun tryHandshake(handshake: ByteArray, secret: ByteArray): HandshakeResult? {
        require(handshake.size == Constants.HANDSHAKE_LEN) { "Handshake must be ${Constants.HANDSHAKE_LEN} bytes" }

        val decPrekeyAndIv = handshake.copyOfRange(
            Constants.SKIP_LEN,
            Constants.SKIP_LEN + Constants.PREKEY_LEN + Constants.IV_LEN
        )
        val decPrekey = decPrekeyAndIv.copyOfRange(0, Constants.PREKEY_LEN)
        val decIv = decPrekeyAndIv.copyOfRange(Constants.PREKEY_LEN, Constants.PREKEY_LEN + Constants.IV_LEN)

        // Key = SHA256(prekey + secret)
        val sha256 = MessageDigest.getInstance("SHA-256")
        sha256.update(decPrekey)
        sha256.update(secret)
        val decKey = sha256.digest()

        // Decrypt full handshake with AES-CTR to check protocol tag
        val decryptor = AesCtrCipher(decKey, decIv)
        val decrypted = decryptor.update(handshake)

        // Check protocol tag at position 56
        val protoTag = decrypted.copyOfRange(Constants.PROTO_TAG_POS, Constants.PROTO_TAG_POS + 4)

        if (!protoTag.contentEquals(Constants.PROTO_TAG_ABRIDGED) &&
            !protoTag.contentEquals(Constants.PROTO_TAG_INTERMEDIATE) &&
            !protoTag.contentEquals(Constants.PROTO_TAG_SECURE)
        ) {
            return null
        }

        // Extract DC index (signed 16-bit little-endian) at position 60
        val dcIdx = ByteBuffer.wrap(decrypted, Constants.DC_IDX_POS, 2)
            .order(ByteOrder.LITTLE_ENDIAN)
            .short.toInt()

        val dcId = kotlin.math.abs(dcIdx)
        val isMedia = dcIdx < 0

        return HandshakeResult(dcId, isMedia, protoTag, decPrekeyAndIv)
    }

    /**
     * Generate a 64-byte relay init for the outbound connection to Telegram.
     * Port of _generate_relay_init from tg_ws_proxy.py.
     */
    fun generateRelayInit(protoTag: ByteArray, dcIdx: Int): ByteArray {
        val random = SecureRandom()

        // Generate random 64 bytes, avoiding reserved patterns
        var rnd: ByteArray
        while (true) {
            rnd = ByteArray(Constants.HANDSHAKE_LEN)
            random.nextBytes(rnd)

            if (rnd[0] in Constants.RESERVED_FIRST_BYTES) continue

            val first4 = rnd.copyOfRange(0, 4)
            if (Constants.isReservedStart(first4)) continue

            val continue4 = rnd.copyOfRange(4, 8)
            if (continue4.contentEquals(Constants.RESERVED_CONTINUE)) continue

            break
        }

        val encKey = rnd.copyOfRange(Constants.SKIP_LEN, Constants.SKIP_LEN + Constants.PREKEY_LEN)
        val encIv = rnd.copyOfRange(
            Constants.SKIP_LEN + Constants.PREKEY_LEN,
            Constants.SKIP_LEN + Constants.PREKEY_LEN + Constants.IV_LEN
        )

        val encryptor = AesCtrCipher(encKey, encIv)

        // DC index as signed 16-bit little-endian
        val dcBytes = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(dcIdx.toShort()).array()

        // Tail: proto_tag (4) + dc_bytes (2) + random (2) = 8 bytes
        val tailPlain = ByteArray(8)
        System.arraycopy(protoTag, 0, tailPlain, 0, 4)
        System.arraycopy(dcBytes, 0, tailPlain, 4, 2)
        val rndTail = ByteArray(2)
        random.nextBytes(rndTail)
        System.arraycopy(rndTail, 0, tailPlain, 6, 2)

        // Encrypt the full random to get the keystream
        val encryptedFull = encryptor.update(rnd)

        // XOR extraction: keystream_tail = encrypted ^ plain, then encrypt tail
        val keystreamTail = ByteArray(8)
        for (i in 0 until 8) {
            keystreamTail[i] = (encryptedFull[56 + i].toInt() xor rnd[56 + i].toInt()).toByte()
        }
        val encryptedTail = ByteArray(8)
        for (i in 0 until 8) {
            encryptedTail[i] = (tailPlain[i].toInt() xor keystreamTail[i].toInt()).toByte()
        }

        // Place encrypted tail at positions 56..63
        val result = rnd.copyOf()
        System.arraycopy(encryptedTail, 0, result, Constants.PROTO_TAG_POS, 8)

        return result
    }
}
