package tigralint.tgproxy.proxy

import java.util.concurrent.ConcurrentHashMap

/**
 * Protection against replay attacks on the MTProto obfuscated handshake.
 *
 * THREAT MODEL:
 * TSPU/DPI can capture a valid 64-byte handshake from a real Telegram client
 * and replay it to probe whether a server is a proxy. Without replay protection,
 * the proxy would accept the replayed handshake and reveal itself.
 *
 * MECHANISM:
 * We store a hash of every accepted handshake's unique bytes (the first 56 bytes,
 * which contain the random nonce + encrypted prekey/IV). If the same nonce is
 * seen again, we reject it silently (treat as invalid handshake → forward to
 * masking domain or drop).
 *
 * The cache is time-bounded: entries older than [maxAgeSec] seconds are evicted
 * on every check, preventing unbounded memory growth. The default TTL of 600s
 * is sufficient because MTProto handshakes include a timestamp that the client
 * validates within ~300s, so replays older than that are already invalid.
 *
 * MEMORY: Each entry is ~36 bytes (32-byte hash key + 8-byte long timestamp).
 * At 1000 connections/min, the cache uses ~35KB — negligible.
 */
class ReplayProtection(
    private val maxAgeSec: Long = 600L // 10 minutes, 2x the MTProto timestamp tolerance
) {
    // Map of SHA-256(handshake nonce) → timestamp when it was first seen
    private val seen = ConcurrentHashMap<Long, Long>(256)

    /**
     * Check if this handshake nonce has been seen before.
     *
     * @param handshake the full 64-byte obfuscated handshake
     * @return true if this is a NEW (non-replayed) handshake, false if it's a replay
     */
    fun checkAndRecord(handshake: ByteArray): Boolean {
        // Use the first 56 bytes as the unique nonce (positions 0-55)
        // These contain the random data + encrypted prekey + IV.
        // Positions 56-63 contain the protocol tag + DC, which could be
        // the same across different legitimate connections.
        val hash = fastHash(handshake, 0, 56)

        val now = System.currentTimeMillis()

        // Evict old entries periodically (every ~100 checks)
        if (seen.size > 100 && (now % 100L) == 0L) {
            evictStale(now)
        }

        // putIfAbsent returns null if the key was NOT present (= new handshake)
        val existing = seen.putIfAbsent(hash, now)
        return existing == null
    }

    /**
     * Remove entries older than maxAgeSec.
     */
    private fun evictStale(now: Long) {
        val cutoff = now - (maxAgeSec * 1000L)
        val iter = seen.entries.iterator()
        while (iter.hasNext()) {
            if (iter.next().value < cutoff) {
                iter.remove()
            }
        }
    }

    /**
     * Fast 64-bit hash of a byte range using FNV-1a.
     * We don't need cryptographic strength here — just collision resistance
     * over a small set of recent handshakes. FNV-1a is ideal: zero-allocation,
     * no object creation, extremely fast on short inputs.
     */
    private fun fastHash(data: ByteArray, offset: Int, length: Int): Long {
        var hash = -0x340d631b7bdddcdbL // FNV offset basis
        for (i in offset until offset + length) {
            hash = hash xor (data[i].toLong() and 0xFF)
            hash *= 0x100000001B3L // FNV prime
        }
        return hash
    }

    /**
     * Reset the cache (called on server stop).
     */
    fun clear() {
        seen.clear()
    }
}
