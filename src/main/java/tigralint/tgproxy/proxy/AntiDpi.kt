package tigralint.tgproxy.proxy

import android.util.Log
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.conscrypt.Conscrypt
import org.json.JSONObject
import java.net.InetAddress
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/**
 * Anti-DPI / Anti-TSPU utilities.
 *
 * Provides:
 * - Junk padding HTTP headers to break packet size signatures
 * - Traffic shaping micro-delays to blur MTProto timing patterns
 * - DNS-over-HTTPS resolver with multi-provider failover
 * - Conscrypt-based SSLSocketFactory for Chrome-like TLS fingerprint
 * - Randomized TCP fragmentation for relay_init handshakes
 * - Client Hints headers for browser fingerprint accuracy
 */
object AntiDpi {
    private const val TAG = "AntiDpi"
    private val random = SecureRandom()

    // =========================================================================
    // 1. JUNK PADDING — Random HTTP headers to break DPI packet size signatures
    // =========================================================================

    /** Realistic browser-like Accept-Language values */
    private val ACCEPT_LANGUAGES = listOf(
        "en-US,en;q=0.9",
        "en-US,en;q=0.9,ru;q=0.8",
        "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"
    )

    /** Chrome 133-134 / Android 14-15 User-Agent strings (updated April 2026) */
    private val USER_AGENTS = listOf(
        "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; 2407FPN8EG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 15; Nothing Phone (2a)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36"
    )

    /** Chrome Client Hints Sec-Ch-Ua values matching the UA strings above */
    private val SEC_CH_UA = listOf(
        "\"Chromium\";v=\"134\", \"Google Chrome\";v=\"134\", \"Not:A-Brand\";v=\"24\"",
        "\"Chromium\";v=\"133\", \"Google Chrome\";v=\"133\", \"Not:A-Brand\";v=\"24\""
    )

    /**
     * Generate a map of random padding HTTP headers.
     * These break DPI packet-size signatures by varying the total
     * size of the HTTP Upgrade request unpredictably.
     *
     * Includes Chrome Client Hints for fingerprint accuracy.
     *
     * @param minPaddingBytes minimum total padding bytes (default 50)
     * @param maxPaddingBytes maximum total padding bytes (default 500)
     */
    fun generatePaddingHeaders(
        minPaddingBytes: Int = 50,
        maxPaddingBytes: Int = 500
    ): Map<String, String> {
        val headers = mutableMapOf<String, String>()

        // 1. Realistic browser headers
        val uaIndex = random.nextInt(USER_AGENTS.size)
        headers["User-Agent"] = USER_AGENTS[uaIndex]
        headers["Accept-Language"] = ACCEPT_LANGUAGES[random.nextInt(ACCEPT_LANGUAGES.size)]
        headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"

        // 2. Chrome Client Hints (modern browsers send these)
        headers["Sec-Ch-Ua"] = SEC_CH_UA[random.nextInt(SEC_CH_UA.size)]
        headers["Sec-Ch-Ua-Mobile"] = "?1"
        headers["Sec-Ch-Ua-Platform"] = "\"Android\""

        // 3. Random session/tracking headers (look like analytics)
        headers["X-Request-Id"] = UUID.randomUUID().toString()

        // 4. Pure junk padding to randomize total packet size
        val currentSize = headers.values.sumOf { it.length }
        val targetPadding = minPaddingBytes + random.nextInt(maxPaddingBytes - minPaddingBytes)
        val remaining = (targetPadding - currentSize).coerceAtLeast(16)

        val paddingBytes = ByteArray(remaining)
        random.nextBytes(paddingBytes)
        headers["X-Pad"] = Base64.getEncoder().encodeToString(paddingBytes)

        return headers
    }

    /**
     * Get a random realistic User-Agent string.
     */
    fun randomUserAgent(): String = USER_AGENTS[random.nextInt(USER_AGENTS.size)]

    // =========================================================================
    // 2. TRAFFIC SHAPING — Micro-delays to blur MTProto timing patterns
    // =========================================================================

    /**
     * Random micro-delay for traffic shaping.
     * Only applies to the first N packets of a session (handshake phase)
     * to avoid degrading throughput during bulk transfer.
     *
     * @param packetIndex 0-based index of the current packet in the session
     * @param handshakePackets number of initial packets to apply shaping to
     * @return delay in milliseconds (0 if past handshake phase)
     */
    fun trafficShapingDelayMs(packetIndex: Int, handshakePackets: Int = 8): Long {
        if (packetIndex >= handshakePackets) return 0
        return 1L + random.nextLong(14) // 1-15ms
    }

    // =========================================================================
    // 3. TCP FRAGMENTATION — Randomized relay_init splitting
    // =========================================================================

    /**
     * Generate randomized fragment sizes for TCP handshake splitting.
     *
     * Instead of a fixed [8, 8, 8] pattern (which is a detectable signature),
     * this generates random chunk sizes that sum to [totalLen].
     * Each chunk is at least 1 byte, with random variation.
     *
     * @param totalLen total data length to fragment
     * @param minChunks minimum number of fragments (default 3)
     * @param maxChunks maximum number of fragments (default 7)
     * @return list of chunk sizes that sum to totalLen
     */
    fun randomFragmentSizes(totalLen: Int, minChunks: Int = 3, maxChunks: Int = 7): List<Int> {
        if (totalLen <= minChunks) return listOf(totalLen)

        val numChunks = minChunks + random.nextInt(maxChunks - minChunks + 1)
        val sizes = mutableListOf<Int>()

        var remaining = totalLen
        for (i in 0 until numChunks - 1) {
            if (remaining <= (numChunks - i)) {
                // Not enough bytes left, give 1 to each remaining chunk
                sizes.add(1)
                remaining -= 1
                continue
            }
            // Random size: at least 1, at most enough to leave 1 byte per remaining chunk
            val maxSize = remaining - (numChunks - i - 1)
            val chunkSize = 1 + random.nextInt(minOf(maxSize, 24)) // cap individual chunks at 25 bytes
            sizes.add(chunkSize)
            remaining -= chunkSize
        }
        sizes.add(remaining) // last chunk gets whatever's left

        return sizes
    }

    /**
     * Random delay between TCP fragments (1-30ms).
     * Variation prevents DPI from detecting fixed inter-fragment timing.
     */
    fun randomFragmentDelayMs(): Long = 1L + random.nextLong(29)

    // =========================================================================
    // 4. DNS-OVER-HTTPS — Multi-provider failover resolver
    // =========================================================================

    private val dnsCache = ConcurrentHashMap<String, CachedDns>()
    private const val DNS_CACHE_TTL_MS = 300_000L // 5 minutes

    private data class CachedDns(val addresses: List<InetAddress>, val expiresAt: Long)

    private val dohClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build()
    }

    /**
     * DNS-over-HTTPS resolver for OkHttp with multi-provider failover.
     *
     * Provider cascade: Cloudflare → Google → Quad9
     * If TSPU blocks one provider, the resolver automatically falls through
     * to the next. The last successful provider is cached for faster lookups.
     *
     * Falls back to system DNS if all DoH providers fail.
     */
    class DohDns(private val primaryDohUrl: String = DOH_CLOUDFLARE) : Dns {
        companion object {
            const val DOH_CLOUDFLARE = "https://1.1.1.1/dns-query"
            const val DOH_GOOGLE = "https://dns.google/resolve"
            const val DOH_QUAD9 = "https://dns.quad9.net:5053/dns-query"

            /** Ordered list of DoH providers for failover */
            val DOH_PROVIDERS = listOf(DOH_CLOUDFLARE, DOH_GOOGLE, DOH_QUAD9)

            /** Cache the last working provider to avoid re-probing dead ones */
            @Volatile
            private var lastWorkingProvider: String = DOH_CLOUDFLARE
        }

        override fun lookup(hostname: String): List<InetAddress> {
            // Check cache first
            val cached = dnsCache[hostname]
            if (cached != null && System.currentTimeMillis() < cached.expiresAt) {
                return cached.addresses
            }

            return try {
                val resolved = resolveWithFailover(hostname)
                if (resolved.isNotEmpty()) {
                    dnsCache[hostname] = CachedDns(
                        resolved,
                        System.currentTimeMillis() + DNS_CACHE_TTL_MS
                    )
                    resolved
                } else {
                    // Fallback to system DNS
                    Dns.SYSTEM.lookup(hostname)
                }
            } catch (e: Exception) {
                Log.d(TAG, "DoH resolve failed for $hostname: ${e.message}, falling back to system DNS")
                Dns.SYSTEM.lookup(hostname)
            }
        }

        /**
         * Try DoH providers in order: last working first, then all others.
         */
        private fun resolveWithFailover(hostname: String): List<InetAddress> {
            // Try last working provider first
            val lastWorking = lastWorkingProvider
            val result = tryResolveDoH(hostname, lastWorking)
            if (result.isNotEmpty()) return result

            // Failover: try all other providers
            for (provider in DOH_PROVIDERS) {
                if (provider == lastWorking) continue
                val fallbackResult = tryResolveDoH(hostname, provider)
                if (fallbackResult.isNotEmpty()) {
                    lastWorkingProvider = provider
                    Log.i(TAG, "DoH failover: switched to $provider")
                    return fallbackResult
                }
            }
            return emptyList()
        }

        private fun tryResolveDoH(hostname: String, dohUrl: String): List<InetAddress> {
            return try {
                val url = "$dohUrl?name=$hostname&type=A"
                val request = Request.Builder()
                    .url(url)
                    .header("Accept", "application/dns-json")
                    .build()

                val response = dohClient.newCall(request).execute()
                val body = response.use { it.body?.string() } ?: return emptyList()
                parseDnsJsonResponse(body)
            } catch (e: Exception) {
                Log.d(TAG, "DoH provider $dohUrl failed for $hostname: ${e.message}")
                emptyList()
            }
        }

        /**
         * Minimal JSON parser for DNS-over-HTTPS JSON responses.
         * Extracts IPv4 (A) and IPv6 (AAAA) addresses from the "Answer" section.
         */
        private fun parseDnsJsonResponse(json: String): List<InetAddress> {
            val addresses = mutableListOf<InetAddress>()
            try {
                val jsonObject = JSONObject(json)
                val answerArray = jsonObject.optJSONArray("Answer") ?: return emptyList()
                for (i in 0 until answerArray.length()) {
                    val obj = answerArray.getJSONObject(i)
                    val type = obj.getInt("type")
                    // type 1 = A-record (IPv4), type 28 = AAAA-record (IPv6)
                    if (type == 1 || type == 28) {
                        addresses.add(InetAddress.getByName(obj.getString("data")))
                    }
                }
            } catch (_: Exception) {}
            return addresses
        }
    }

    // =========================================================================
    // 5. CONSCRYPT SSL — Chrome-like TLS configuration
    // =========================================================================

    /**
     * Create a trust-all SSLSocketFactory using Conscrypt (BoringSSL).
     * This is only used for direct connections to Telegram IPs when the SNI
     * doesn't match the IP's certificate (ssl.CERT_NONE equivalent).
     */
    fun createTrustAllConscryptSslContext(): Pair<javax.net.ssl.SSLSocketFactory, X509TrustManager> {
        val trustAllManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        return createSslContext(trustAllManager)
    }

    /**
     * Create an SSLSocketFactory using Conscrypt with system trust validation.
     * Prevents MITM attacks when connecting to CF proxy domains or GitHub.
     */
    fun createSystemConscryptSslContext(): Pair<javax.net.ssl.SSLSocketFactory, X509TrustManager> {
        val factory = javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
        )
        factory.init(null as java.security.KeyStore?)
        val systemTrustManager = factory.trustManagers.first { it is X509TrustManager } as X509TrustManager
        return createSslContext(systemTrustManager)
    }

    private fun createSslContext(trustManager: X509TrustManager): Pair<javax.net.ssl.SSLSocketFactory, X509TrustManager> {
        val sslContext = try {
            SSLContext.getInstance("TLS", Conscrypt.newProvider())
        } catch (e: Exception) {
            SSLContext.getInstance("TLS")
        }
        sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
        return Pair(sslContext.socketFactory, trustManager)
    }
}
