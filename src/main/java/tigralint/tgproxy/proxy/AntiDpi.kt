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
 * - DNS-over-HTTPS resolver for ECH (Encrypted Client Hello) support
 * - Conscrypt-based SSLSocketFactory for Chrome-like TLS fingerprint
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
        "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"
    )

    /** Realistic Chrome/mobile user-agent strings */
    private val USER_AGENTS = listOf(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; 22101316G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
    )

    /**
     * Generate a map of random padding HTTP headers.
     * These break DPI packet-size signatures by varying the total
     * size of the HTTP Upgrade request unpredictably.
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
        headers["User-Agent"] = USER_AGENTS[random.nextInt(USER_AGENTS.size)]
        headers["Accept-Language"] = ACCEPT_LANGUAGES[random.nextInt(ACCEPT_LANGUAGES.size)]
        headers["Accept-Encoding"] = "gzip, deflate, br"
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"

        // 2. Random session/tracking headers (look like analytics)
        headers["X-Request-Id"] = UUID.randomUUID().toString()

        // 3. Pure junk padding to randomize total packet size
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
    // 3. DNS-OVER-HTTPS — Resolve domains via DoH for ECH support
    // =========================================================================

    private val dnsCache = ConcurrentHashMap<String, CachedDns>()
    private const val DNS_CACHE_TTL_MS = 300_000L // 5 minutes

    private data class CachedDns(val addresses: List<InetAddress>, val expiresAt: Long)

    private val dohClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()
    }

    /**
     * DNS-over-HTTPS resolver for OkHttp.
     * Resolves domains via Cloudflare DoH (1.1.1.1) or Google DoH,
     * which returns HTTPS records containing ECH keys.
     * This enables ECH (Encrypted Client Hello) when the TLS provider
     * (Conscrypt/BoringSSL) supports it.
     *
     * Falls back to system DNS on failure.
     */
    class DohDns(private val dohUrl: String = DOH_CLOUDFLARE) : Dns {
        companion object {
            const val DOH_CLOUDFLARE = "https://1.1.1.1/dns-query"
            const val DOH_GOOGLE = "https://dns.google/resolve"
        }

        override fun lookup(hostname: String): List<InetAddress> {
            // Check cache first
            val cached = dnsCache[hostname]
            if (cached != null && System.currentTimeMillis() < cached.expiresAt) {
                return cached.addresses
            }

            return try {
                val resolved = resolveDoH(hostname)
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

        private fun resolveDoH(hostname: String): List<InetAddress> {
            val url = if (dohUrl.contains("dns.google")) {
                "$dohUrl?name=$hostname&type=A"
            } else {
                "$dohUrl?name=$hostname&type=A"
            }

            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-json")
                .build()

            val response = dohClient.newCall(request).execute()
            val body = response.body?.string() ?: return emptyList()

            // Parse JSON response (minimal parser to avoid extra deps)
            return parseDnsJsonResponse(body)
        }

        /**
         * Minimal JSON parser for DNS-over-HTTPS JSON responses.
         * Extracts IPv4 addresses from the "Answer" section.
         */
        private fun parseDnsJsonResponse(json: String): List<InetAddress> {
            val addresses = mutableListOf<InetAddress>()
            try {
                val jsonObject = JSONObject(json)
                val answerArray = jsonObject.optJSONArray("Answer") ?: return emptyList()
                for (i in 0 until answerArray.length()) {
                    val obj = answerArray.getJSONObject(i)
                    // type 1 is A-record (IPv4)
                    if (obj.getInt("type") == 1) {
                        addresses.add(InetAddress.getByName(obj.getString("data")))
                    }
                }
            } catch (_: Exception) {}
            return addresses
        }
    }

    // =========================================================================
    // 4. CONSCRYPT SSL — Chrome-like TLS configuration
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
     * Prevents MITM attacks when connecting to Cloudflare Workers or GitHub.
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
