package tigralint.tgproxy.proxy

import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.SecureRandom

/**
 * Proxy configuration.
 * Port of config.py ProxyConfig dataclass + CF domain decode.
 */
data class ProxyConfig(
    var port: Int = 1443,
    var host: String = "127.0.0.1",
    var secret: String = generateSecret(),
    var dcRedirects: MutableMap<Int, String> = mutableMapOf(
        2 to "149.154.167.220",
        4 to "149.154.167.220"
    ),
    var bufferSize: Int = 256 * 1024,
    var poolSize: Int = 4,
    var fallbackCfProxy: Boolean = true,
    var fallbackCfProxyPriority: Boolean = true,
    var cfProxyUserDomain: String = "",
    var cfProxyDomains: MutableList<String> = mutableListOf(),
    var activeCfProxyDomain: String = "",
    var fakeTlsDomain: String = "",
) {
    companion object {
        private const val CFPROXY_DOMAINS_URL =
            "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

        private val httpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .build()
        }

        /** Domain suffix for CF proxy decoding. */
        private val SUFFIX = buildString {
            append(46.toChar())  // .
            append(99.toChar())  // c
            append(111.toChar()) // o
            append(46.toChar())  // .
            append(117.toChar()) // u
            append(107.toChar()) // k
        }

        private val ENCODED_DEFAULTS = listOf(
            "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com"
        )

        /** Decode CF proxy domain from encoded form. Port of _dd() from config.py. */
        fun decodeDomain(s: String): String {
            if (!s.endsWith(".com")) return s
            val prefix = s.dropLast(4)
            val n = prefix.count { it.isLetter() }
            val decoded = prefix.map { c ->
                if (c.isLetter()) {
                    val base = if (c > '`') 97 else 65
                    ((c.code - base - n).mod(26) + base).toChar()
                } else c
            }.joinToString("")
            return decoded + SUFFIX
        }

        val DEFAULT_CF_DOMAINS: List<String> = ENCODED_DEFAULTS.map { decodeDomain(it) }

        fun generateSecret(): String {
            val bytes = ByteArray(16)
            SecureRandom().nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }

        /**
         * Fetch CF proxy domain list from GitHub.
         * @return decoded domain list, or empty on failure
         */
        fun fetchCfProxyDomains(): List<String> {
            return try {
                val random = (1..7).map { ('a'..'z').random() }.joinToString("")
                val request = Request.Builder()
                    .url("$CFPROXY_DOMAINS_URL?$random")
                    .header("User-Agent", "tg-ws-proxy-android")
                    .build()
                val response = httpClient.newCall(request).execute()
                val text = response.body?.string() ?: ""
                text.lines()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith('#') }
                    .map { decodeDomain(it) }
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    /** Initialize CF proxy domains on first start. */
    fun initCfProxyDomains() {
        if (cfProxyUserDomain.isNotEmpty()) {
            cfProxyDomains = mutableListOf(cfProxyUserDomain)
            activeCfProxyDomain = cfProxyUserDomain
        } else {
            cfProxyDomains = DEFAULT_CF_DOMAINS.toMutableList()
            activeCfProxyDomain = DEFAULT_CF_DOMAINS.random()
        }
    }
}
