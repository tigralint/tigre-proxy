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
        // Only DC2 and DC4 are served by the Telegram WS gateway.
        // DC1/3/5 do NOT work via this gateway — they return 302 redirect loops.
        // Traffic for DC1/3/5 automatically falls through to CF proxy or TCP fallback.
        2 to "149.154.167.220",
        4 to "149.154.167.220"
    ),
    var bufferSize: Int = 256 * 1024,
    var poolSize: Int = 8,  // 8 pre-connected WS per DC (4 was too low for media bursts)
    var fallbackCfProxy: Boolean = true,
    var fallbackCfProxyPriority: Boolean = true,
    var cfProxyUserDomain: String = "",
    var cfProxyDomains: MutableList<String> = mutableListOf(),
    var activeCfProxyDomain: String = "",
    var fakeTlsDomain: String = "",
    // Anti-DPI / TSPU bypass settings
    var antiDpiEnabled: Boolean = true,      // Enable Chrome-like TLS fingerprint + padding
    var dohEnabled: Boolean = true,           // DNS-over-HTTPS for ECH support
    var dohServer: String = "https://1.1.1.1/dns-query",
    var trafficShaping: Boolean = true,       // Micro-delays during handshake to blur timing
    var tlsRecordSplitting: Boolean = true,   // Split ClientHello TLS records to hide SNI from DPI
    var wsPoolMaxAgeMs: Long = 120_000L,      // Max age for pooled WebSocket connections
    var readBufferSize: Int = 65536,          // TCP read buffer size for Bridge

) {
    /** Initialize CF proxy domains on start. */
    fun initCfProxyDomains() {
        if (cfProxyUserDomain.isNotEmpty()) {
            cfProxyDomains = mutableListOf(cfProxyUserDomain)
            activeCfProxyDomain = cfProxyUserDomain
        } else if (cfProxyDomains.isEmpty()) {
            cfProxyDomains = CfProxyManager.defaultDomains.toMutableList()
            activeCfProxyDomain = cfProxyDomains.random()
        }
    }

    companion object {
        fun generateSecret(): String {
            val bytes = ByteArray(16)
            SecureRandom().nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
    }

    /**
     * Generate tg://proxy link for this configuration.
     * Uses 'ee' prefix for FakeTLS (modern padded format) or 'dd' for standard.
     */
    fun toTgLink(actualHost: String): String {
        val type = if (fakeTlsDomain.isNotEmpty()) "ee" else "dd"
        val domainHex = if (fakeTlsDomain.isNotEmpty()) {
            fakeTlsDomain.toByteArray(Charsets.US_ASCII).joinToString("") { "%02x".format(it) }
        } else ""
        
        return "tg://proxy?server=$actualHost&port=$port&secret=$type$secret$domainHex"
    }
}
