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
        1 to "149.154.175.50",
        2 to "149.154.167.220",
        3 to "149.154.175.100",
        4 to "91.108.4.218",
        5 to "91.108.56.143"
    ),
    var bufferSize: Int = 256 * 1024,
    var poolSize: Int = 4,
    var fallbackCfProxy: Boolean = true,
    var fallbackCfProxyPriority: Boolean = false,
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
