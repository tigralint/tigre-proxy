package tigralint.tgproxy.proxy

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Manages public Cloudflare proxy domains.
 * Handles decoding of "obfuscated" domains and fetching updates from GitHub.
 */
object CfProxyManager {
    private const val TAG = "CfProxyManager"
    
    const val CFPROXY_DOMAINS_URL =
        "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

    private val httpClient by lazy {
        val (sslFactory, trustManager) = AntiDpi.createSystemConscryptSslContext()
        OkHttpClient.Builder()
            .sslSocketFactory(sslFactory, trustManager)
            .dns(AntiDpi.DohDns())
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    /** Domain suffix for CF proxy decoding (.co.uk). */
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

    /** 
     * Decode CF proxy domain from encoded form. 
     * Port of _dd() from config.py in tg-ws-proxy. 
     */
    fun decodeDomain(s: String): String {
        if (!s.endsWith(".com")) return s
        val prefix = s.dropLast(4)
        val n = prefix.count { it.isLetter() }
        val decoded = prefix.map { c ->
            if (c.isLetter()) {
                val base = if (c > '`') 97 else 65
                val code = c.code - base
                val shifted = (code - n).let { if (it < 0) (it % 26 + 26) % 26 else it % 26 }
                (shifted + base).toChar()
            } else c
        }.joinToString("")
        return decoded + SUFFIX
    }

    val defaultDomains: List<String> = ENCODED_DEFAULTS.map { decodeDomain(it) }

    /**
     * Fetch CF proxy domain list from GitHub.
     */
    fun fetchDomains(): List<String> {
        return try {
            val random = (1..7).map { ('a'..'z').random() }.joinToString("")
            val request = Request.Builder()
                .url("$CFPROXY_DOMAINS_URL?$random")
                .header("User-Agent", "tg-ws-proxy-android")
                .build()
            
            val response = httpClient.newCall(request).execute()
            if (!response.isSuccessful) return emptyList()
            
            val text = response.body?.string() ?: ""
            text.lines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith('#') }
                .map { decodeDomain(it) }
                .distinct()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch CF domains: ${e.message}")
            emptyList()
        }
    }
}
