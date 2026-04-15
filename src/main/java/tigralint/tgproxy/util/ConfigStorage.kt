package tigralint.tgproxy.util

import android.content.Context
import tigralint.tgproxy.proxy.ProxyConfig

/**
 * Helper for persisting ProxyConfig to SharedPreferences.
 */
object ConfigStorage {
    private const val PREFS_NAME = "TgProxyConfig"
    private const val KEY_PORT = "port"
    private const val KEY_SECRET = "secret"
    private const val KEY_FAKETLS = "faketls"
    private const val KEY_ANTI_BLOCK = "anti_block"
    private const val KEY_CF_DOMAIN = "cf_domain"
    private const val KEY_DC_MAPPINGS = "dc_mappings"
    private const val KEY_ANTI_DPI = "anti_dpi"
    private const val KEY_DOH = "doh_enabled"
    private const val KEY_TRAFFIC_SHAPING = "traffic_shaping"
    private const val KEY_TLS_RECORD_SPLITTING = "tls_record_splitting"

    fun save(context: Context, config: ProxyConfig) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().apply {
            putInt(KEY_PORT, config.port)
            putString(KEY_SECRET, config.secret)
            putString(KEY_FAKETLS, config.fakeTlsDomain)
            putBoolean(KEY_ANTI_BLOCK, config.fallbackCfProxy)
            putString(KEY_CF_DOMAIN, config.cfProxyUserDomain)
            
            // Serialize DC mappings: "2:IP,4:IP"
            val mappings = config.dcRedirects.entries.joinToString(",") { "${it.key}:${it.value}" }
            putString(KEY_DC_MAPPINGS, mappings)
            
            // Anti-DPI settings
            putBoolean(KEY_ANTI_DPI, config.antiDpiEnabled)
            putBoolean(KEY_DOH, config.dohEnabled)
            putBoolean(KEY_TRAFFIC_SHAPING, config.trafficShaping)
            putBoolean(KEY_TLS_RECORD_SPLITTING, config.tlsRecordSplitting)
            
            apply()
        }
    }

    fun load(context: Context): ProxyConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.contains(KEY_SECRET)) {
            val defaultConfig = ProxyConfig()
            save(context, defaultConfig)
            return defaultConfig
        }

        val config = ProxyConfig()
        config.port = prefs.getInt(KEY_PORT, 1443)
        config.secret = prefs.getString(KEY_SECRET, config.secret) ?: config.secret
        config.fakeTlsDomain = prefs.getString(KEY_FAKETLS, "") ?: ""
        config.fallbackCfProxy = prefs.getBoolean(KEY_ANTI_BLOCK, true)
        config.cfProxyUserDomain = prefs.getString(KEY_CF_DOMAIN, "") ?: ""
        
        val mappingsStr = prefs.getString(KEY_DC_MAPPINGS, "")
        if (!mappingsStr.isNullOrEmpty()) {
            val map = mutableMapOf<Int, String>()
            mappingsStr.split(",").forEach { pair ->
                val parts = pair.split(":")
                if (parts.size == 2) {
                    parts[0].toIntOrNull()?.let { dc ->
                        map[dc] = parts[1]
                    }
                }
            }
            if (map.isNotEmpty()) {
                // Merge: user-saved DCs override defaults, but keep defaults for unsaved DCs
                val merged = config.dcRedirects.toMutableMap()
                merged.putAll(map)
                config.dcRedirects = merged
            }
        }
        
        // Anti-DPI settings
        config.antiDpiEnabled = prefs.getBoolean(KEY_ANTI_DPI, true)
        config.dohEnabled = prefs.getBoolean(KEY_DOH, true)
        config.trafficShaping = prefs.getBoolean(KEY_TRAFFIC_SHAPING, true)
        config.tlsRecordSplitting = prefs.getBoolean(KEY_TLS_RECORD_SPLITTING, true)
        
        // Migration: Replace raw DC IPs (which don't support WebSocket) with WS gateway
        // IMPORTANT: Only DC2 and DC4 are supported by the WS gateway.
        // DC1/3/5 cause redirect loops and must be removed.
        val WS_GATEWAY = "149.154.167.220"
        val RAW_DC_IPS = setOf(
            "149.154.175.50", "149.154.167.50", "149.154.175.100",
            "149.154.167.91", "91.108.4.218", "91.108.56.100", "91.108.56.143"
        )
        for ((dc, ip) in config.dcRedirects.toMap()) {
            if (ip in RAW_DC_IPS) {
                if (dc == 2 || dc == 4) {
                    config.dcRedirects[dc] = WS_GATEWAY
                } else {
                    // DC1/3/5 can't use WS gateway — remove to trigger fallback
                    config.dcRedirects.remove(dc)
                }
            }
        }
        // Also remove DC1/3/5 if they point to WS gateway (left over from old builds)
        for (dc in listOf(1, 3, 5)) {
            if (config.dcRedirects[dc] == WS_GATEWAY) {
                config.dcRedirects.remove(dc)
            }
        }

        return config
    }
}
