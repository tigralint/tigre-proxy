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
                config.dcRedirects = map
            }
        }
        
        return config
    }
}
