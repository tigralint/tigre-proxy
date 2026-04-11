package tigralint.tgproxy.proxy

import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import java.util.ArrayDeque

/**
 * WebSocket connection pool, pre-creates connections per (DC, isMedia) pair.
 * Port of _WsPool from tg_ws_proxy.py.
 */
class WsPool(
    private val config: ProxyConfig,
    private val stats: ProxyStats,
    private val scope: CoroutineScope
) {
    companion object {
        private const val TAG = "WsPool"
        private const val WS_POOL_MAX_AGE_MS = 120_000L

        /**
         * Get WebSocket domain names for a given DC.
         * Port of _ws_domains from tg_ws_proxy.py.
         */
        fun wsDomains(dc: Int, isMedia: Boolean?): List<String> {
            val effectiveDc = if (dc == 203) 2 else dc
            return if (isMedia == null || isMedia) {
                listOf("kws${effectiveDc}-1.web.telegram.org", "kws${effectiveDc}.web.telegram.org")
            } else {
                listOf("kws${effectiveDc}.web.telegram.org", "kws${effectiveDc}-1.web.telegram.org")
            }
        }
    }

    private data class PoolKey(val dc: Int, val isMedia: Boolean)
    private data class PoolEntry(val ws: ProxyWebSocket, val createdAt: Long)

    private val idle = ConcurrentHashMap<PoolKey, ArrayDeque<PoolEntry>>()
    private val refilling = ConcurrentHashMap.newKeySet<PoolKey>()

    /**
     * Get a WebSocket connection from the pool, or null if none available.
     */
    suspend fun get(dc: Int, isMedia: Boolean, targetIp: String, domains: List<String>): ProxyWebSocket? {
        val key = PoolKey(dc, isMedia)
        val now = System.currentTimeMillis()

        val bucket = idle.getOrPut(key) { ArrayDeque() }
        synchronized(bucket) {
            while (bucket.isNotEmpty()) {
                val entry = bucket.poll() ?: break
                val age = now - entry.createdAt
                if (age > WS_POOL_MAX_AGE_MS || entry.ws.isClosed) {
                    scope.launch { entry.ws.close() }
                    continue
                }
                stats.poolHits.incrementAndGet()
                Log.d(TAG, "WS pool hit DC$dc${if (isMedia) "m" else ""} (age=${age}ms, left=${bucket.size})")
                scheduleRefill(key, targetIp, domains)
                return entry.ws
            }
        }

        stats.poolMisses.incrementAndGet()
        scheduleRefill(key, targetIp, domains)
        return null
    }

    private fun scheduleRefill(key: PoolKey, targetIp: String, domains: List<String>) {
        if (!refilling.add(key)) return
        scope.launch(Dispatchers.IO) {
            try {
                refill(key, targetIp, domains)
            } finally {
                refilling.remove(key)
            }
        }
    }

    private suspend fun refill(key: PoolKey, targetIp: String, domains: List<String>) {
        val bucket = idle.getOrPut(key) { ArrayDeque() }
        val needed = config.poolSize - synchronized(bucket) { bucket.size }
        if (needed <= 0) return

        val results = (0 until needed).map {
            scope.async(Dispatchers.IO) { connectOne(targetIp, domains) }
        }

        for (deferred in results) {
            try {
                val ws = deferred.await()
                if (ws != null) {
                    synchronized(bucket) {
                        bucket.add(PoolEntry(ws, System.currentTimeMillis()))
                    }
                }
            } catch (_: Exception) {}
        }

        Log.d(TAG, "WS pool refilled DC${key.dc}${if (key.isMedia) "m" else ""}: ${synchronized(bucket) { bucket.size }} ready")
    }

    private suspend fun connectOne(targetIp: String, domains: List<String>): ProxyWebSocket? {
        for (domain in domains) {
            try {
                return ProxyWebSocket.connect(targetIp, domain, timeoutMs = 8000)
            } catch (e: WsHandshakeError) {
                if (e.isRedirect) continue
                return null
            } catch (_: Exception) {
                return null
            }
        }
        return null
    }

    /**
     * Warmup the pool by pre-connecting to all configured DCs.
     */
    fun warmup(dcRedirects: Map<Int, String>) {
        for ((dc, targetIp) in dcRedirects) {
            for (isMedia in listOf(false, true)) {
                val domains = wsDomains(dc, isMedia)
                scheduleRefill(PoolKey(dc, isMedia), targetIp, domains)
            }
        }
        Log.i(TAG, "WS pool warmup started for ${dcRedirects.size} DC(s)")
    }

    fun reset() {
        idle.values.forEach { bucket ->
            synchronized(bucket) {
                while (bucket.isNotEmpty()) {
                    bucket.poll()?.ws?.close()
                }
            }
        }
        idle.clear()
        refilling.clear()
    }
}
