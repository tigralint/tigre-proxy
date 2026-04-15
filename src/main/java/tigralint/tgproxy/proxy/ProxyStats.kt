package tigralint.tgproxy.proxy

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Thread-safe proxy statistics.
 * Port of stats.py with Android-friendly StateFlow exposure.
 */
class ProxyStats {
    val connectionsTotal = AtomicInteger(0)
    val connectionsActive = AtomicInteger(0)
    val connectionsWs = AtomicInteger(0)
    val connectionsTcpFallback = AtomicInteger(0)
    val connectionsCfProxy = AtomicInteger(0)
    val connectionsBad = AtomicInteger(0)
    val connectionsMasked = AtomicInteger(0)
    val wsErrors = AtomicInteger(0)
    val bytesUp = AtomicLong(0)
    val bytesDown = AtomicLong(0)
    val poolHits = AtomicInteger(0)
    val poolMisses = AtomicInteger(0)

    // StateFlow for UI observation
    private val _snapshot = MutableStateFlow(Snapshot())
    val snapshot: StateFlow<Snapshot> = _snapshot.asStateFlow()

    data class Snapshot(
        val connectionsTotal: Int = 0,
        val connectionsActive: Int = 0,
        val connectionsWs: Int = 0,
        val connectionsTcpFallback: Int = 0,
        val connectionsCfProxy: Int = 0,
        val connectionsBad: Int = 0,
        val connectionsMasked: Int = 0,
        val wsErrors: Int = 0,
        val bytesUp: Long = 0,
        val bytesDown: Long = 0,
        val poolHits: Int = 0,
        val poolMisses: Int = 0
    )

    /** Update the StateFlow snapshot — call periodically or on significant changes. */
    fun publishSnapshot() {
        _snapshot.value = Snapshot(
            connectionsTotal = connectionsTotal.get(),
            connectionsActive = connectionsActive.get(),
            connectionsWs = connectionsWs.get(),
            connectionsTcpFallback = connectionsTcpFallback.get(),
            connectionsCfProxy = connectionsCfProxy.get(),
            connectionsBad = connectionsBad.get(),
            connectionsMasked = connectionsMasked.get(),
            wsErrors = wsErrors.get(),
            bytesUp = bytesUp.get(),
            bytesDown = bytesDown.get(),
            poolHits = poolHits.get(),
            poolMisses = poolMisses.get()
        )
    }

    fun summary(): String {
        val poolTotal = poolHits.get() + poolMisses.get()
        val poolStr = if (poolTotal > 0) "${poolHits.get()}/$poolTotal" else "n/a"
        return "total=${connectionsTotal.get()} " +
                "active=${connectionsActive.get()} " +
                "ws=${connectionsWs.get()} " +
                "tcp_fb=${connectionsTcpFallback.get()} " +
                "cf=${connectionsCfProxy.get()} " +
                "bad=${connectionsBad.get()} " +
                "err=${wsErrors.get()} " +
                "pool=$poolStr " +
                "up=${Constants.humanBytes(bytesUp.get())} " +
                "down=${Constants.humanBytes(bytesDown.get())}"
    }

    fun reset() {
        connectionsTotal.set(0)
        connectionsActive.set(0)
        connectionsWs.set(0)
        connectionsTcpFallback.set(0)
        connectionsCfProxy.set(0)
        connectionsBad.set(0)
        connectionsMasked.set(0)
        wsErrors.set(0)
        bytesUp.set(0)
        bytesDown.set(0)
        poolHits.set(0)
        poolMisses.set(0)
        publishSnapshot()
    }
}
