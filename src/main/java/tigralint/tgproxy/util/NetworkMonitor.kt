package tigralint.tgproxy.util

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Monitors network connectivity changes (Wi-Fi ↔ LTE).
 * Can trigger proxy reconnection when network changes.
 */
class NetworkMonitor(context: Context) {

    companion object {
        private const val TAG = "NetworkMonitor"
    }

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val _isConnected = MutableStateFlow(true)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()

    private val _networkType = MutableStateFlow("Unknown")
    val networkType: StateFlow<String> = _networkType.asStateFlow()

    var onNetworkChanged: (() -> Unit)? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Network available")
            val wasConnected = _isConnected.value
            _isConnected.value = true
            updateNetworkType()
            if (!wasConnected) {
                onNetworkChanged?.invoke()
            }
        }

        override fun onLost(network: Network) {
            Log.i(TAG, "Network lost")
            _isConnected.value = false
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            val oldType = _networkType.value
            updateNetworkType()
            if (oldType != _networkType.value) {
                Log.i(TAG, "Network type changed: $oldType → ${_networkType.value}")
                onNetworkChanged?.invoke()
            }
        }
    }

    fun start() {
        stop() // Prevent multiple registrations
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, callback)
        updateNetworkType()
    }

    fun stop() {
        try {
            connectivityManager.unregisterNetworkCallback(callback)
        } catch (_: Exception) {}
    }

    private fun updateNetworkType() {
        val network = connectivityManager.activeNetwork
        val capabilities = network?.let { connectivityManager.getNetworkCapabilities(it) }
        _networkType.value = when {
            capabilities == null -> "None"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Other"
        }
    }
}
