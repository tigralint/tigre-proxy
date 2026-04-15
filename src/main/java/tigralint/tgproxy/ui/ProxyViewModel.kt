package tigralint.tgproxy.ui

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import tigralint.tgproxy.proxy.ProxyConfig
import tigralint.tgproxy.proxy.ProxyStats
import tigralint.tgproxy.service.ProxyForegroundService
import tigralint.tgproxy.service.ProxyForegroundService.ProxyStatus
import tigralint.tgproxy.util.BatteryOptimization
import tigralint.tgproxy.util.ConfigStorage

/**
 * ViewModel for the proxy UI.
 *
 * Survives configuration changes (rotation, theme switch) unlike Activity-level state.
 * Owns the service binding lifecycle — binds in init, unbinds in onCleared().
 *
 * Design decisions:
 * - Uses flatMapLatest on the service reference to automatically switch between
 *   "no service" (defaults) and "bound service" (live data) states.
 * - Config is loaded once from SharedPreferences and kept in memory.
 */
class ProxyViewModel(application: Application) : AndroidViewModel(application) {

    // --- Config ---
    private val _config = MutableStateFlow(ConfigStorage.load(application))
    val config: StateFlow<ProxyConfig> = _config.asStateFlow()

    // --- Battery ---
    private val _isBatteryOptimized = MutableStateFlow(true)
    val isBatteryOptimized: StateFlow<Boolean> = _isBatteryOptimized.asStateFlow()

    private val _hasAutoStart = MutableStateFlow(false)
    val hasAutoStart: StateFlow<Boolean> = _hasAutoStart.asStateFlow()

    // --- Service binding ---
    private val _service = MutableStateFlow<ProxyForegroundService?>(null)
    private var isBound = false

    /**
     * Proxy status: derived from the bound service's StateFlow.
     * When service is null (unbound), defaults to STOPPED.
     */
    val status: StateFlow<ProxyStatus> = _service
        .flatMapLatest { svc -> svc?.status ?: flowOf(ProxyStatus.STOPPED) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ProxyStatus.STOPPED)

    /**
     * Stats snapshot: derived from the bound service's ProxyStats StateFlow.
     * When service is null, returns empty snapshot.
     */
    val stats: StateFlow<ProxyStats.Snapshot> = _service
        .flatMapLatest { svc -> svc?.stats?.snapshot ?: flowOf(ProxyStats.Snapshot()) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ProxyStats.Snapshot())

    /**
     * Proxy link: reactive StateFlow derived from status + service.
     * Automatically updates when status changes to RUNNING or service binds.
     * Must be a StateFlow (not a plain getter) so Compose observes changes.
     */
    val proxyLink: StateFlow<String> = kotlinx.coroutines.flow.combine(
        status,
        _service
    ) { currentStatus, svc ->
        if (currentStatus == ProxyStatus.RUNNING && svc != null) {
            svc.getProxyLink()
        } else ""
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), "")

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val service = (binder as ProxyForegroundService.ProxyBinder).getService()
            _service.value = service
            // Sync config from service (it may have been loaded earlier)
            _config.value = service.config
            isBound = true
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            _service.value = null
            isBound = false
        }
    }

    init {
        bindService()
    }

    // --- Public actions ---

    fun toggleProxy() {
        val ctx = getApplication<Application>()
        val service = _service.value ?: return
        val currentStatus = service.status.value

        if (currentStatus == ProxyStatus.RUNNING) {
            val stopIntent = Intent(ctx, ProxyForegroundService::class.java).apply {
                action = ProxyForegroundService.ACTION_STOP
            }
            ctx.startService(stopIntent)
        } else {
            service.updateConfig(_config.value)
            val startIntent = Intent(ctx, ProxyForegroundService::class.java).apply {
                action = ProxyForegroundService.ACTION_START
            }
            ctx.startForegroundService(startIntent)
        }
    }

    fun updateConfig(newConfig: ProxyConfig) {
        _config.value = newConfig
        val ctx = getApplication<Application>()
        ConfigStorage.save(ctx, newConfig)
        _service.value?.updateConfig(newConfig)
    }

    fun refreshBatteryStatus() {
        val ctx = getApplication<Application>()
        _isBatteryOptimized.value = BatteryOptimization.isBatteryOptimized(ctx)
        _hasAutoStart.value = BatteryOptimization.hasAutoStartSettings(ctx)
    }

    fun requestDisableBatteryOptimization(context: Context) {
        BatteryOptimization.requestDisableBatteryOptimization(context)
    }

    fun requestAutoStart(context: Context) {
        BatteryOptimization.requestAutoStart(context)
    }

    // --- Service lifecycle ---

    fun bindService() {
        if (isBound) return
        val ctx = getApplication<Application>()
        val intent = Intent(ctx, ProxyForegroundService::class.java)
        ctx.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    fun unbindService() {
        if (!isBound) return
        val ctx = getApplication<Application>()
        try {
            ctx.unbindService(serviceConnection)
        } catch (_: Exception) {}
        isBound = false
    }

    override fun onCleared() {
        unbindService()
        super.onCleared()
    }
}
