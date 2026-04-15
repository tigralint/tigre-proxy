package tigralint.tgproxy.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.PowerManager
import android.content.pm.ServiceInfo
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import tigralint.tgproxy.MainActivity
import tigralint.tgproxy.R
import tigralint.tgproxy.TgProxyApp
import tigralint.tgproxy.proxy.ProxyConfig
import tigralint.tgproxy.proxy.ProxyStats
import tigralint.tgproxy.proxy.TcpServer
import tigralint.tgproxy.util.ConfigStorage

/**
 * Foreground service that runs the MTProto proxy.
 * Keeps the proxy alive even when the app is in the background.
 */
class ProxyForegroundService : Service() {

    companion object {
        const val ACTION_START = "tigralint.tgproxy.START"
        const val ACTION_STOP = "tigralint.tgproxy.STOP"
        private const val NOTIFICATION_ID = 1

        var isRunning = false
            private set

        fun requestTileUpdate(context: android.content.Context) {
            try {
                android.service.quicksettings.TileService.requestListeningState(
                    context,
                    android.content.ComponentName(context, ProxyTileService::class.java)
                )
            } catch (_: Exception) {}
        }
    }

    enum class ProxyStatus {
        STOPPED, STARTING, RUNNING, ERROR
    }

    private val binder = ProxyBinder()
    private var serviceScope: CoroutineScope? = null
    private var serverJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null

    private var tcpServer: TcpServer? = null
    var config: ProxyConfig = ProxyConfig()
        private set

    private val _status = MutableStateFlow(ProxyStatus.STOPPED)
    val status: StateFlow<ProxyStatus> = _status.asStateFlow()

    private val _stats = ProxyStats()
    val stats: ProxyStats get() = _stats

    inner class ProxyBinder : Binder() {
        fun getService(): ProxyForegroundService = this@ProxyForegroundService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        config = ConfigStorage.load(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startProxy()
            ACTION_STOP -> stopProxy()
        }
        return START_STICKY
    }

    fun updateConfig(newConfig: ProxyConfig) {
        config = newConfig
    }

    fun startProxy() {
        if (_status.value == ProxyStatus.RUNNING || _status.value == ProxyStatus.STARTING) return

        _status.value = ProxyStatus.STARTING
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification("Starting proxy..."),
            if (android.os.Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        )
        acquireWakeLock()

        val server = TcpServer(config, _stats)
        tcpServer = server

        serverJob = serviceScope?.launch {
            try {
                _status.value = ProxyStatus.RUNNING
                isRunning = true
                requestTileUpdate(this@ProxyForegroundService)
                updateNotification("Listening on ${config.host}:${config.port}")
                server.start()
            } catch (e: CancellationException) {
                // Normal stop
            } catch (e: Exception) {
                _status.value = ProxyStatus.ERROR
                updateNotification("Error: ${e.message}")
            } finally {
                if (_status.value != ProxyStatus.ERROR) {
                    _status.value = ProxyStatus.STOPPED
                }
            }
        }
    }

    fun stopProxy() {
        serverJob?.cancel()
        tcpServer?.stop()
        tcpServer = null
        _status.value = ProxyStatus.STOPPED
        isRunning = false
        requestTileUpdate(this)
        releaseWakeLock()
        updateNotification("Proxy stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopProxy()
        serviceScope?.cancel()
        serviceScope = null
        super.onDestroy()
    }

    /**
     * Called when the user swipes the app away from recents.
     * Ensures WakeLock is always released even if the system kills us.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        releaseWakeLock()
        super.onTaskRemoved(rootIntent)
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, ProxyForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val tgIntent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("tg://")).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val tgPendingIntent = PendingIntent.getActivity(
            this, 2, tgIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val btnStop = tigralint.tgproxy.util.Texts.stopProxy
        val btnTg = tigralint.tgproxy.util.Texts.openInTelegram

        return NotificationCompat.Builder(this, TgProxyApp.NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_media_pause, btnStop, stopIntent)
            .addAction(android.R.drawable.ic_menu_send, btnTg, tgPendingIntent)
            .setOngoing(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification(text: String) {
        try {
            val notification = buildNotification(text)
            val manager = getSystemService(android.app.NotificationManager::class.java)
            manager.notify(NOTIFICATION_ID, notification)
        } catch (_: Exception) {}
    }

    /**
     * Acquire WakeLock and WifiLock to keep the proxy running in background.
     *
     * FIXED: No hardcoded timeout — lock is held until explicitly released.
     * Release is guaranteed by stopProxy(), onDestroy(), and onTaskRemoved().
     *
     * Uses WIFI_MODE_FULL_LOW_LATENCY on Android 12+ for optimal
     * WiFi performance with low-latency proxy traffic.
     */
    private fun acquireWakeLock() {
        val pm = getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "TgProxy::ProxyWakeLock"
        ).apply {
            setReferenceCounted(false)
            acquire()
        }
        
        val wm = getSystemService(android.net.wifi.WifiManager::class.java)
        @Suppress("DEPRECATION")
        val wifiMode = if (android.os.Build.VERSION.SDK_INT >= 31) {
            android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
        } else {
            android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
        }
        wifiLock = wm?.createWifiLock(
            wifiMode,
            "TgProxy::ProxyWifiLock"
        )?.apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) it.release()
            }
        } catch (_: Exception) {}
        wakeLock = null
        
        try {
            wifiLock?.let {
                if (it.isHeld) it.release()
            }
        } catch (_: Exception) {}
        wifiLock = null
    }

    /**
     * Generate the tg:// proxy link for sharing.
     */
    fun getProxyLink(): String {
        return config.toTgLink(config.host)
    }
}
