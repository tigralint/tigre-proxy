package tigralint.tgproxy.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
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

/**
 * Foreground service that runs the MTProto proxy.
 * Keeps the proxy alive even when the app is in the background.
 */
class ProxyForegroundService : Service() {

    companion object {
        const val ACTION_START = "tigralint.tgproxy.START"
        const val ACTION_STOP = "tigralint.tgproxy.STOP"
        private const val NOTIFICATION_ID = 1
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
        startForeground(NOTIFICATION_ID, buildNotification("Starting proxy..."))
        acquireWakeLock()

        val server = TcpServer(config, _stats)
        tcpServer = server

        serverJob = serviceScope?.launch {
            try {
                _status.value = ProxyStatus.RUNNING
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
        releaseWakeLock()
        updateNotification("Proxy stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopProxy()
        serviceScope?.cancel()
        super.onDestroy()
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

        return NotificationCompat.Builder(this, TgProxyApp.NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_media_pause, "Stop", stopIntent)
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

    private fun acquireWakeLock() {
        val pm = getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "TgProxy::ProxyWakeLock"
        ).apply {
            acquire(10 * 60 * 60 * 1000L) // 10 hours max
        }
        
        val wm = getSystemService(android.net.wifi.WifiManager::class.java)
        wifiLock = wm?.createWifiLock(
            android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF,
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
        val ftls = config.fakeTlsDomain
        return if (ftls.isNotEmpty()) {
            val domainHex = ftls.toByteArray(Charsets.US_ASCII)
                .joinToString("") { "%02x".format(it) }
            "tg://proxy?server=${config.host}&port=${config.port}&secret=ee${config.secret}$domainHex"
        } else {
            "tg://proxy?server=${config.host}&port=${config.port}&secret=dd${config.secret}"
        }
    }
}
