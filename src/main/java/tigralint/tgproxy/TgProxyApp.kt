package tigralint.tgproxy

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.util.Log
import org.conscrypt.Conscrypt
import java.security.Security

class TgProxyApp : Application() {

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "tg_proxy_channel"
        private const val TAG = "TgProxyApp"
    }

    override fun onCreate() {
        super.onCreate()
        installConscrypt()
        createNotificationChannel()
    }

    /**
     * Install Conscrypt (BoringSSL) as the primary security provider.
     * This changes the TLS fingerprint of ALL connections (OkHttp, etc.)
     * from "typical Java/Android" to "Chrome-like BoringSSL", making
     * the proxy traffic indistinguishable from Chrome for DPI/TSPU systems.
     */
    private fun installConscrypt() {
        try {
            val provider = Conscrypt.newProvider()
            val pos = Security.insertProviderAt(provider, 1)
            if (pos != -1) {
                Log.i(TAG, "Conscrypt (BoringSSL) installed as primary TLS provider at position $pos")
            } else {
                Log.w(TAG, "Conscrypt provider already installed")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to install Conscrypt: ${e.message}")
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
}
