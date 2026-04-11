package tigralint.tgproxy.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

object BatteryOptimization {

    /**
     * Check if battery optimization is currently ACTIVE for our app
     * (i.e., we are NOT whitelisted — which is bad for background proxy).
     */
    fun isBatteryOptimized(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return !pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /**
     * Launch the system dialog to request disabling battery optimization.
     */
    fun requestDisableBatteryOptimization(context: Context) {
        try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } catch (_: Exception) {
            // Fallback: open battery optimization settings
            try {
                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
            } catch (_: Exception) {}
        }
    }

    private val autoStartIntents = listOf(
        // Huawei
        Intent().setComponent(android.content.ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")),
        Intent().setComponent(android.content.ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity")),
        // Xiaomi
        Intent().setComponent(android.content.ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
        // Oppo
        Intent().setComponent(android.content.ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")),
        Intent().setComponent(android.content.ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")),
        Intent().setComponent(android.content.ComponentName("com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity")),
        // Vivo
        Intent().setComponent(android.content.ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity")),
        Intent().setComponent(android.content.ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")),
        // Asus
        Intent().setComponent(android.content.ComponentName("com.asus.mobilemanager", "com.asus.mobilemanager.entry.FunctionActivity")),
        Intent().setComponent(android.content.ComponentName("com.asus.mobilemanager", "com.asus.mobilemanager.autostart.AutoStartActivity")),
        // Samsung
        Intent().setComponent(android.content.ComponentName("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity"))
    )

    fun hasAutoStartSettings(context: Context): Boolean {
        return autoStartIntents.any { intent ->
            context.packageManager.resolveActivity(intent, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY) != null
        }
    }

    fun requestAutoStart(context: Context) {
        for (intent in autoStartIntents) {
            try {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (context.packageManager.resolveActivity(intent, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY) != null) {
                    context.startActivity(intent)
                    return
                }
            } catch (_: Exception) {}
        }
    }
}
