package tigralint.tgproxy

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material.icons.filled.Help
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import tigralint.tgproxy.proxy.ProxyConfig
import tigralint.tgproxy.proxy.ProxyStats
import tigralint.tgproxy.proxy.TcpServer
import tigralint.tgproxy.service.ProxyForegroundService
import tigralint.tgproxy.ui.screens.DashboardScreen
import tigralint.tgproxy.ui.screens.FaqScreen
import tigralint.tgproxy.ui.screens.SettingsScreen
import tigralint.tgproxy.util.Texts
import tigralint.tgproxy.ui.theme.*
import tigralint.tgproxy.util.BatteryOptimization

class MainActivity : ComponentActivity() {

    private val proxyServiceState = mutableStateOf<ProxyForegroundService?>(null)
    private var proxyService: ProxyForegroundService?
        get() = proxyServiceState.value
        set(value) { proxyServiceState.value = value }
    private var isBound = false

    // State holders
    private val proxyStatus = mutableStateOf(ProxyForegroundService.ProxyStatus.STOPPED)
    private val proxyStats = mutableStateOf(ProxyStats.Snapshot())
    private val proxyConfig = mutableStateOf(ProxyConfig())
    private val proxyLink = mutableStateOf("")
    private val isBatteryOptimized = mutableStateOf(true)

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val service = (binder as ProxyForegroundService.ProxyBinder).getService()
            proxyService = service
            isBound = true

            // Sync state
            proxyConfig.value = service.config

            // Observe service status
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            proxyService = null
            isBound = false
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* granted or not, we proceed */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences("TgProxyPrefs", Context.MODE_PRIVATE)
        Texts.isRu = prefs.getBoolean("isRu", true)
        enableEdgeToEdge()

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            TgProxyTheme {
                MainApp()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        isBatteryOptimized.value = BatteryOptimization.isBatteryOptimized(this)
        bindProxyService()
    }

    override fun onPause() {
        super.onPause()
        unbindProxyService()
    }

    private fun bindProxyService() {
        val intent = Intent(this, ProxyForegroundService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    private fun unbindProxyService() {
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
    }

    private fun toggleProxy() {
        val service = proxyService ?: return
        val status = service.status.value

        if (status == ProxyForegroundService.ProxyStatus.RUNNING) {
            val stopIntent = Intent(this, ProxyForegroundService::class.java).apply {
                action = ProxyForegroundService.ACTION_STOP
            }
            startService(stopIntent)
        } else {
            service.updateConfig(proxyConfig.value)
            val startIntent = Intent(this, ProxyForegroundService::class.java).apply {
                action = ProxyForegroundService.ACTION_START
            }
            startForegroundService(startIntent)
        }
    }

    @Composable
    private fun MainApp() {
        val navController = rememberNavController()

        // Collect service state
        val service = proxyService
        val status by service?.status?.collectAsState() ?: remember { proxyStatus }
        val statsSnapshot by service?.stats?.snapshot?.collectAsState()
            ?: remember { mutableStateOf(ProxyStats.Snapshot()) }
        val link = if (status == ProxyForegroundService.ProxyStatus.RUNNING) {
            service?.getProxyLink() ?: ""
        } else ""

        Scaffold(
            bottomBar = {
                NavigationBar(
                    containerColor = AppleSurface,
                    contentColor = TextSecondary,
                    tonalElevation = 0.dp
                ) {
                    val navBackStackEntry by navController.currentBackStackEntryAsState()
                    val currentDestination = navBackStackEntry?.destination

                    listOf(
                        NavItem("dashboard", Texts.dashboard, Icons.Filled.Dashboard, Icons.Outlined.Dashboard),
                        NavItem("settings", Texts.settings, Icons.Filled.Settings, Icons.Outlined.Settings),
                        NavItem("faq", Texts.faq, Icons.Filled.Help, Icons.Outlined.HelpOutline)
                    ).forEach { item ->
                        val selected = currentDestination?.hierarchy?.any { it.route == item.route } == true
                        NavigationBarItem(
                            icon = {
                                Icon(
                                    if (selected) item.selectedIcon else item.unselectedIcon,
                                    contentDescription = item.label
                                )
                            },
                            label = { Text(item.label) },
                            selected = selected,
                            onClick = {
                                navController.navigate(item.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = AppleBlue,
                                selectedTextColor = AppleBlue,
                                unselectedIconColor = TextSecondary,
                                unselectedTextColor = TextSecondary,
                                indicatorColor = Color.Transparent
                            )
                        )
                    }
                }
            }
        ) { innerPadding ->
            NavHost(
                navController = navController,
                startDestination = "dashboard",
                modifier = Modifier.padding(innerPadding)
            ) {
                composable("dashboard") {
                    DashboardScreen(
                        status = status,
                        stats = statsSnapshot,
                        proxyLink = link,
                        onToggleProxy = ::toggleProxy
                    )
                }
                composable("settings") {
                    SettingsScreen(
                        config = proxyConfig.value,
                        isRunning = status == ProxyForegroundService.ProxyStatus.RUNNING,
                        onSave = { newConfig ->
                            proxyConfig.value = newConfig
                            proxyService?.updateConfig(newConfig)
                        },
                        onRequestBatteryOptimization = {
                            BatteryOptimization.requestDisableBatteryOptimization(this@MainActivity)
                        },
                        isBatteryOptimized = isBatteryOptimized.value
                    )
                }
                composable("faq") {
                    FaqScreen()
                }
            }
        }
    }

    data class NavItem(
        val route: String,
        val label: String,
        val selectedIcon: ImageVector,
        val unselectedIcon: ImageVector
    )
}
