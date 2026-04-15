package tigralint.tgproxy

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import tigralint.tgproxy.service.ProxyForegroundService
import tigralint.tgproxy.ui.ProxyViewModel
import tigralint.tgproxy.ui.screens.DashboardScreen
import tigralint.tgproxy.ui.screens.FaqScreen
import tigralint.tgproxy.ui.screens.LogsScreen
import tigralint.tgproxy.ui.screens.SettingsScreen
import tigralint.tgproxy.util.AppLogger
import tigralint.tgproxy.util.Texts
import tigralint.tgproxy.ui.theme.*
import tigralint.tgproxy.util.BatteryOptimization

class MainActivity : ComponentActivity() {

    private val viewModel by viewModels<ProxyViewModel>()

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* granted or not, we proceed */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences("TgProxyPrefs", MODE_PRIVATE)
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
                MainApp(viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshBatteryStatus()
        viewModel.bindService()
        AppLogger.flush() // Ensure logs UI is up to date
    }

    override fun onPause() {
        super.onPause()
        viewModel.unbindService()
    }

    @Composable
    private fun MainApp(vm: ProxyViewModel) {
        val navController = rememberNavController()

        // Collect ViewModel state (lifecycle-aware — no leaks)
        val status by vm.status.collectAsStateWithLifecycle()
        val statsSnapshot by vm.stats.collectAsStateWithLifecycle()
        val config by vm.config.collectAsStateWithLifecycle()
        val isBatteryOptimized by vm.isBatteryOptimized.collectAsStateWithLifecycle()
        val hasAutoStart by vm.hasAutoStart.collectAsStateWithLifecycle()
        val link by vm.proxyLink.collectAsStateWithLifecycle()

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
                        NavItem("logs", Texts.logsTitle, Icons.Filled.List, Icons.Outlined.List),
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
                        onToggleProxy = vm::toggleProxy,
                        isBatteryOptimized = isBatteryOptimized,
                        onRequestBatteryOptimization = {
                            vm.requestDisableBatteryOptimization(this@MainActivity)
                        }
                    )
                }
                composable("settings") {
                    SettingsScreen(
                        config = config,
                        isRunning = status == ProxyForegroundService.ProxyStatus.RUNNING,
                        onSave = { newConfig -> vm.updateConfig(newConfig) },
                        onRequestBatteryOptimization = {
                            vm.requestDisableBatteryOptimization(this@MainActivity)
                        },
                        isBatteryOptimized = isBatteryOptimized,
                        hasAutoStart = hasAutoStart,
                        onRequestAutoStart = {
                            vm.requestAutoStart(this@MainActivity)
                        }
                    )
                }
                composable("logs") {
                    LogsScreen()
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
