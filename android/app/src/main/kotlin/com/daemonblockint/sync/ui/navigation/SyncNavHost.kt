package com.daemonblockint.sync.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.daemonblockint.sync.ui.screens.AlertHistoryScreen
import com.daemonblockint.sync.ui.screens.DashboardScreen
import com.daemonblockint.sync.ui.screens.ScanResultScreen
import com.daemonblockint.sync.ui.screens.SettingsScreen

object Routes {
    const val DASHBOARD = "dashboard"
    const val SCAN_RESULT = "scan_result"
    const val ALERT_HISTORY = "alert_history"
    const val SETTINGS = "settings"
}

@Composable
fun SyncNavHost() {
    val navController = rememberNavController()

    NavHost(
        navController = navController,
        startDestination = Routes.DASHBOARD,
    ) {
        composable(Routes.DASHBOARD) {
            DashboardScreen(
                onNavigateToAlerts = { navController.navigate(Routes.ALERT_HISTORY) },
                onNavigateToSettings = { navController.navigate(Routes.SETTINGS) },
                onNavigateToScanResult = { navController.navigate(Routes.SCAN_RESULT) },
            )
        }
        composable(Routes.SCAN_RESULT) {
            ScanResultScreen(
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.ALERT_HISTORY) {
            AlertHistoryScreen(
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
                onBack = { navController.popBackStack() },
            )
        }
    }
}
