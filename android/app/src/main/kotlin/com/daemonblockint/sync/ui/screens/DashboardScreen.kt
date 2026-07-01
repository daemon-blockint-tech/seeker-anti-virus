package com.daemonblockint.sync.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.analyzer.ThreatReport
import com.daemonblockint.sync.ui.viewmodel.DashboardViewModel

@Composable
fun DashboardScreen(
    onNavigateToAlerts: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onNavigateToScanResult: () -> Unit,
    viewModel: DashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Sync", fontWeight = FontWeight.Bold) },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Protection status card
            item { ProtectionStatusCard(state) }

            // Engine status
            item { EngineStatusCard(state) }

            // Quick scan
            item { QuickScanCard(viewModel, state, onNavigateToScanResult) }

            // Recent alerts
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Recent Alerts", style = MaterialTheme.typography.titleMedium)
                    TextButton(onClick = onNavigateToAlerts) { Text("View All") }
                }
            }

            if (state.recentAlerts.isEmpty()) {
                item { EmptyAlertsCard() }
            } else {
                items(state.recentAlerts.take(5)) { alert ->
                    AlertItem(alert.appId, alert.severity, alert.title, alert.score)
                }
            }
        }
    }
}

@Composable
private fun ProtectionStatusCard(state: com.daemonblockint.sync.ui.viewmodel.DashboardState) {
    val statusColor = if (state.isProtected) Color(0xFF00C853) else Color(0xFFFF1744)
    val statusText = if (state.isProtected) "Protected" else "At Risk"

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(20.dp),
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                if (state.isProtected) Icons.Default.Shield else Icons.Default.Warning,
                contentDescription = null,
                tint = statusColor,
                modifier = Modifier.size(64.dp),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                statusText,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = statusColor,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "${state.threatCount} threats detected",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun EngineStatusCard(state: com.daemonblockint.sync.ui.viewmodel.DashboardState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Engine Status", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(12.dp))
            StatusRow("YARA Engine", if (state.yaraNativeActive) "Native (NDK)" else "Kotlin fallback")
            StatusRow("Threat DB", "${state.threatDbSize} records")
            StatusRow("Last Scan", "${state.lastScanScore}/100 (${state.lastScanSeverity})")
        }
    }
}

@Composable
private fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun QuickScanCard(
    viewModel: DashboardViewModel,
    state: com.daemonblockint.sync.ui.viewmodel.DashboardState,
    onNavigateToScanResult: () -> Unit,
) {
    var scanText by remember { mutableStateOf("") }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Quick Scan", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = scanText,
                onValueChange = { scanText = it },
                label = { Text("Paste text, URL, or contract address") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = {
                    if (scanText.isNotBlank()) {
                        viewModel.scanText(scanText)
                        onNavigateToScanResult()
                    }
                },
                enabled = scanText.isNotBlank() && !state.isScanning,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (state.isScanning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                } else {
                    Icon(Icons.Default.Search, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Scan Now")
                }
            }
        }
    }
}

@Composable
private fun EmptyAlertsCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF00C853))
            Spacer(Modifier.height(8.dp))
            Text("No threats detected yet", style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
fun AlertItem(appId: String, severity: Severity, title: String, score: Int) {
    val color = when (severity) {
        Severity.CRITICAL -> Color(0xFFFF1744)
        Severity.HIGH -> Color(0xFFFF9100)
        Severity.MEDIUM -> Color(0xFFFFC107)
        Severity.LOW -> Color(0xFF00C853)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = color)
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                Text(
                    appId.take(20),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                "$score",
                style = MaterialTheme.typography.titleLarge,
                color = color,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}
