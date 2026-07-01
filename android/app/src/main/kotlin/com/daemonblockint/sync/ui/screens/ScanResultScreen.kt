package com.daemonblockint.sync.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.ui.viewmodel.DashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanResultScreen(
    onBack: () -> Unit,
    viewModel: DashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val result = state.lastScanResult

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan Result") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        if (result == null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center,
            ) {
                Text("No scan result yet. Run a scan from the dashboard.")
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Score card
            item {
                ScoreCard(
                    score = result.score,
                    severity = result.severity,
                    verdict = result.report.verdict,
                    summary = result.report.summary,
                )
            }

            // Breakdown
            item {
                BreakdownCard(result.breakdown.behavioral, result.breakdown.yara, result.breakdown.signature)
            }

            // Findings
            if (result.findings.isNotEmpty()) {
                item {
                    Text("Findings (${result.findings.size})", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                }
                items(result.findings) { finding ->
                    FindingCard(
                        title = finding.title,
                        description = finding.description,
                        severity = finding.severity,
                        source = finding.source.name,
                        confidence = finding.confidence,
                        evidence = finding.evidence,
                    )
                }
            }

            // Remediation
            if (result.report.remediation.isNotEmpty()) {
                item {
                    RemediationCard(result.report.remediation)
                }
            }
        }
    }
}

@Composable
private fun ScoreCard(
    score: Int,
    severity: Severity,
    verdict: ThreatReportVerdict,
    summary: String,
) {
    val color = when (severity) {
        Severity.CRITICAL -> Color(0xFFFF1744)
        Severity.HIGH -> Color(0xFFFF9100)
        Severity.MEDIUM -> Color(0xFFFFC107)
        Severity.LOW -> Color(0xFF00C853)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                "$score",
                style = MaterialTheme.typography.displayLarge,
                fontWeight = FontWeight.Bold,
                color = color,
            )
            Text("/ 100", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
            AssistChip(
                onClick = {},
                label = { Text(verdict.name, fontWeight = FontWeight.Bold) },
                colors = AssistChipDefaults.assistChipColors(containerColor = color.copy(alpha = 0.15f)),
            )
            Spacer(Modifier.height(12.dp))
            Text(summary, style = MaterialTheme.typography.bodyMedium, textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        }
    }
}

private typealias ThreatReportVerdict = com.daemonblockint.sync.engine.analyzer.ThreatReport.Verdict

@Composable
private fun BreakdownCard(behavioral: Int, yara: Int, signature: Int) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Risk Breakdown", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(12.dp))
            BreakdownBar("Behavioral", behavioral, Color(0xFF7C4DFF))
            Spacer(Modifier.height(8.dp))
            BreakdownBar("YARA", yara, Color(0xFF00E5FF))
            Spacer(Modifier.height(8.dp))
            BreakdownBar("Signature", signature, Color(0xFFFF5252))
        }
    }
}

@Composable
private fun BreakdownBar(label: String, value: Int, color: Color) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text("$value", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { value / 100f },
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp),
            color = color,
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
        )
    }
}

@Composable
private fun FindingCard(
    title: String,
    description: String,
    severity: Severity,
    source: String,
    confidence: Double,
    evidence: List<String>,
) {
    val color = when (severity) {
        Severity.CRITICAL -> Color(0xFFFF1744)
        Severity.HIGH -> Color(0xFFFF9100)
        Severity.MEDIUM -> Color(0xFFFFC107)
        Severity.LOW -> Color(0xFF00C853)
    }

    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Surface(
                    color = color.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(
                        "  ${severity.name}  ",
                        style = MaterialTheme.typography.labelSmall,
                        color = color,
                        modifier = Modifier.padding(2.dp),
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(description, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            Row {
                Text("Source: $source", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.width(16.dp))
                Text("Confidence: ${(confidence * 100).toInt()}%", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (evidence.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text("Evidence: ${evidence.joinToString(", ")}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun RemediationCard(steps: List<String>) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Recommended Actions", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            for ((i, step) in steps.withIndex()) {
                Row(modifier = Modifier.padding(vertical = 4.dp)) {
                    Text("${i + 1}. ", fontWeight = FontWeight.Bold)
                    Text(step, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}
