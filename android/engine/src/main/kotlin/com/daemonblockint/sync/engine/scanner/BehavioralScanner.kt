package com.daemonblockint.sync.engine.scanner

import com.daemonblockint.sync.engine.BehaviorEvent
import com.daemonblockint.sync.engine.DangerousPermission
import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory

/** Permissions considered high-risk on a crypto-custody device. */
private val DANGEROUS_PERMISSIONS: Map<DangerousPermission, Double> = mapOf(
    DangerousPermission.READ_SMS to 0.9,
    DangerousPermission.RECEIVE_SMS to 0.9,
    DangerousPermission.READ_CLIPBOARD to 0.95,
    DangerousPermission.BIND_ACCESSIBILITY_SERVICE to 0.95,
    DangerousPermission.SYSTEM_ALERT_WINDOW to 0.8,
    DangerousPermission.RECORD_AUDIO to 0.7,
    DangerousPermission.READ_CONTACTS to 0.5,
    DangerousPermission.ACCESS_FINE_LOCATION to 0.5,
    DangerousPermission.CAMERA to 0.5,
    DangerousPermission.QUERY_ALL_PACKAGES to 0.6,
    DangerousPermission.REQUEST_INSTALL_PACKAGES to 0.7,
)

/** Known-bad / suspicious endpoint heuristics for C2 detection. */
private val SUSPICIOUS_HOST_PATTERNS = listOf(
        Regex("\\.(top|xyz|ru|tk|gq|cf)$", RegexOption.IGNORE_CASE),
        Regex("\\d{1,3}(\\.\\d{1,3}){3}"),
        Regex("(pastebin|ngrok|trycloudflare|duckdns|no-ip)\\.", RegexOption.IGNORE_CASE),
)

/** Anomalous transfer threshold (~5 SOL). */
private const val LARGE_TRANSFER_LAMPORTS = 5_000_000_000L

/** Above this (~50 SOL) a transfer is treated as a near-certain anomaly. */
private const val VERY_LARGE_TRANSFER_LAMPORTS = 50_000_000_000L

data class BehavioralScannerOptions(
    val largeTransferLamports: Long = LARGE_TRANSFER_LAMPORTS,
)

/**
 * Behavioral Scanner (PRD 5.1).
 *
 * Inspects declared permissions and a stream of runtime behavior events
 * for permission abuse, C2 networking, anomalous transfers and binary injection.
 * Pure and synchronous so it can run inside a tight on-device monitoring loop.
 */
class BehavioralScanner(
    private val options: BehavioralScannerOptions = BehavioralScannerOptions(),
) {
    private val largeTransfer get() = options.largeTransferLamports

    fun scan(target: ScanTarget): List<Finding> = buildList {
        addAll(scanPermissions(target.permissions))
        addAll(scanEvents(target.events))
    }

    private fun scanPermissions(permissions: List<DangerousPermission>): List<Finding> {
        val flagged = permissions.filter { it in DANGEROUS_PERMISSIONS }
        if (flagged.isEmpty()) return emptyList()

        val maxWeight = flagged.maxOf { DANGEROUS_PERMISSIONS[it]!! }
        val combo = DangerousPermission.READ_CLIPBOARD in flagged &&
            (DangerousPermission.BIND_ACCESSIBILITY_SERVICE in flagged ||
                DangerousPermission.READ_SMS in flagged)

        return listOf(
            Finding(
                source = Finding.Source.BEHAVIORAL,
                ruleId = "BEH_DANGEROUS_PERMISSIONS",
                title = "Dangerous permission set requested",
                description = if (combo)
                    "App requests a permission combination commonly used by wallet drainers and keyloggers (clipboard + accessibility/SMS)."
                else
                    "App requests permissions that can be abused to capture sensitive data.",
                category = ThreatCategory.PERMISSION_ABUSE,
                severity = if (combo || maxWeight >= 0.9) Severity.HIGH else Severity.MEDIUM,
                confidence = minOf(0.99, maxWeight + if (combo) 0.1 else 0.0),
                evidence = flagged.map { it.name },
            ),
        )
    }

    private fun scanEvents(events: List<BehaviorEvent>): List<Finding> {
        val suspiciousHosts = mutableSetOf<String>()
        var unsignedLoads = 0
        val largeTransfers = mutableListOf<String>()
        var maxTransferLamports = 0L
        var clipboardReads = 0

        for (ev in events) {
            when (ev.type) {
                BehaviorEvent.Type.NETWORK -> {
                    ev.host?.let { host ->
                        if (isSuspiciousHost(host)) {
                            suspiciousHosts.add("$host${ev.port?.let { ":$it" } ?: ""}")
                        }
                    }
                }
                BehaviorEvent.Type.BINARY_LOAD -> if (ev.unsigned == true) unsignedLoads++
                BehaviorEvent.Type.CRYPTO_TRANSACTION -> {
                    val amount = ev.amountLamports ?: 0
                    if (amount >= largeTransfer) {
                        maxTransferLamports = maxOf(maxTransferLamports, amount)
                        largeTransfers.add("${"%.2f".format(amount / 1e9)} SOL → ${ev.targetAddress ?: "unknown"}")
                    }
                }
                BehaviorEvent.Type.CLIPBOARD_ACCESS -> clipboardReads++
                else -> {}
            }
        }

        val findings = mutableListOf<Finding>()

        if (suspiciousHosts.isNotEmpty()) {
            findings.add(
                Finding(
                    source = Finding.Source.BEHAVIORAL,
                    ruleId = "BEH_C2_NETWORK",
                    title = "Suspicious network endpoints (possible C2)",
                    description = "App contacted endpoints matching command-and-control heuristics (raw IPs, throwaway TLDs, tunneling services).",
                    category = ThreatCategory.C2,
                    severity = Severity.HIGH,
                    confidence = 0.7,
                    evidence = suspiciousHosts.toList(),
                ),
            )
        }

        if (unsignedLoads > 0) {
            findings.add(
                Finding(
                    source = Finding.Source.BEHAVIORAL,
                    ruleId = "BEH_BINARY_INJECTION",
                    title = "Unsigned binary / code injection",
                    description = "App loaded unsigned native binaries at runtime — a common code-injection and RAT technique.",
                    category = ThreatCategory.MALWARE,
                    severity = Severity.HIGH,
                    confidence = 0.75,
                    evidence = listOf("$unsignedLoads unsigned load(s)"),
                ),
            )
        }

        if (largeTransfers.isNotEmpty()) {
            val veryLarge = maxTransferLamports >= VERY_LARGE_TRANSFER_LAMPORTS
            findings.add(
                Finding(
                    source = Finding.Source.BEHAVIORAL,
                    ruleId = "BEH_ANOMALOUS_TRANSFER",
                    title = "Large / anomalous transfer detected",
                    description = "Transfer exceeds the anomaly threshold. Verify the recipient and amount before approving.",
                    category = ThreatCategory.DRAINER,
                    severity = Severity.HIGH,
                    confidence = if (veryLarge) 0.95 else 0.87,
                    evidence = largeTransfers,
                ),
            )
        }

        if (clipboardReads >= 3) {
            findings.add(
                Finding(
                    source = Finding.Source.BEHAVIORAL,
                    ruleId = "BEH_CLIPBOARD_HIJACK",
                    title = "Repeated clipboard access",
                    description = "Frequent clipboard reads can indicate address-swapping or seed-phrase theft.",
                    category = ThreatCategory.SPYWARE,
                    severity = Severity.MEDIUM,
                    confidence = 0.6,
                    evidence = listOf("$clipboardReads clipboard reads"),
                ),
            )
        }

        return findings
    }

    private fun isSuspiciousHost(host: String): Boolean =
        SUSPICIOUS_HOST_PATTERNS.any { it.containsMatchIn(host) != null }
}
