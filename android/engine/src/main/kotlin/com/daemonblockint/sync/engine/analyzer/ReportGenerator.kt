package com.daemonblockint.sync.engine.analyzer

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import java.util.Date

data class ThreatReport(
    val target: TargetInfo,
    val score: Int,
    val severity: Severity,
    val verdict: Verdict,
    val summary: String,
    val findings: List<Finding>,
    val remediation: List<String>,
    val generatedAt: String,
) {
    data class TargetInfo(val id: String, val kind: ScanTarget.Kind, val label: String?)
    enum class Verdict { BLOCKED, WARN, CAUTION, CLEAN }
}

/** Plain-language action verb for each severity (PRD §11 / FR-12). */
private val ACTION_BY_SEVERITY: Map<Severity, ThreatReport.Verdict> = mapOf(
    Severity.CRITICAL to ThreatReport.Verdict.BLOCKED,
    Severity.HIGH to ThreatReport.Verdict.WARN,
    Severity.MEDIUM to ThreatReport.Verdict.CAUTION,
    Severity.LOW to ThreatReport.Verdict.CLEAN,
)

/** One-tap remediation suggestions keyed by finding category (FR-13). */
private val REMEDIATION_BY_CATEGORY: Map<String, String> = mapOf(
    "PERMISSION_ABUSE" to "Revoke the flagged permissions in Android settings.",
    "C2" to "Disconnect from the network and uninstall the app.",
    "MALWARE" to "Quarantine and uninstall immediately; rotate any exposed keys.",
    "SPYWARE" to "Uninstall the app and move funds to a fresh wallet.",
    "TROJAN" to "Uninstall immediately and run a full device scan.",
    "DRAINER" to "Do not sign. Revoke token approvals via your wallet.",
    "RUG_PULL" to "Do not buy. Exit any existing position if liquidity remains.",
    "HONEYPOT" to "Do not buy — sells are restricted by the contract.",
    "EXPLOIT" to "Avoid interacting with this contract until audited.",
    "PHISHING" to "Close the site; never enter your seed phrase. Verify the official domain.",
)

private fun severityRank(s: Severity): Int = Severity.rank[s] ?: 0

/**
 * Report Generator (PRD core module `analyzer/`, FR-10/FR-12/FR-13).
 *
 * Turns a RiskResult into a plain-language, exportable threat report
 * with deduplicated, prioritized remediation steps.
 */
class ReportGenerator {
    fun generate(target: ScanTarget, result: RiskResult): ThreatReport {
        val verdict = ACTION_BY_SEVERITY[result.severity]!!
        val findings = result.findings.sortedByDescending { severityRank(it.severity) }

        return ThreatReport(
            target = ThreatReport.TargetInfo(target.id, target.kind, target.label),
            score = result.score,
            severity = result.severity,
            verdict = verdict,
            summary = summarize(target, result),
            findings = findings,
            remediation = remediation(findings, verdict),
            generatedAt = Date().toInstant().toString(),
        )
    }

    private fun summarize(target: ScanTarget, result: RiskResult): String {
        val label = target.label ?: target.id
        if (result.findings.isEmpty()) {
            return "No threats detected in $label. Risk score ${result.score}/100 (low)."
        }
        val top = result.findings.sortedByDescending { severityRank(it.severity) }.first()
        val escalation = if (result.escalated)
            " A critical signature/YARA match escalated the overall severity."
        else ""
        return "$label scored ${result.score}/100 (${result.severity}). " +
            "${result.findings.size} finding(s); most severe: \"${top.title}\".$escalation"
    }

    private fun remediation(findings: List<Finding>, verdict: ThreatReport.Verdict): List<String> {
        if (verdict == ThreatReport.Verdict.CLEAN) return listOf("No action required. Continue monitoring.")

        val steps = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        for (f in findings) {
            val tip = REMEDIATION_BY_CATEGORY[f.category.name]
            if (tip != null && seen.add(tip)) steps.add(tip)
        }
        if (verdict == ThreatReport.Verdict.BLOCKED) {
            steps.add(0, "Action blocked automatically — do not proceed.")
        }
        return steps
    }
}
