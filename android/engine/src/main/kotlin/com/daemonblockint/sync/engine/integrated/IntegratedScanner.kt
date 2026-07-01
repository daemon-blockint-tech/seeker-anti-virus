package com.daemonblockint.sync.engine.integrated

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.analyzer.ReportGenerator
import com.daemonblockint.sync.engine.analyzer.RiskResult
import com.daemonblockint.sync.engine.analyzer.RiskScorer
import com.daemonblockint.sync.engine.scanner.BehavioralScanner
import com.daemonblockint.sync.engine.signatures.SignatureMatcher
import com.daemonblockint.sync.engine.signatures.DEFAULT_SIGNATURES
import com.daemonblockint.sync.engine.signatures.ThreatSignature
import com.daemonblockint.sync.engine.yara.RuleManager
import com.daemonblockint.sync.engine.yara.SOLANA_YARA_RULES
import com.daemonblockint.sync.engine.yara.YaraRule

/** Optional LLM classifier hook (PRD 5.4) — opt-in, async, off by default. */
fun interface LlmClassifier {
    suspend fun classify(target: ScanTarget, priorFindings: List<Finding>): List<Finding>
}

data class IntegratedScannerOptions(
    val signatures: List<ThreatSignature> = DEFAULT_SIGNATURES,
    val yaraRules: List<YaraRule> = SOLANA_YARA_RULES,
    val llm: LlmClassifier? = null,
    val llmEscalationThreshold: Int = 60,
    val onLlmError: (error: Throwable, target: ScanTarget) -> Unit = { err, target ->
        println("[sync] LLM classification failed for ${target.id}: $err")
    },
)

/** ScanResult extends RiskResult with the generated report. */
data class ScanResult(
    val score: Int,
    val severity: com.daemonblockint.sync.engine.Severity,
    val breakdown: RiskResult.Breakdown,
    val escalated: Boolean,
    val findings: List<Finding>,
    val report: com.daemonblockint.sync.engine.analyzer.ThreatReport,
)

/**
 * Integrated Scanner (PRD core module `integrated-scanner`).
 *
 * Unified pipeline: Behavioral → Signature → YARA → (opt-in) LLM, fed into the
 * Risk Scoring Engine and Report Generator. This is the primary entry point a
 * mobile/host app calls.
 */
class IntegratedScanner(
    private val options: IntegratedScannerOptions = IntegratedScannerOptions(),
) {
    private val behavioral = BehavioralScanner()
    private val signatures: SignatureMatcher = SignatureMatcher(options.signatures.toMutableList())
    private val rules: RuleManager = RuleManager(options.yaraRules)
    private val scorer = RiskScorer()
    private val reporter = ReportGenerator()

    /** Access the rule manager for custom-rule management (FR-15). */
    val ruleManager: RuleManager get() = rules
    val signatureMatcher: SignatureMatcher get() = signatures

    /** Run the full pipeline against a target and produce a scored report. */
    suspend fun scan(target: ScanTarget): ScanResult {
        val findings = mutableListOf<Finding>()
        findings.addAll(behavioral.scan(target))
        findings.addAll(signatures.scan(target))
        findings.addAll(rules.scanner().scan(target))

        // Opt-in LLM escalation for ambiguous/high-stakes cases (PRD 5.4).
        if (options.llm != null) {
            val interim = scorer.score(findings)
            if (interim.score >= options.llmEscalationThreshold) {
                try {
                    findings.addAll(options.llm.classify(target, findings.toList()))
                } catch (err: Throwable) {
                    options.onLlmError(err, target)
                }
            }
        }

        return finalize(target, findings)
    }

    /** Synchronous local-only scan (no LLM) for tight on-device loops. */
    fun scanLocal(target: ScanTarget): ScanResult {
        val findings = mutableListOf<Finding>()
        findings.addAll(behavioral.scan(target))
        findings.addAll(signatures.scan(target))
        findings.addAll(rules.scanner().scan(target))
        return finalize(target, findings)
    }

    private fun finalize(target: ScanTarget, findings: List<Finding>): ScanResult {
        val result = scorer.score(findings)
        val report = reporter.generate(target, result)
        return ScanResult(
            score = result.score,
            severity = result.severity,
            breakdown = result.breakdown,
            escalated = result.escalated,
            findings = result.findings,
            report = report,
        )
    }
}
