package com.daemonblockint.sync.engine.analyzer

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.Severity

data class RiskResult(
    val score: Int,
    val severity: Severity,
    val breakdown: Breakdown,
    val escalated: Boolean,
    val findings: List<Finding>,
) {
    data class Breakdown(val behavioral: Int, val yara: Int, val signature: Int)
}

/**
 * Risk Scoring Engine (PRD section 11).
 *
 * Combined score weights behavioral (60%) and YARA (40%). Signature hits are
 * folded into whichever layer is most relevant but also tracked separately. A
 * critical YARA match escalates the overall severity to critical regardless of
 * the behavioral score.
 */
class RiskScorer(
    private val weights: Weights = Weights(),
) {
    data class Weights(val behavioral: Double = 0.6, val yara: Double = 0.4)

    fun score(findings: List<Finding>): RiskResult {
        val behavioral = layerScore(findings.filter { it.source == Finding.Source.BEHAVIORAL || it.source == Finding.Source.LLM })
        val yara = layerScore(findings.filter { it.source == Finding.Source.YARA })
        val signature = layerScore(findings.filter { it.source == Finding.Source.SIGNATURE })

        val behavioralComponent = maxOf(behavioral, signature)
        val yaraComponent = maxOf(yara, signature)

        val activeWeight =
            (if (behavioralComponent > 0) weights.behavioral else 0.0) +
            (if (yaraComponent > 0) weights.yara else 0.0)

        var combined = if (activeWeight == 0.0) 0.0
            else (weights.behavioral * behavioralComponent + weights.yara * yaraComponent) / activeWeight

        val criticalYara = findings.any { it.source == Finding.Source.YARA && it.severity == Severity.CRITICAL }
        val criticalSig = findings.any {
            it.source == Finding.Source.SIGNATURE && it.severity == Severity.CRITICAL && it.confidence >= 0.9
        }
        val escalated = criticalYara || criticalSig
        if (escalated) combined = maxOf(combined, 85.0)

        val score = minOf(100, combined.toInt())

        return RiskResult(
            score = score,
            severity = Severity.fromScore(score),
            breakdown = RiskResult.Breakdown(
                behavioral = behavioral.toInt(),
                yara = yara.toInt(),
                signature = signature.toInt(),
            ),
            escalated = escalated,
            findings = findings,
        )
    }

    /**
     * Reduce a layer's findings to a 0–100 score. The strongest finding sets the
     * floor (severity ceiling × confidence); additional findings add diminishing
     * weight so many minor flags can still accumulate.
     */
    private fun layerScore(findings: List<Finding>): Double {
        if (findings.isEmpty()) return 0.0

        val weighted = findings
            .map { Severity.scoreCeiling(it.severity) * it.confidence }
            .sortedDescending()

        var score = weighted[0]
        for (i in 1 until weighted.size) {
            score += weighted[i] * (0.3 / i)
        }
        return minOf(100.0, score)
    }
}
