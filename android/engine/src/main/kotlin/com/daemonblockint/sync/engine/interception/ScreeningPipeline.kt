package com.daemonblockint.sync.engine.interception

import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.analyzer.ThreatReport
import com.daemonblockint.sync.engine.integrated.IntegratedScanner
import com.daemonblockint.sync.engine.integrated.ScanResult

enum class ScreeningDecision { ALLOW, WARN, BLOCK }

data class ScreeningResult(
    val decision: ScreeningDecision,
    val severity: Severity,
    val score: Int,
    val decoded: DecodedTransaction,
    val report: ThreatReport,
)

data class ScreeningPipelineOptions(
    val scanner: IntegratedScanner? = null,
    val blockAt: Severity = Severity.CRITICAL,
    val warnAt: Severity = Severity.HIGH,
)

/**
 * Transaction screening pipeline (PRD §5.5 / §10.1–10.2, FR-2).
 *
 * Decodes an intercepted signing request, runs it through the
 * IntegratedScanner, and maps the risk to an allow / warn / block
 * decision before any signature is produced.
 */
class ScreeningPipeline(
    private val scanner: IntegratedScanner = IntegratedScanner(),
    private val blockAt: Severity = Severity.CRITICAL,
    private val warnAt: Severity = Severity.HIGH,
) {
    constructor(options: ScreeningPipelineOptions) : this(
        scanner = options.scanner ?: IntegratedScanner(),
        blockAt = options.blockAt,
        warnAt = options.warnAt,
    )

    /** Screen a raw serialized transaction (signature vector + message, or message). */
    fun screen(txBytes: ByteArray, id: String? = null): ScreeningResult {
        val decoded = decodeTransaction(txBytes)
        val target = transactionToScanTarget(decoded, id)
        val result = scanner.scanLocal(target)

        var decision = ScreeningDecision.ALLOW
        if ((Severity.rank[result.severity] ?: 0) >= (Severity.rank[blockAt] ?: 0))
            decision = ScreeningDecision.BLOCK
        else if ((Severity.rank[result.severity] ?: 0) >= (Severity.rank[warnAt] ?: 0))
            decision = ScreeningDecision.WARN

        return ScreeningResult(
            decision = decision,
            severity = result.severity,
            score = result.score,
            decoded = decoded,
            report = result.report,
        )
    }
}
