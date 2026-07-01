package com.daemonblockint.sync.engine.monitor

import com.daemonblockint.sync.engine.BehaviorEvent
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.integrated.IntegratedScanner
import com.daemonblockint.sync.engine.integrated.ScanResult

data class ThreatAlert(
    val appId: String,
    val severity: Severity,
    val score: Int,
    val title: String,
    val at: Long,
    val result: ScanResult,
)

fun interface AlertHandler {
    fun onAlert(alert: ThreatAlert)
}

data class MonitorOptions(
    val alertThreshold: Severity = Severity.HIGH,
    val flushEvery: Int = 25,
)

/**
 * Real-Time Monitor (PRD core module `monitor/`, FR-1/FR-3).
 *
 * Maintains per-app monitoring sessions, buffers incoming behavior events, and
 * re-runs the integrated scanner, pushing alerts when a session crosses the
 * configured severity threshold.
 */
class Monitor(
    private val scanner: IntegratedScanner,
    private val options: MonitorOptions = MonitorOptions(),
) {
    private data class Session(val target: ScanTarget, var buffered: Int)

    private val sessions = mutableMapOf<String, Session>()
    private val handlers = mutableListOf<AlertHandler>()

    fun onAlert(handler: AlertHandler) { handlers.add(handler) }

    /** Begin (or reset) a monitoring session for an app. */
    fun start(target: ScanTarget) {
        sessions[target.id] = Session(target.copy(events = target.events.toMutableList()), 0)
    }

    fun stop(appId: String) { sessions.remove(appId) }

    val activeSessions: List<String> get() = sessions.keys.toList()

    /**
     * Feed a runtime event into a session. Triggers a re-scan once enough events
     * have accumulated. Returns an alert if one fired, else null.
     */
    fun ingest(appId: String, event: BehaviorEvent): ThreatAlert? {
        val session = sessions[appId] ?: return null
        session.target.events.add(event)
        session.buffered++
        if (session.buffered < options.flushEvery) return null
        return evaluate(appId)
    }

    /** Force an immediate re-scan of a session. */
    fun evaluate(appId: String): ThreatAlert? {
        val session = sessions[appId] ?: return null
        session.buffered = 0

        val result = scanner.scanLocal(session.target)
        if ((Severity.rank[result.severity] ?: 0) < (Severity.rank[options.alertThreshold] ?: 0))
            return null

        val top = result.report.findings.firstOrNull()
        val alert = ThreatAlert(
            appId = appId,
            severity = result.severity,
            score = result.score,
            title = top?.title ?: "Threat detected",
            at = System.currentTimeMillis(),
            result = result,
        )
        for (h in handlers) h.onAlert(alert)
        return alert
    }
}
