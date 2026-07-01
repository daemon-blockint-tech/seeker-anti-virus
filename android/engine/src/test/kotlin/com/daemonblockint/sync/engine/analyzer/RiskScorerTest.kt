package com.daemonblockint.sync.engine.analyzer

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RiskScorerTest {

    private val scorer = RiskScorer()

    @Test
    fun `no findings produces low score`() {
        val result = scorer.score(emptyList())
        assertEquals(0, result.score)
        assertEquals(Severity.LOW, result.severity)
        assertFalse(result.escalated)
    }

    @Test
    fun `critical yara finding escalates`() {
        val findings = listOf(
            Finding(
                source = Finding.Source.YARA,
                ruleId = "test",
                title = "Test",
                description = "Test",
                category = ThreatCategory.MALWARE,
                severity = Severity.CRITICAL,
                confidence = 0.9,
            ),
        )
        val result = scorer.score(findings)
        assertTrue(result.escalated)
        assertEquals(Severity.CRITICAL, result.severity)
        assertTrue(result.score >= 85)
    }

    @Test
    fun `high behavioral finding scores high`() {
        val findings = listOf(
            Finding(
                source = Finding.Source.BEHAVIORAL,
                ruleId = "test",
                title = "Test",
                description = "Test",
                category = ThreatCategory.PERMISSION_ABUSE,
                severity = Severity.HIGH,
                confidence = 0.8,
            ),
        )
        val result = scorer.score(findings)
        assertEquals(Severity.HIGH, result.severity)
        assertTrue(result.score >= 60)
    }

    @Test
    fun `multiple findings accumulate`() {
        val findings = listOf(
            Finding(Finding.Source.BEHAVIORAL, "r1", "A", "D", ThreatCategory.C2, Severity.HIGH, 0.7),
            Finding(Finding.Source.BEHAVIORAL, "r2", "B", "D", ThreatCategory.MALWARE, Severity.MEDIUM, 0.6),
            Finding(Finding.Source.SIGNATURE, "r3", "C", "D", ThreatCategory.DRAINER, Severity.HIGH, 0.8),
        )
        val result = scorer.score(findings)
        assertTrue(result.score > 50)
    }
}

class ReportGeneratorTest {

    private val reporter = ReportGenerator()
    private val scorer = RiskScorer()

    @Test
    fun `clean report has clean verdict`() {
        val target = ScanTarget(id = "com.clean.app", kind = ScanTarget.Kind.APP, label = "Clean App")
        val result = scorer.score(emptyList())
        val report = reporter.generate(target, result)
        assertEquals(ThreatReport.Verdict.CLEAN, report.verdict)
        assertTrue(report.remediation.contains("No action required"))
    }

    @Test
    fun `critical report has blocked verdict`() {
        val target = ScanTarget(id = "com.evil.app", kind = ScanTarget.Kind.APP, label = "Evil App")
        val result = scorer.score(listOf(
            Finding(Finding.Source.YARA, "r1", "Malware", "Desc", ThreatCategory.MALWARE, Severity.CRITICAL, 0.95),
        ))
        val report = reporter.generate(target, result)
        assertEquals(ThreatReport.Verdict.BLOCKED, report.verdict)
        assertTrue(report.remediation.first().contains("blocked automatically"))
    }

    @Test
    fun `findings are sorted by severity descending`() {
        val target = ScanTarget(id = "test", kind = ScanTarget.Kind.APP)
        val result = scorer.score(listOf(
            Finding(Finding.Source.BEHAVIORAL, "r1", "Low", "D", ThreatCategory.C2, Severity.LOW, 0.5),
            Finding(Finding.Source.YARA, "r2", "Critical", "D", ThreatCategory.MALWARE, Severity.CRITICAL, 0.9),
            Finding(Finding.Source.SIGNATURE, "r3", "High", "D", ThreatCategory.DRAINER, Severity.HIGH, 0.8),
        ))
        val report = reporter.generate(target, result)
        assertEquals(Severity.CRITICAL, report.findings[0].severity)
        assertEquals(Severity.HIGH, report.findings[1].severity)
        assertEquals(Severity.LOW, report.findings[2].severity)
    }

    @Test
    fun `remediation steps are deduplicated`() {
        val target = ScanTarget(id = "test", kind = ScanTarget.Kind.APP)
        val result = scorer.score(listOf(
            Finding(Finding.Source.BEHAVIORAL, "r1", "A", "D", ThreatCategory.MALWARE, Severity.HIGH, 0.8),
            Finding(Finding.Source.SIGNATURE, "r2", "B", "D", ThreatCategory.MALWARE, Severity.HIGH, 0.7),
        ))
        val report = reporter.generate(target, result)
        // Both findings have MALWARE category — only one remediation step
        val malwareSteps = report.remediation.filter { it.contains("Quarantine") }
        assertEquals(1, malwareSteps.size)
    }
}

