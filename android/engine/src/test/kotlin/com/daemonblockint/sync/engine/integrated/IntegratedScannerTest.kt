package com.daemonblockint.sync.engine.integrated

import com.daemonblockint.sync.engine.DangerousPermission
import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory
import com.daemonblockint.sync.engine.threatdb.InMemoryBackend
import com.daemonblockint.sync.engine.threatdb.IndicatorKind
import com.daemonblockint.sync.engine.threatdb.ThreatRecord
import com.daemonblockint.sync.engine.threatdb.ThreatStore
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class IntegratedScannerTest {

    private val scanner = IntegratedScanner()

    @Test
    fun `clean target produces low score`() {
        val target = ScanTarget(
            id = "com.clean.app",
            kind = ScanTarget.Kind.APP,
            text = "A normal application",
        )
        val result = scanner.scanLocal(target)
        assertEquals(Severity.LOW, result.severity)
        assertEquals(0, result.score)
    }

    @Test
    fun `suspicious text triggers findings`() {
        val target = ScanTarget(
            id = "com.evil.app",
            kind = ScanTarget.Kind.APP,
            text = "const mnemonic = 'abandon abandon'; fetch('https://evil.xyz')",
            permissions = listOf(DangerousPermission.READ_CLIPBOARD, DangerousPermission.BIND_ACCESSIBILITY_SERVICE),
        )
        val result = scanner.scanLocal(target)
        assertTrue(result.score > 60)
        assertTrue(result.findings.isNotEmpty())
    }

    @Test
    fun `report is generated with verdict`() {
        val target = ScanTarget(
            id = "com.test.app",
            kind = ScanTarget.Kind.APP,
            text = "Hello world",
            label = "Test App",
        )
        val result = scanner.scanLocal(target)
        assertEquals("Test App", result.report.target.label)
    }

    @Test
    fun `phishing domain triggers signature match`() {
        val target = ScanTarget(
            id = "https://s0lana.xyz",
            kind = ScanTarget.Kind.URL,
            domain = "s0lana.xyz",
        )
        val result = scanner.scanLocal(target)
        assertTrue(result.findings.any { it.source == Finding.Source.SIGNATURE })
    }

    @Test
    fun `threat store findings appear in scan results`() {
        val store = ThreatStore()
        store.add(listOf(
            ThreatRecord(
                id = "known-drainer",
                indicator = "drainer.xyz",
                indicatorKind = IndicatorKind.DOMAIN,
                category = ThreatCategory.PHISHING,
                severity = Severity.CRITICAL,
                description = "Known wallet drainer domain",
                source = "ota-bundle",
                addedAt = System.currentTimeMillis(),
            ),
        ))
        val scannerWithStore = IntegratedScanner(
            IntegratedScannerOptions(threatStore = store),
        )
        val target = ScanTarget(
            id = "https://drainer.xyz",
            kind = ScanTarget.Kind.URL,
            domain = "drainer.xyz",
        )
        val result = scannerWithStore.scanLocal(target)
        val threatDbFinding = result.findings.find { it.ruleId.startsWith("THREATDB:") }
        assertNotNull(threatDbFinding)
        assertEquals(Severity.CRITICAL, threatDbFinding.severity)
        assertTrue(threatDbFinding.confidence > 0.9)
    }

    @Test
    fun `threat store is exposed for OTA updates`() {
        val store = ThreatStore()
        val scannerWithStore = IntegratedScanner(
            IntegratedScannerOptions(threatStore = store),
        )
        assertNotNull(scannerWithStore.threatStoreRef)

        // Simulate OTA update adding a new threat
        scannerWithStore.threatStoreRef!!.add(listOf(
            ThreatRecord(
                id = "new-threat",
                indicator = "evil-program-id",
                indicatorKind = IndicatorKind.PROGRAM,
                category = ThreatCategory.MALWARE,
                severity = Severity.HIGH,
                description = "Newly discovered malicious program",
                addedAt = System.currentTimeMillis(),
            ),
        ))

        val target = ScanTarget(
            id = "evil-program-id",
            kind = ScanTarget.Kind.APP,
            text = "benign text",
        )
        val result = scannerWithStore.scanLocal(target)
        assertTrue(result.findings.any { it.ruleId == "THREATDB:new-threat" })
    }

    @Test
    fun `scanner without threat store still works`() {
        val scannerNoStore = IntegratedScanner()
        assertEquals(null, scannerNoStore.threatStoreRef)

        val target = ScanTarget(
            id = "com.clean.app",
            kind = ScanTarget.Kind.APP,
            text = "clean",
        )
        val result = scannerNoStore.scanLocal(target)
        assertEquals(0, result.score)
    }
}
