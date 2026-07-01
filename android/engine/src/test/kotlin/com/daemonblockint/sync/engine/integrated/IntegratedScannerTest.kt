package com.daemonblockint.sync.engine.integrated

import com.daemonblockint.sync.engine.DangerousPermission
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import org.junit.Test
import kotlin.test.assertEquals
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
}
