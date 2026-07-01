package com.daemonblockint.sync.engine.scanner

import com.daemonblockint.sync.engine.BehaviorEvent
import com.daemonblockint.sync.engine.DangerousPermission
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BehavioralScannerTest {

    private val scanner = BehavioralScanner()

    @Test
    fun `clean target produces no findings`() {
        val target = ScanTarget(
            id = "com.clean.app",
            kind = ScanTarget.Kind.APP,
            permissions = emptyList(),
            events = emptyList(),
        )
        assertEquals(0, scanner.scan(target).size)
    }

    @Test
    fun `dangerous permissions are flagged`() {
        val target = ScanTarget(
            id = "com.suspicious.app",
            kind = ScanTarget.Kind.APP,
            permissions = listOf(DangerousPermission.READ_SMS, DangerousPermission.READ_CLIPBOARD),
        )
        val findings = scanner.scan(target)
        assertEquals(1, findings.size)
        assertEquals("BEH_DANGEROUS_PERMISSIONS", findings[0].ruleId)
        assertEquals(ThreatCategory.PERMISSION_ABUSE, findings[0].category)
    }

    @Test
    fun `clipboard plus accessibility combo is high severity`() {
        val target = ScanTarget(
            id = "com.drainer.app",
            kind = ScanTarget.Kind.APP,
            permissions = listOf(
                DangerousPermission.READ_CLIPBOARD,
                DangerousPermission.BIND_ACCESSIBILITY_SERVICE,
            ),
        )
        val findings = scanner.scan(target)
        assertEquals(Severity.HIGH, findings[0].severity)
        assertTrue(findings[0].confidence > 0.9)
    }

    @Test
    fun `suspicious host triggers C2 finding`() {
        val target = ScanTarget(
            id = "com.c2.app",
            kind = ScanTarget.Kind.APP,
            events = listOf(
                BehaviorEvent(
                    type = BehaviorEvent.Type.NETWORK,
                    timestamp = 0,
                    host = "evil.xyz",
                    port = 443,
                ),
            ),
        )
        val findings = scanner.scan(target)
        val c2 = findings.find { it.ruleId == "BEH_C2_NETWORK" }
        assertNotNull(c2)
        assertEquals(ThreatCategory.C2, c2.category)
        assertEquals(Severity.HIGH, c2.severity)
    }

    @Test
    fun `raw IP host triggers C2 finding`() {
        val target = ScanTarget(
            id = "com.ip.app",
            kind = ScanTarget.Kind.APP,
            events = listOf(
                BehaviorEvent(
                    type = BehaviorEvent.Type.NETWORK,
                    timestamp = 0,
                    host = "192.168.1.1",
                ),
            ),
        )
        val findings = scanner.scan(target)
        assertTrue(findings.any { it.ruleId == "BEH_C2_NETWORK" })
    }

    @Test
    fun `large transfer triggers anomalous transfer finding`() {
        val target = ScanTarget(
            id = "com.transfer.app",
            kind = ScanTarget.Kind.APP,
            events = listOf(
                BehaviorEvent(
                    type = BehaviorEvent.Type.CRYPTO_TRANSACTION,
                    timestamp = 0,
                    amountLamports = 10_000_000_000L, // 10 SOL
                    targetAddress = "SomeAddr111111111111111111111111111111111",
                ),
            ),
        )
        val findings = scanner.scan(target)
        val transfer = findings.find { it.ruleId == "BEH_ANOMALOUS_TRANSFER" }
        assertNotNull(transfer)
        assertEquals(ThreatCategory.DRAINER, transfer.category)
    }

    @Test
    fun `unsigned binary load triggers injection finding`() {
        val target = ScanTarget(
            id = "com.inject.app",
            kind = ScanTarget.Kind.APP,
            events = listOf(
                BehaviorEvent(
                    type = BehaviorEvent.Type.BINARY_LOAD,
                    timestamp = 0,
                    unsigned = true,
                    source = "/data/data/com.evil/lib.so",
                ),
            ),
        )
        val findings = scanner.scan(target)
        assertTrue(findings.any { it.ruleId == "BEH_BINARY_INJECTION" })
    }

    @Test
    fun `repeated clipboard access triggers hijack finding`() {
        val target = ScanTarget(
            id = "com.clip.app",
            kind = ScanTarget.Kind.APP,
            events = (1..3).map {
                BehaviorEvent(type = BehaviorEvent.Type.CLIPBOARD_ACCESS, timestamp = it.toLong())
            },
        )
        val findings = scanner.scan(target)
        assertTrue(findings.any { it.ruleId == "BEH_CLIPBOARD_HIJACK" })
    }
}
