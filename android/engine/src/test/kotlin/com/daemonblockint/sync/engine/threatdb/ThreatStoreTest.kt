package com.daemonblockint.sync.engine.threatdb

import com.daemonblockint.sync.engine.BehaviorEvent
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ThreatStoreTest {

    private fun makeRecord(
        indicator: String = "evil.com",
        kind: IndicatorKind = IndicatorKind.DOMAIN,
        severity: Severity = Severity.HIGH,
        expiresAt: Long? = null,
    ) = ThreatRecord(
        id = "test-1",
        indicator = indicator,
        indicatorKind = kind,
        category = ThreatCategory.PHISHING,
        severity = severity,
        description = "Test threat",
        addedAt = 1000L,
        expiresAt = expiresAt,
    )

    @Test
    fun `add and lookup works`() {
        val store = ThreatStore()
        store.add(listOf(makeRecord()))
        val rec = store.lookup("evil.com")
        assertNotNull(rec)
        assertEquals("test-1", rec.id)
    }

    @Test
    fun `expired records are not returned`() {
        val store = ThreatStore()
        store.add(listOf(makeRecord(expiresAt = 500L)))
        assertNull(store.lookup("evil.com", now = 1000L))
    }

    @Test
    fun `scan matches target indicators`() {
        val store = ThreatStore()
        store.add(listOf(
            makeRecord(indicator = "known-bad-program", kind = IndicatorKind.PROGRAM),
        ))
        val target = ScanTarget(
            id = "test",
            kind = ScanTarget.Kind.TRANSACTION,
            events = mutableListOf(
                BehaviorEvent(
                    type = BehaviorEvent.Type.CRYPTO_TRANSACTION,
                    timestamp = 0,
                    programId = "known-bad-program",
                ),
            ),
        )
        val findings = store.scan(target)
        assertTrue(findings.isNotEmpty())
        assertTrue(findings[0].ruleId.startsWith("THREATDB:"))
    }

    @Test
    fun `purgeExpired removes old records`() {
        val store = ThreatStore()
        store.add(listOf(
            makeRecord(indicator = "old.com", expiresAt = 500L),
            makeRecord(indicator = "new.com", expiresAt = Long.MAX_VALUE),
        ))
        val purged = store.purgeExpired(now = 1000L)
        assertEquals(1, purged)
        assertNotNull(store.lookup("new.com"))
        assertNull(store.lookup("old.com"))
    }

    @Test
    fun `version tracking works`() {
        val store = ThreatStore()
        assertEquals(0, store.version)
        store.version = 42
        assertEquals(42, store.version)
    }
}

