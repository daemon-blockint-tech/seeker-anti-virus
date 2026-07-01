package com.daemonblockint.sync.engine

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TypesTest {

    @Test
    fun `scoreToSeverity maps correctly`() {
        assertEquals(Severity.CRITICAL, Severity.fromScore(80))
        assertEquals(Severity.CRITICAL, Severity.fromScore(100))
        assertEquals(Severity.HIGH, Severity.fromScore(60))
        assertEquals(Severity.HIGH, Severity.fromScore(79))
        assertEquals(Severity.MEDIUM, Severity.fromScore(40))
        assertEquals(Severity.MEDIUM, Severity.fromScore(59))
        assertEquals(Severity.LOW, Severity.fromScore(0))
        assertEquals(Severity.LOW, Severity.fromScore(39))
    }

    @Test
    fun `severity score ceiling is correct`() {
        assertEquals(20, Severity.scoreCeiling(Severity.LOW))
        assertEquals(50, Severity.scoreCeiling(Severity.MEDIUM))
        assertEquals(70, Severity.scoreCeiling(Severity.HIGH))
        assertEquals(95, Severity.scoreCeiling(Severity.CRITICAL))
    }

    @Test
    fun `severity rank is ordered`() {
        assertTrue(Severity.rank[Severity.LOW]!! < Severity.rank[Severity.MEDIUM]!!)
        assertTrue(Severity.rank[Severity.MEDIUM]!! < Severity.rank[Severity.HIGH]!!)
        assertTrue(Severity.rank[Severity.HIGH]!! < Severity.rank[Severity.CRITICAL]!!)
    }
}
