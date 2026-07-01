package com.daemonblockint.sync.engine.signatures

import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SignatureMatcherTest {

    private val matcher = SignatureMatcher()

    @Test
    fun `default signatures are loaded`() {
        assertTrue(matcher.size > 0)
    }

    @Test
    fun `indicator match produces finding`() {
        val target = ScanTarget(
            id = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            kind = ScanTarget.Kind.CONTRACT,
        )
        val findings = matcher.scan(target)
        val drainer = findings.find { it.ruleId == "SIG_DRAINER_SETAUTHORITY" }
        assertNotNull(drainer)
        assertEquals(Severity.CRITICAL, drainer.severity)
        assertTrue(drainer.confidence >= 0.9)
    }

    @Test
    fun `domain match produces phishing finding`() {
        val target = ScanTarget(
            id = "https://s0lana.xyz/claim",
            kind = ScanTarget.Kind.URL,
            domain = "s0lana.xyz",
        )
        val findings = matcher.scan(target)
        val phishing = findings.find { it.ruleId == "SIG_PHISHING_LOOKALIKE" }
        assertNotNull(phishing)
        assertEquals(Severity.HIGH, phishing.severity)
    }

    @Test
    fun `pattern match in text produces finding`() {
        val target = ScanTarget(
            id = "some-contract",
            kind = ScanTarget.Kind.CONTRACT,
            text = "mint_authority = Some(pubkey)",
        )
        val findings = matcher.scan(target)
        assertTrue(findings.any { it.ruleId == "SIG_RUG_PULL_MINT_AUTH" })
    }

    @Test
    fun `clean target produces no findings`() {
        val target = ScanTarget(
            id = "com.clean.app",
            kind = ScanTarget.Kind.APP,
            text = "Hello world",
        )
        assertEquals(0, matcher.scan(target).size)
    }

    @Test
    fun `upsert adds new signatures`() {
        val initial = matcher.size
        matcher.upsert(listOf(
            ThreatSignature(
                id = "SIG_CUSTOM_TEST",
                name = "Custom test signature",
                category = com.daemonblockint.sync.engine.ThreatCategory.MALWARE,
                severity = Severity.MEDIUM,
                indicators = listOf("custom-indicator-123"),
                description = "Test",
            ),
        ))
        assertEquals(initial + 1, matcher.size)
    }
}
