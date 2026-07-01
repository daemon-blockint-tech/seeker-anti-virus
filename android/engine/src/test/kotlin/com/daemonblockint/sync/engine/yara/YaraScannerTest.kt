package com.daemonblockint.sync.engine.yara

import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class YaraScannerTest {

    @Test
    fun `wallet stealer rule matches seed phrase text`() {
        val scanner = YaraScanner(SOLANA_YARA_RULES)
        val target = ScanTarget(
            id = "test",
            kind = ScanTarget.Kind.APP,
            text = "const mnemonic = 'abandon abandon abandon'; fetch('https://evil.com')",
        )
        val findings = scanner.scan(target)
        val steal = findings.find { it.ruleId == "Sync_Wallet_Stealer" }
        assertNotNull(steal)
        assertEquals(Severity.CRITICAL, steal!!.severity)
    }

    @Test
    fun `rug pull rule matches liquidity drain text`() {
        val scanner = YaraScanner(SOLANA_YARA_RULES)
        val target = ScanTarget(
            id = "test",
            kind = ScanTarget.Kind.CONTRACT,
            text = "function drain() { remove_liquidity(); only_owner; mint_authority; }",
        )
        val findings = scanner.scan(target)
        assertTrue(findings.any { it.ruleId == "Sync_Rug_Pull_Contract" })
    }

    @Test
    fun `flash loan requires all three strings`() {
        val scanner = YaraScanner(SOLANA_YARA_RULES)
        // Only 2 of 3 — should NOT match (condition is "all")
        val target = ScanTarget(
            id = "test",
            kind = ScanTarget.Kind.CONTRACT,
            text = "flash_loan borrow",
        )
        val findings = scanner.scan(target)
        assertTrue(findings.none { it.ruleId == "Sync_Flash_Loan_Attack" })

        // All 3 — should match
        val target2 = target.copy(text = "flash_loan borrow repay")
        assertTrue(scanner.scan(target2).any { it.ruleId == "Sync_Flash_Loan_Attack" })
    }

    @Test
    fun `clean text produces no findings`() {
        val scanner = YaraScanner(SOLANA_YARA_RULES)
        val target = ScanTarget(id = "test", kind = ScanTarget.Kind.APP, text = "Hello world")
        assertEquals(0, scanner.scan(target).size)
    }

    @Test
    fun `exportRule produces valid YARA syntax`() {
        val rule = SOLANA_YARA_RULES[0]
        val exported = YaraScanner.exportRule(rule)
        assertTrue(exported.startsWith("rule ${rule.name} {"))
        assertTrue(exported.contains("meta:"))
        assertTrue(exported.contains("strings:"))
        assertTrue(exported.contains("condition:"))
        assertTrue(exported.endsWith("}"))
    }
}

class RuleManagerTest {

    @Test
    fun `default rules are loaded`() {
        val mgr = RuleManager()
        assertEquals(8, mgr.list().size)
    }

    @Test
    fun `add and remove rules`() {
        val mgr = RuleManager()
        val custom = YaraRule(
            name = "Custom_Rule",
            category = com.daemonblockint.sync.engine.ThreatCategory.MALWARE,
            severity = Severity.HIGH,
            meta = YaraMeta(description = "Custom"),
            strings = listOf(YaraString("a", "evil", YaraString.Type.TEXT)),
            condition = YaraCondition.Any,
        )
        mgr.add(custom)
        assertEquals(9, mgr.list().size)
        assertTrue(mgr.remove("Custom_Rule"))
        assertEquals(8, mgr.list().size)
    }

    @Test
    fun `invalid rule name throws`() {
        val mgr = RuleManager()
        val bad = YaraRule(
            name = "123-Bad",
            category = com.daemonblockint.sync.engine.ThreatCategory.MALWARE,
            severity = Severity.HIGH,
            meta = YaraMeta(description = "Bad"),
            strings = listOf(YaraString("a", "evil", YaraString.Type.TEXT)),
            condition = YaraCondition.Any,
        )
        assertFailsWith<IllegalArgumentException> { mgr.add(bad) }
    }

    @Test
    fun `atLeast exceeding string count throws`() {
        val mgr = RuleManager()
        val bad = YaraRule(
            name = "Bad_Rule",
            category = com.daemonblockint.sync.engine.ThreatCategory.MALWARE,
            severity = Severity.HIGH,
            meta = YaraMeta(description = "Bad"),
            strings = listOf(YaraString("a", "evil", YaraString.Type.TEXT)),
            condition = YaraCondition.AtLeast(5),
        )
        assertFailsWith<IllegalArgumentException> { mgr.add(bad) }
    }

    @Test
    fun `exportAll produces all rules`() {
        val mgr = RuleManager()
        val exported = mgr.exportAll()
        val ruleCount = exported.split("\n\n").size
        assertEquals(8, ruleCount)
    }
}
