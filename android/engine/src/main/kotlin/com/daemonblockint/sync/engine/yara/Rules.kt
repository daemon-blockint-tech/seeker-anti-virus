package com.daemonblockint.sync.engine.yara

import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory

/** A single string condition inside a YARA-style rule. */
data class YaraString(
    val id: String,
    val value: String,
    val type: Type,
    val nocase: Boolean = false,
) {
    enum class Type { TEXT, REGEX, HEX }
}

/** Condition for a YARA rule: all, any, or at-least-N. */
sealed interface YaraCondition {
    data object All : YaraCondition
    data object Any : YaraCondition
    data class AtLeast(val n: Int) : YaraCondition
}

/** A YARA-compatible rule. */
data class YaraRule(
    val name: String,
    val category: ThreatCategory,
    val severity: Severity,
    val meta: YaraMeta,
    val strings: List<YaraString>,
    val condition: YaraCondition,
)

data class YaraMeta(
    val description: String,
    val author: String? = null,
    val reference: String? = null,
)

/** The 8 Solana-specific YARA rules from the PRD (section 5.3). */
val SOLANA_YARA_RULES: List<YaraRule> = listOf(
    YaraRule(
        name = "Sync_Wallet_Stealer",
        category = ThreatCategory.MALWARE,
        severity = Severity.CRITICAL,
        meta = YaraMeta(description = "Seed / private-key extraction and exfiltration."),
        strings = listOf(
            YaraString("$m1", "mnemonic", YaraString.Type.TEXT, nocase = true),
            YaraString("$m2", "seed_phrase", YaraString.Type.TEXT, nocase = true),
            YaraString("$m3", "secretKey", YaraString.Type.TEXT),
            YaraString("$x1", "(POST|fetch).{0,40}https?://", YaraString.Type.REGEX, nocase = true),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
    YaraRule(
        name = "Sync_Rug_Pull_Contract",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.CRITICAL,
        meta = YaraMeta(description = "Liquidity drain plus hidden owner logic."),
        strings = listOf(
            YaraString("$a", "remove_liquidity", YaraString.Type.TEXT, nocase = true),
            YaraString("$b", "only_owner", YaraString.Type.TEXT, nocase = true),
            YaraString("$c", "mint_authority", YaraString.Type.TEXT, nocase = true),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
    YaraRule(
        name = "Sync_Honeypot_Token",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.CRITICAL,
        meta = YaraMeta(description = "Sell restrictions plus backdoors."),
        strings = listOf(
            YaraString("$s1", "can_sell", YaraString.Type.TEXT, nocase = true),
            YaraString("$s2", "is_whitelisted", YaraString.Type.TEXT, nocase = true),
            YaraString("$s3", "transfer_hook", YaraString.Type.TEXT, nocase = true),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
    YaraRule(
        name = "Sync_Flash_Loan_Attack",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.HIGH,
        meta = YaraMeta(description = "Price manipulation with same-block repay."),
        strings = listOf(
            YaraString("$f1", "flash_loan", YaraString.Type.TEXT, nocase = true),
            YaraString("$f2", "borrow", YaraString.Type.TEXT, nocase = true),
            YaraString("$f3", "repay", YaraString.Type.TEXT, nocase = true),
        ),
        condition = YaraCondition.All,
    ),
    YaraRule(
        name = "Sync_Bridge_Exploit",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.CRITICAL,
        meta = YaraMeta(description = "Signature bypass and drain on a bridge program."),
        strings = listOf(
            YaraString("$b1", "skip_verification", YaraString.Type.TEXT, nocase = true),
            YaraString("$b2", "verify_signature = false", YaraString.Type.TEXT, nocase = true),
            YaraString("$b3", "release_funds", YaraString.Type.TEXT, nocase = true),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
    YaraRule(
        name = "Sync_NFT_Scam",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.HIGH,
        meta = YaraMeta(description = "Fraudulent mint plus fee extraction."),
        strings = listOf(
            YaraString("$n1", "hidden_fee", YaraString.Type.TEXT, nocase = true),
            YaraString("$n2", "unlimited_mint", YaraString.Type.TEXT, nocase = true),
            YaraString("$n3", "set_authority", YaraString.Type.TEXT, nocase = true),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
    YaraRule(
        name = "Sync_Mobile_Keylogger",
        category = ThreatCategory.MALWARE,
        severity = Severity.CRITICAL,
        meta = YaraMeta(description = "Input capture and exfiltration."),
        strings = listOf(
            YaraString("$k1", "AccessibilityService", YaraString.Type.TEXT),
            YaraString("$k2", "onKeyEvent", YaraString.Type.TEXT),
            YaraString("$k3", "getClipboardData", YaraString.Type.TEXT),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
    YaraRule(
        name = "Sync_Remote_Access_Trojan",
        category = ThreatCategory.TROJAN,
        severity = Severity.CRITICAL,
        meta = YaraMeta(description = "C2 socket plus command loop."),
        strings = listOf(
            YaraString("$r1", "Socket", YaraString.Type.TEXT),
            YaraString("$r2", "gate.php", YaraString.Type.TEXT, nocase = true),
            YaraString("$r3", "exec(", YaraString.Type.TEXT),
            YaraString("$r4", "while.{0,20}recv", YaraString.Type.REGEX, nocase = true),
        ),
        condition = YaraCondition.AtLeast(2),
    ),
)
