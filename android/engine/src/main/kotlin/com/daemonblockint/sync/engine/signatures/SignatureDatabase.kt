package com.daemonblockint.sync.engine.signatures

import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory

/** A known-threat signature: matched against target text/domain/addresses. */
data class ThreatSignature(
    val id: String,
    val name: String,
    val category: ThreatCategory,
    val severity: Severity,
    val patterns: List<Regex> = emptyList(),
    val indicators: List<String> = emptyList(),
    val domains: List<String> = emptyList(),
    val description: String,
)

/**
 * Curated database of known Solana-ecosystem threat patterns (PRD 5.2).
 * In production delivered via signed OTA updates; these seed the on-device matcher.
 */
val DEFAULT_SIGNATURES: List<ThreatSignature> = listOf(
    ThreatSignature(
        id = "SIG_RUG_PULL_MINT_AUTH",
        name = "Rug pull — retained mint authority",
        category = ThreatCategory.RUG_PULL,
        severity = Severity.CRITICAL,
        patterns = listOf(
            Regex("mint[_-]?authority\\s*[:=].*(?!null)", RegexOption.IGNORE_CASE),
            Regex("set_authority\\s*\\(\\s*MintTokens", RegexOption.IGNORE_CASE),
        ),
        description = "Token retains an active mint authority, allowing the owner to inflate supply and drain liquidity.",
    ),
    ThreatSignature(
        id = "SIG_HONEYPOT_SELL_BLOCK",
        name = "Honeypot — sell restriction",
        category = ThreatCategory.HONEYPOT,
        severity = Severity.CRITICAL,
        patterns = listOf(
            Regex("require\\s*\\(\\s*is_whitelisted", RegexOption.IGNORE_CASE),
            Regex("transfer_hook.*block.*sell", RegexOption.IGNORE_CASE),
            Regex("can_sell\\s*=\\s*false", RegexOption.IGNORE_CASE),
        ),
        description = "Contract blocks or whitelists sells, letting buyers in but trapping their funds.",
    ),
    ThreatSignature(
        id = "SIG_DRAINER_SETAUTHORITY",
        name = "Wallet drainer — token account delegation",
        category = ThreatCategory.DRAINER,
        severity = Severity.CRITICAL,
        indicators = listOf("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        patterns = listOf(
            Regex("approve\\s*\\(.*max.*\\)", RegexOption.IGNORE_CASE),
            Regex("set_authority.*AccountOwner", RegexOption.IGNORE_CASE),
        ),
        description = "Requests unlimited delegation/approval over token accounts — the core drainer primitive.",
    ),
    ThreatSignature(
        id = "SIG_BRIDGE_SIG_BYPASS",
        name = "Bridge exploit — signature bypass",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.CRITICAL,
        patterns = listOf(
            Regex("verify_signature\\s*=\\s*false", RegexOption.IGNORE_CASE),
            Regex("skip[_-]?verification", RegexOption.IGNORE_CASE),
        ),
        description = "Bridge program skips signature verification before releasing funds.",
    ),
    ThreatSignature(
        id = "SIG_FLASHLOAN_SAMEBLOCK",
        name = "Flash-loan price manipulation",
        category = ThreatCategory.EXPLOIT,
        severity = Severity.HIGH,
        patterns = listOf(
            Regex("flash_?loan", RegexOption.IGNORE_CASE),
            Regex("same[_-]?block.*repay", RegexOption.IGNORE_CASE),
        ),
        description = "Same-block borrow/repay pattern used to manipulate oracle prices.",
    ),
    ThreatSignature(
        id = "SIG_PHISHING_LOOKALIKE",
        name = "Phishing — look-alike domain",
        category = ThreatCategory.PHISHING,
        severity = Severity.HIGH,
        domains = listOf("s0lana.xyz", "phantom-wallet.app", "magiceden-mint.com", "jupiter-swap.xyz"),
        description = "Domain impersonates a well-known Solana brand to harvest approvals or seed phrases.",
    ),
    ThreatSignature(
        id = "SIG_C2_BEACON",
        name = "C2 malware beacon",
        category = ThreatCategory.C2,
        severity = Severity.CRITICAL,
        patterns = listOf(
            Regex("/gate\\.php", RegexOption.IGNORE_CASE),
            Regex("beacon.*interval", RegexOption.IGNORE_CASE),
            Regex("cmd_?exec", RegexOption.IGNORE_CASE),
        ),
        description = "Command-and-control beaconing patterns associated with RAT malware.",
    ),
    ThreatSignature(
        id = "SIG_SEED_EXFIL",
        name = "Seed-phrase exfiltration",
        category = ThreatCategory.SPYWARE,
        severity = Severity.CRITICAL,
        patterns = listOf(
            Regex("(mnemonic|seed[_-]?phrase|secret[_-]?key)\\s*[:=]", RegexOption.IGNORE_CASE),
            Regex("bip39", RegexOption.IGNORE_CASE),
        ),
        description = "Code references mnemonic/secret-key material alongside network egress.",
    ),
)
