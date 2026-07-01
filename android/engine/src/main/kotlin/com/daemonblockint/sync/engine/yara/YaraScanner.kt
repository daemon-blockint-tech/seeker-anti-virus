package com.daemonblockint.sync.engine.yara

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity

/** Result of evaluating one rule against a buffer. */
data class YaraMatch(
    val rule: String,
    val matchedStrings: List<String>,
)

/** Decode raw bytes to a latin1 string so byte patterns survive intact. */
private fun bytesToText(bytes: ByteArray): String =
    String(bytes, Charsets.ISO_8859_1)

/** Build a matcher function for a YARA string. */
private fun buildMatcher(s: YaraString): (String) -> Boolean = when (s.type) {
    YaraString.Type.TEXT -> { haystack ->
        if (s.nocase) haystack.lowercase().contains(s.value.lowercase())
        else haystack.contains(s.value)
    }
    YaraString.Type.REGEX -> { haystack ->
        val re = Regex(s.value, if (s.nocase) setOf(RegexOption.IGNORE_CASE) else emptySet())
        re.containsMatchIn(haystack)
    }
    YaraString.Type.HEX -> { haystack ->
        val raw = s.value.replace(Regex("\\s+"), "")
            .chunked(2)
            .joinToString("") { b ->
                b.toInt(16).toChar().toString()
            }
        haystack.contains(raw)
    }
}

/**
 * YARA Scanner (PRD 5.3).
 *
 * A self-contained evaluator for the subset of YARA needed by Sync's bundled
 * rules (text/regex/hex strings; all / any / "N of them" conditions). Operates
 * on raw bytes or decoded text and is YARA-export compatible.
 */
class YaraScanner(private val rules: List<YaraRule>) {

    val ruleNames: List<String> get() = rules.map { it.name }

    /** Evaluate every rule against a buffer, returning raw matches. */
    fun matchBuffer(haystack: String): List<YaraMatch> {
        val matches = mutableListOf<YaraMatch>()
        for (rule in rules) {
            val hit = mutableListOf<String>()
            for (s in rule.strings) {
                if (buildMatcher(s)(haystack)) hit.add(s.id)
            }
            if (conditionMet(rule, hit.size, rule.strings.size)) {
                matches.add(YaraMatch(rule.name, hit))
            }
        }
        return matches
    }

    /** Scan a target's bytes and/or text, producing normalized findings. */
    fun scan(target: ScanTarget): List<Finding> {
        val haystacks = mutableListOf<String>()
        target.bytes?.let { haystacks.add(bytesToText(it)) }
        target.text?.let { haystacks.add(it) }
        if (haystacks.isEmpty()) return emptyList()

        val haystack = haystacks.joinToString("\n")
        val findings = mutableListOf<Finding>()

        for (match in matchBuffer(haystack)) {
            val rule = rules.find { it.name == match.rule }!!
            findings.add(
                Finding(
                    source = Finding.Source.YARA,
                    ruleId = rule.name,
                    title = rule.name.removePrefix("Sync_").replace('_', ' '),
                    description = rule.meta.description,
                    category = rule.category,
                    severity = rule.severity,
                    confidence = confidenceFor(rule, match.matchedStrings.size),
                    evidence = match.matchedStrings,
                ),
            )
        }

        return findings
    }

    private fun conditionMet(rule: YaraRule, hits: Int, total: Int): Boolean = when (val c = rule.condition) {
        is YaraCondition.All -> hits == total
        is YaraCondition.Any -> hits > 0
        is YaraCondition.AtLeast -> hits >= c.n
    }

    private fun confidenceFor(rule: YaraRule, hits: Int): Double {
        val total = rule.strings.size
        return minOf(0.98, 0.5 + 0.5 * (hits.toDouble() / maxOf(1, total)))
    }

    companion object {
        /** Export a rule in YARA source format for interoperability (PRD 5.3). */
        fun exportRule(rule: YaraRule): String {
            val lines = mutableListOf("rule ${rule.name} {", "  meta:")
            lines.add("    description = \"${rule.meta.description}\"")
            lines.add("    category = \"${rule.category}\"")
            lines.add("    severity = \"${rule.severity}\"")
            rule.meta.author?.let { lines.add("    author = \"$it\"") }
            lines.add("  strings:")
            for (s in rule.strings) {
                val mods = if (s.nocase) " nocase" else ""
                when (s.type) {
                    YaraString.Type.REGEX -> lines.add("    ${s.id} = /${s.value}/${if (s.nocase) "i" else ""}")
                    YaraString.Type.HEX -> lines.add("    ${s.id} = { ${s.value} }")
                    YaraString.Type.TEXT -> lines.add("    ${s.id} = \"${s.value}\"$mods")
                }
            }
            lines.add("  condition:")
            when (val c = rule.condition) {
                is YaraCondition.All -> lines.add("    all of them")
                is YaraCondition.Any -> lines.add("    any of them")
                is YaraCondition.AtLeast -> lines.add("    ${c.n} of them")
            }
            lines.add("}")
            return lines.joinToString("\n")
        }
    }
}
