package com.daemonblockint.sync.engine.yara

/**
 * Rule Manager (PRD core module `yara/`, FR-15).
 *
 * Owns the live YARA rule set: bundled Solana rules plus user/custom rules.
 * Supports add / remove / list / export and hands out a configured YaraScanner.
 */
class RuleManager(initial: List<YaraRule> = SOLANA_YARA_RULES) {
    private val rules = linkedMapOf<String, YaraRule>()

    init {
        for (r in initial) rules[r.name] = r
    }

    fun list(): List<YaraRule> = rules.values.toList()

    fun get(name: String): YaraRule? = rules[name]

    /** Add or replace a (custom) rule. Throws on a structurally invalid rule. */
    fun add(rule: YaraRule) {
        validate(rule)
        rules[rule.name] = rule
    }

    fun remove(name: String): Boolean = rules.remove(name) != null

    /** Build a scanner over the current rule set. */
    fun scanner(): YaraScanner = YaraScanner(list())

    /** Export all rules in YARA source format (FR-15, PRD 5.3). */
    fun exportAll(): String = list().joinToString("\n\n") { YaraScanner.exportRule(it) }

    companion object {
        fun validate(rule: YaraRule) {
            require(rule.name.isNotEmpty() && Regex("^[A-Za-z_][A-Za-z0-9_]*$").matches(rule.name)) {
                "Invalid YARA rule name: ${rule.name}"
            }
            require(rule.strings.isNotEmpty()) {
                "Rule ${rule.name} must declare at least one string"
            }
            if (rule.condition is YaraCondition.AtLeast) {
                require(rule.condition.n <= rule.strings.size) {
                    "Rule ${rule.name}: condition 'atLeast' exceeds number of strings"
                }
            }
            for (s in rule.strings) {
                if (s.type == YaraString.Type.REGEX) {
                    try { Regex(s.value) } catch (e: Exception) {
                        throw IllegalArgumentException("Rule ${rule.name}: invalid regex in ${s.id}", e)
                    }
                }
            }
        }
    }
}
