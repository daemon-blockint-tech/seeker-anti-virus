package com.daemonblockint.sync.engine.signatures

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget

/** Normalize a domain for look-alike comparison. */
private fun normalizeDomain(input: String): String =
    input.trim()
        .lowercase()
        .removePrefix("https://")
        .removePrefix("http://")
        .removePrefix("www.")
        .substringBefore("/")
        .substringBefore(":")

/**
 * Signature Matcher (PRD 5.2).
 *
 * Fast lookup of a target's text / domain / indicators against the curated
 * signature database. Designed for the <30 ms/event budget.
 */
class SignatureMatcher(
    private val signatures: MutableList<ThreatSignature> = DEFAULT_SIGNATURES.toMutableList(),
) {
    /** Add or replace signatures (e.g. after a signed OTA update). */
    fun upsert(newSigs: List<ThreatSignature>) {
        for (sig in newSigs) {
            val idx = signatures.indexOfFirst { it.id == sig.id }
            if (idx >= 0) signatures[idx] = sig else signatures.add(sig)
        }
    }

    val size: Int get() = signatures.size

    fun scan(target: ScanTarget): List<Finding> {
        val findings = mutableListOf<Finding>()
        val text = target.text ?: ""
        val domain = target.domain ?: if (target.kind == ScanTarget.Kind.URL) target.id else null
        val normDomain = domain?.let { normalizeDomain(it) }

        for (sig in signatures) {
            val evidence = mutableListOf<String>()

            if (target.id in sig.indicators) {
                evidence.add("indicator:${target.id}")
            }

            if (normDomain != null && sig.domains.isNotEmpty()) {
                for (d in sig.domains) {
                    if (normalizeDomain(d) == normDomain) evidence.add("domain:$d")
                }
            }

            if (sig.patterns.isNotEmpty() && text.isNotEmpty()) {
                for (re in sig.patterns) {
                    val m = re.find(text)
                    if (m != null) evidence.add("pattern:${m.value.take(60)}")
                }
            }

            if (evidence.isNotEmpty()) {
                findings.add(
                    Finding(
                        source = Finding.Source.SIGNATURE,
                        ruleId = sig.id,
                        title = sig.name,
                        description = sig.description,
                        category = sig.category,
                        severity = sig.severity,
                        confidence = if (evidence.any { it.startsWith("pattern:") }) 0.8 else 0.95,
                        evidence = evidence,
                    ),
                )
            }
        }

        return findings
    }
}
