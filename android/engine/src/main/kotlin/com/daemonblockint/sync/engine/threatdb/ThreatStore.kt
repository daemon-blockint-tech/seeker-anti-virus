package com.daemonblockint.sync.engine.threatdb

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget

private const val VERSION_KEY = "bundle_version"

/**
 * On-device threat database (PRD §8, FR-8/FR-9).
 *
 * A local cache of threat-intelligence records over a pluggable
 * ThreatStoreBackend (in-memory or SQLite). Acts as an extra detection
 * input via scan, returning normalized Findings for any stored
 * indicator that matches a scan target.
 */
class ThreatStore(
    private val backend: ThreatStoreBackend = InMemoryBackend(),
) {
    /** Add or replace threat records. */
    fun add(records: List<ThreatRecord>) {
        backend.upsert(records)
    }

    /** Look up a single indicator, ignoring (and not returning) expired records. */
    fun lookup(indicator: String, now: Long = System.currentTimeMillis()): ThreatRecord? {
        val rec = backend.get(indicator) ?: return null
        if (rec.expiresAt != null && rec.expiresAt <= now) return null
        return rec
    }

    /**
     * Match a scan target's indicators (id, domain, and any program ids in its
     * events) against the store, producing findings for live records.
     */
    fun scan(target: ScanTarget, now: Long = System.currentTimeMillis()): List<Finding> {
        val indicators = linkedSetOf<String>()
        indicators.add(target.id)
        target.domain?.let { indicators.add(it) }
        for (ev in target.events) {
            ev.programId?.let { indicators.add(it) }
            ev.targetAddress?.let { indicators.add(it) }
        }

        val findings = mutableListOf<Finding>()
        for (indicator in indicators) {
            val rec = lookup(indicator, now) ?: continue
            findings.add(
                Finding(
                    source = Finding.Source.SIGNATURE,
                    ruleId = "THREATDB:${rec.id}",
                    title = "Known threat: ${rec.id}",
                    description = rec.description,
                    category = rec.category,
                    severity = rec.severity,
                    confidence = 0.97,
                    evidence = buildList {
                        add("${rec.indicatorKind}:${rec.indicator}")
                        rec.source?.let { add("source:$it") }
                    },
                ),
            )
        }
        return findings
    }

    /** Remove expired records; returns how many were purged. */
    fun purgeExpired(now: Long = System.currentTimeMillis()): Int =
        backend.purgeExpired(now)

    /** The applied bundle version (0 if none). */
    var version: Int
        get() = backend.getMeta(VERSION_KEY)?.toIntOrNull() ?: 0
        set(v) { backend.setMeta(VERSION_KEY, v.toString()) }

    val size: Int get() = backend.list().size

    fun close() { backend.close() }
}
