package com.daemonblockint.sync.engine.threatdb

/** In-memory backend — the default, dependency-free store. */
class InMemoryBackend : ThreatStoreBackend {
    private val records = mutableMapOf<String, ThreatRecord>()
    private val meta = mutableMapOf<String, String>()

    override fun upsert(records: List<ThreatRecord>) {
        for (r in records) this.records[r.indicator] = r
    }

    override fun get(indicator: String): ThreatRecord? = records[indicator]

    override fun list(): List<ThreatRecord> = records.values.toList()

    override fun remove(indicator: String): Boolean = records.remove(indicator) != null

    override fun purgeExpired(now: Long): Int {
        val toRemove = records.entries.filter { (_, r) ->
            r.expiresAt != null && r.expiresAt <= now
        }
        for ((k, _) in toRemove) records.remove(k)
        return toRemove.size
    }

    override fun getMeta(key: String): String? = meta[key]

    override fun setMeta(key: String, value: String) { meta[key] = value }

    override fun close() {
        records.clear()
        meta.clear()
    }
}
