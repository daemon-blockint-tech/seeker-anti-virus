package com.daemonblockint.sync.engine.threatdb

import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory
import com.daemonblockint.sync.engine.signatures.ThreatSignature
import com.daemonblockint.sync.engine.yara.YaraRule

/** Kind of indicator a ThreatRecord matches on. */
enum class IndicatorKind { ADDRESS, DOMAIN, PROGRAM, HASH }

/** A single piece of threat intelligence stored on-device. */
data class ThreatRecord(
    val id: String,
    val indicator: String,
    val indicatorKind: IndicatorKind,
    val category: ThreatCategory,
    val severity: Severity,
    val description: String,
    val source: String? = null,
    val addedAt: Long,
    val expiresAt: Long? = null,
)

/** A threat-intelligence update bundle. */
data class ThreatBundle(
    val version: Int,
    val createdAt: Long,
    val threats: List<ThreatRecord>? = null,
    val signatures: List<ThreatSignature>? = null,
    val yaraRules: List<YaraRule>? = null,
)

/** A ThreatBundle wrapped with a detached signature over its payload. */
data class SignedBundle(
    val keyId: String,
    val algorithm: String, // "ed25519"
    val payload: String,
    val signature: String, // base64
)

/** Backend persistence contract — synchronous to suit an on-device runtime. */
interface ThreatStoreBackend {
    fun upsert(records: List<ThreatRecord>)
    fun get(indicator: String): ThreatRecord?
    fun list(): List<ThreatRecord>
    fun remove(indicator: String): Boolean
    fun purgeExpired(now: Long): Int
    fun getMeta(key: String): String?
    fun setMeta(key: String, value: String)
    fun close()
}
