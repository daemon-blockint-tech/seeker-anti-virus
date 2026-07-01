package com.daemonblockint.sync.engine

/** Severity buckets, aligned with the PRD risk-scoring table (section 11). */
enum class Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    companion object {
        /** Map a 0–100 score to a severity bucket (PRD section 11). */
        fun fromScore(score: Int): Severity = when {
            score >= 80 -> CRITICAL
            score >= 60 -> HIGH
            score >= 40 -> MEDIUM
            else -> LOW
        }

        /** Numeric weight ceiling per severity (PRD section 11). */
        fun scoreCeiling(s: Severity): Int = when (s) {
            LOW -> 20
            MEDIUM -> 50
            HIGH -> 70
            CRITICAL -> 95
        }

        val rank: Map<Severity, Int> = mapOf(LOW to 0, MEDIUM to 1, HIGH to 2, CRITICAL to 3)
    }
}

/** High-level threat taxonomy used across signatures and YARA rules. */
enum class ThreatCategory {
    MALWARE, SPYWARE, TROJAN, EXPLOIT, PHISHING,
    RUG_PULL, HONEYPOT, DRAINER, PERMISSION_ABUSE, C2, UNKNOWN
}

/** Android-style dangerous permissions Sync watches for. */
enum class DangerousPermission {
    READ_CONTACTS, READ_SMS, RECEIVE_SMS, RECORD_AUDIO,
    ACCESS_FINE_LOCATION, CAMERA, READ_CLIPBOARD,
    SYSTEM_ALERT_WINDOW, BIND_ACCESSIBILITY_SERVICE,
    QUERY_ALL_PACKAGES, REQUEST_INSTALL_PACKAGES
}

/** A single observed runtime event from a monitored app. */
data class BehaviorEvent(
    val type: Type,
    val timestamp: Long,
    val permission: DangerousPermission? = null,
    val host: String? = null,
    val port: Int? = null,
    val amountLamports: Long? = null,
    val targetAddress: String? = null,
    val programId: String? = null,
    val source: String? = null,
    val unsigned: Boolean? = null,
    val meta: Map<String, Any?> = emptyMap(),
) {
    enum class Type {
        PERMISSION_REQUEST, NETWORK, CRYPTO_TRANSACTION,
        BINARY_LOAD, CLIPBOARD_ACCESS, ACCESSIBILITY
    }
}

/** Target being scanned. */
data class ScanTarget(
    val id: String,
    val kind: Kind,
    val label: String? = null,
    val bytes: ByteArray? = null,
    val text: String? = null,
    val events: MutableList<BehaviorEvent> = mutableListOf(),
    val permissions: List<DangerousPermission> = emptyList(),
    val domain: String? = null,
) {
    enum class Kind { APP, CONTRACT, TOKEN, URL, TRANSACTION }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ScanTarget) return false
        return id == other.id && kind == other.kind && label == other.label
    }

    override fun hashCode(): Int = id.hashCode() * 31 + kind.hashCode()
}

/** A normalized finding emitted by any detection layer. */
data class Finding(
    val source: Source,
    val ruleId: String,
    val title: String,
    val description: String,
    val category: ThreatCategory,
    val severity: Severity,
    val confidence: Double,
    val evidence: List<String> = emptyList(),
) {
    enum class Source { BEHAVIORAL, SIGNATURE, YARA, LLM }
}
