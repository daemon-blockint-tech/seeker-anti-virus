package com.daemonblockint.sync.yara

import com.daemonblockint.sync.engine.Finding
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.ThreatCategory
import com.daemonblockint.sync.engine.yara.YaraRule
import com.daemonblockint.sync.engine.yara.YaraScanner

/**
 * Bridge between the native libyara engine and the Kotlin detection engine.
 *
 * When libyara is available (loaded via [YaraNative.loadLibrary]), this class
 * compiles rules into native YARA and scans byte buffers through the JNI bridge.
 * When libyara is not available (stub), it falls back to the pure-Kotlin
 * YaraScanner so the engine always works.
 */
class NativeYaraBridge(
    private val rules: List<YaraRule> = com.daemonblockint.sync.engine.yara.SOLANA_YARA_RULES,
) {
    private var nativeHandle: Long = 0
    private var useNative: Boolean = false
    private val fallbackScanner: YaraScanner = YaraScanner(rules)

    /**
     * Initialize the native YARA engine. Call once at startup.
     * @return true if native YARA is active, false if using Kotlin fallback.
     */
    fun init(): Boolean {
        return try {
            YaraNative.loadLibrary()
            val rulesText = rules.joinToString("\n\n") { YaraScanner.exportRule(it) }
            nativeHandle = YaraNative.loadRules(rulesText)
            useNative = nativeHandle != 0L
            useNative
        } catch (e: Throwable) {
            // Native library not available — use Kotlin fallback
            useNative = false
            false
        }
    }

    /** Whether the native libyara engine is active. */
    val isNativeActive: Boolean get() = useNative

    /** Scan a target using native YARA or Kotlin fallback. */
    fun scan(target: ScanTarget): List<Finding> {
        if (!useNative || nativeHandle == 0L) {
            return fallbackScanner.scan(target)
        }

        val data = target.bytes ?: target.text?.toByteArray()
        if (data == null || data.isEmpty()) return emptyList()

        val matchIndices = YaraNative.scan(data, nativeHandle) ?: return emptyList()

        // Map native match indices back to rules and produce Findings.
        // The native engine returns rule indices in the order they were compiled.
        val findings = mutableListOf<Finding>()
        for (idx in matchIndices) {
            val rule = rules.getOrNull(idx) ?: continue
            findings.add(
                Finding(
                    source = Finding.Source.YARA,
                    ruleId = rule.name,
                    title = rule.name.removePrefix("Sync_").replace('_', ' '),
                    description = rule.meta.description,
                    category = rule.category,
                    severity = rule.severity,
                    confidence = 0.95,
                    evidence = listOf("native:yara"),
                ),
            )
        }
        return findings
    }

    /** Release native resources. */
    fun close() {
        if (nativeHandle != 0L) {
            YaraNative.cleanup(nativeHandle)
            nativeHandle = 0
        }
    }
}
