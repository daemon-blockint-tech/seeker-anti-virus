package com.daemonblockint.sync.engine.threatdb

import com.daemonblockint.sync.engine.signatures.SignatureMatcher
import com.daemonblockint.sync.engine.yara.RuleManager
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class BundleVerificationError(message: String) : Exception(message)

/**
 * Verifies signed bundles against a set of trusted Ed25519 public keys
 * (PRD §7: "signed rule updates only").
 */
class BundleVerifier(trustedKeys: Map<String, String>) {
    private val keys = mutableMapOf<String, java.security.PublicKey>()

    init {
        for ((id, pem) in trustedKeys) {
            val keyBytes = extractKeyBytes(pem)
            keys[id] = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(keyBytes))
        }
    }

    /** Verify a signed bundle, returning the parsed bundle or throwing. */
    fun verify(signed: SignedBundle): ThreatBundle {
        require(signed.algorithm == "ed25519") {
            "unsupported algorithm: ${signed.algorithm}"
        }
        val key = keys[signed.keyId]
            ?: throw BundleVerificationError("untrusted key id: ${signed.keyId}")

        val sig = Signature.getInstance("Ed25519")
        sig.initVerify(key)
        sig.update(signed.payload.toByteArray(Charsets.UTF_8))

        val sigBytes = Base64.getDecoder().decode(signed.signature)
        val ok = try { sig.verify(sigBytes) } catch (e: Exception) { false }

        if (!ok) throw BundleVerificationError("signature verification failed")

        return parseBundle(signed.payload)
    }

    private fun extractKeyBytes(pem: String): ByteArray {
        val cleaned = pem.lines()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
        return Base64.getDecoder().decode(cleaned)
    }

    private fun parseBundle(payload: String): ThreatBundle {
        // Minimal JSON parsing for the bundle structure.
        // In production, use kotlinx.serialization or Gson.
        throw BundleVerificationError("Bundle JSON parsing requires serialization library — implement with kotlinx.serialization in app module")
    }
}

data class ApplyTargets(
    val store: ThreatStore,
    val signatureMatcher: SignatureMatcher? = null,
    val ruleManager: RuleManager? = null,
)

data class ApplyResult(
    val applied: Boolean,
    val version: Int,
    val counts: Counts,
) {
    data class Counts(val threats: Int, val signatures: Int, val yaraRules: Int)
}

/**
 * OTA Updater (PRD §7 "Updatability").
 *
 * Verifies a signed bundle, enforces monotonic versioning (anti-rollback), and
 * applies its threats / signatures / YARA rules into the live engine. Rejects
 * unsigned, tampered, or stale bundles.
 */
class OtaUpdater(private val verifier: BundleVerifier) {

    fun apply(signed: SignedBundle, targets: ApplyTargets): ApplyResult {
        val bundle = verifier.verify(signed) // throws on bad signature

        val current = targets.store.version
        if (bundle.version <= current) {
            throw BundleVerificationError("stale bundle: version ${bundle.version} <= current $current")
        }

        var threats = 0
        var signatures = 0
        var yaraRules = 0

        bundle.threats?.let {
            targets.store.add(it)
            threats = it.size
        }
        bundle.signatures?.let {
            targets.signatureMatcher?.upsert(it)
            signatures = it.size
        }
        bundle.yaraRules?.let {
            for (rule in it) targets.ruleManager?.add(rule)
            yaraRules = it.size
        }

        targets.store.version = bundle.version
        return ApplyResult(applied = true, version = bundle.version,
            counts = ApplyResult.Counts(threats, signatures, yaraRules))
    }
}
