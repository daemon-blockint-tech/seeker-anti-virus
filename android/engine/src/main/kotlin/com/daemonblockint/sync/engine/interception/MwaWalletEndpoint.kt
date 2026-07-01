package com.daemonblockint.sync.engine.interception

/**
 * Seed Vault delegate. Sync registers as an MWA wallet endpoint but **never
 * custodies keys** (PRD §3 Non-Goals / §5.5 Strategy A): all signing is proxied
 * to the device's Seed Vault through this interface.
 */
interface SeedVaultSigner {
    /** The wallet's public key (base58). */
    suspend fun publicKey(): String

    /** Sign already-approved transactions, returning the signed bytes. */
    suspend fun signTransactions(transactions: List<ByteArray>): List<ByteArray>
}

/** MWA `authorize` / `reauthorize` request (subset Sync cares about). */
data class AuthorizeRequest(
    val identityName: String? = null,
    val identityUri: String? = null,
    val cluster: String? = null,
)

data class AuthorizeResult(
    val publicKey: String,
    val accountLabel: String,
)

/** Per-transaction outcome from a sign request. */
data class SignedOutcome(
    val index: Int,
    val screening: ScreeningResult,
    val signed: ByteArray? = null,
    val blockedReason: String? = null,
)

data class SignTransactionsResult(
    val outcomes: List<SignedOutcome>,
    val allSigned: Boolean,
)

/**
 * Called when a transaction screens as `warn` (high severity). Return `true` to
 * proceed with signing, `false` to decline. If omitted, warns are declined.
 */
fun interface WarnConfirmHandler {
    suspend fun onWarn(result: ScreeningResult): Boolean
}

data class SyncWalletEndpointOptions(
    val pipeline: ScreeningPipeline? = null,
    val onWarn: WarnConfirmHandler? = null,
)

/**
 * Sync-as-Wallet MWA endpoint (PRD §5.5 Strategy A).
 *
 * Implements the wallet side of the Mobile Wallet Adapter signing flow, but
 * screens every transaction through the ScreeningPipeline first and
 * delegates the actual signing to a SeedVaultSigner. Critical findings
 * block signing outright; high findings require explicit user confirmation.
 */
class SyncWalletEndpoint(
    private val seedVault: SeedVaultSigner,
    options: SyncWalletEndpointOptions = SyncWalletEndpointOptions(),
) {
    private val pipeline: ScreeningPipeline = options.pipeline ?: ScreeningPipeline()
    private val onWarn: WarnConfirmHandler? = options.onWarn

    /** Handle an MWA authorize/reauthorize request. */
    suspend fun authorize(request: AuthorizeRequest = AuthorizeRequest()): AuthorizeResult {
        val publicKey = seedVault.publicKey()
        return AuthorizeResult(publicKey, "Seed Vault (screened by Sync)")
    }

    /**
     * Screen then sign a batch of transactions. Each transaction is approved,
     * confirmed (warn), or blocked independently; only approved ones are sent to
     * the Seed Vault for signing.
     */
    suspend fun signTransactions(transactions: List<ByteArray>): SignTransactionsResult {
        val outcomes = mutableListOf<SignedOutcome>()
        val toSign = mutableListOf<IndexedValue<ByteArray>>()

        for ((i, tx) in transactions.withIndex()) {
            val screening = pipeline.screen(tx)

            if (screening.decision == ScreeningDecision.BLOCK) {
                outcomes.add(SignedOutcome(i, screening, blockedReason = reason(screening)))
                continue
            }
            if (screening.decision == ScreeningDecision.WARN) {
                val proceed = onWarn?.onWarn(screening) ?: false
                if (!proceed) {
                    outcomes.add(SignedOutcome(i, screening, blockedReason = "declined_by_user"))
                    continue
                }
            }
            toSign.add(IndexedValue(i, tx))
            outcomes.add(SignedOutcome(i, screening))
        }

        // Delegate the approved set to Seed Vault in one call.
        if (toSign.isNotEmpty()) {
            val signed = seedVault.signTransactions(toSign.map { it.value })
            toSign.forEachIndexed { k, (idx, _) ->
                val outcome = outcomes.find { it.index == idx }!!
                outcomes[outcomes.indexOf(outcome)] = outcome.copy(signed = signed[k])
            }
        }

        outcomes.sortBy { it.index }
        return SignTransactionsResult(
            outcomes = outcomes,
            allSigned = outcomes.all { it.signed != null },
        )
    }

    private fun reason(screening: ScreeningResult): String {
        val top = screening.report.findings.firstOrNull()
        return if (top != null) "blocked: ${top.title}" else "blocked: ${screening.severity} risk"
    }
}
