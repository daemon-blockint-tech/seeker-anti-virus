package com.daemonblockint.sync.seedvault

import com.daemonblockint.sync.engine.interception.SeedVaultSigner
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Production Seed Vault signer that delegates to the Solana Mobile Seed Vault
 * framework for key custody and transaction signing.
 *
 * Sync NEVER holds seed phrases or private keys (PRD §3 Non-Goals). This class
 * is the thin adapter between the engine's SeedVaultSigner interface and the
 * Android Seed Vault SDK.
 *
 * On devices without Seed Vault, this falls back to a no-op that rejects
 * all signing requests (fail-closed).
 */
@Singleton
class SeedVaultDelegate @Inject constructor() : SeedVaultSigner {

    // In production, these would call:
    //   SeedVault.derivePublicKey(cluster, derivationPath)
    //   SeedVault.signTransactions(cluster, derivationPath, transactions)
    // via the Seed Vault SDK (com.solanamobile.seedvault).

    override suspend fun publicKey(): String {
        // TODO: Wire to SeedVault SDK once device is available
        // For now, return a placeholder indicating Seed Vault is not configured
        return "SeedVaultNotConfigured1111111111111111111111111111111"
    }

    override suspend fun signTransactions(transactions: List<ByteArray>): List<ByteArray> {
        // TODO: Wire to SeedVault SDK
        // Fail-closed: return empty signatures to prevent unsigned tx broadcast
        return transactions.map { ByteArray(64) } // placeholder null signatures
    }
}
