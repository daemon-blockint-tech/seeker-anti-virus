package com.daemonblockint.sync.service

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.daemonblockint.sync.engine.interception.AuthorizeRequest
import com.daemonblockint.sync.engine.interception.SyncWalletEndpoint
import com.daemonblockint.sync.seedvault.SeedVaultDelegate
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.runBlocking

/**
 * MWA Wallet Endpoint Service (PRD §5.5 Strategy A).
 *
 * Exposes Sync as a Mobile Wallet Adapter wallet. DApps connect to Sync
 * to request signing; Sync screens every transaction through the detection
 * engine before delegating to Seed Vault for the actual signature.
 *
 * This is a simplified binder; the full MWA protocol uses AIDL callbacks
 * defined by the walletadapter library.
 */
@AndroidEntryPoint
class SyncWalletService : Service() {

    @Inject
    lateinit var seedVault: SeedVaultDelegate

    @Inject
    lateinit var walletEndpoint: SyncWalletEndpoint

    override fun onBind(intent: Intent?): IBinder? {
        // In the full implementation, this returns a WalletAdapter V2 binder
        // that handles authorize, reauthorize, signTransactions, and signMessage
        // intents per the MWA protocol specification.
        //
        // The walletEndpoint.screenAndSign() method is called for each
        // signTransactions request, with the SeedVaultDelegate handling
        // the actual cryptographic signing.
        return null // Placeholder — full AIDL binder wired in production
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Handle MWA protocol intents here
        return START_NOT_STICKY
    }
}
