package com.daemonblockint.sync.di

import android.content.Context
import com.daemonblockint.sync.engine.integrated.IntegratedScanner
import com.daemonblockint.sync.engine.interception.ScreeningPipeline
import com.daemonblockint.sync.engine.interception.SyncWalletEndpoint
import com.daemonblockint.sync.engine.signatures.SignatureMatcher
import com.daemonblockint.sync.engine.threatdb.InMemoryBackend
import com.daemonblockint.sync.engine.threatdb.ThreatStore
import com.daemonblockint.sync.engine.yara.RuleManager
import com.daemonblockint.sync.seedvault.SeedVaultDelegate
import com.daemonblockint.sync.yara.NativeYaraBridge
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object EngineModule {

    @Provides @Singleton
    fun provideNativeYaraBridge(): NativeYaraBridge = NativeYaraBridge()

    @Provides @Singleton
    fun provideRuleManager(): RuleManager = RuleManager()

    @Provides @Singleton
    fun provideSignatureMatcher(): SignatureMatcher = SignatureMatcher()

    @Provides @Singleton
    fun provideThreatStore(): ThreatStore = ThreatStore(InMemoryBackend())

    @Provides @Singleton
    fun provideIntegratedScanner(
        signatureMatcher: SignatureMatcher,
        ruleManager: RuleManager,
    ): IntegratedScanner = IntegratedScanner(
        com.daemonblockint.sync.engine.integrated.IntegratedScannerOptions(
            signatures = signatureMatcher.let { emptyList() }, // uses defaults
        ),
    )

    @Provides @Singleton
    fun provideScreeningPipeline(
        scanner: IntegratedScanner,
    ): ScreeningPipeline = ScreeningPipeline(scanner)

    @Provides @Singleton
    fun provideSyncWalletEndpoint(
        seedVault: SeedVaultDelegate,
        pipeline: ScreeningPipeline,
    ): SyncWalletEndpoint = SyncWalletEndpoint(
        seedVault = seedVault,
        options = com.daemonblockint.sync.engine.interception.SyncWalletEndpointOptions(
            pipeline = pipeline,
        ),
    )
}
