package com.daemonblockint.sync.di;

import com.daemonblockint.sync.engine.interception.ScreeningPipeline;
import com.daemonblockint.sync.engine.interception.SyncWalletEndpoint;
import com.daemonblockint.sync.seedvault.SeedVaultDelegate;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.Preconditions;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata("javax.inject.Singleton")
@QualifierMetadata
@DaggerGenerated
@Generated(
    value = "dagger.internal.codegen.ComponentProcessor",
    comments = "https://dagger.dev"
)
@SuppressWarnings({
    "unchecked",
    "rawtypes",
    "KotlinInternal",
    "KotlinInternalInJava",
    "cast"
})
public final class EngineModule_ProvideSyncWalletEndpointFactory implements Factory<SyncWalletEndpoint> {
  private final Provider<SeedVaultDelegate> seedVaultProvider;

  private final Provider<ScreeningPipeline> pipelineProvider;

  public EngineModule_ProvideSyncWalletEndpointFactory(
      Provider<SeedVaultDelegate> seedVaultProvider, Provider<ScreeningPipeline> pipelineProvider) {
    this.seedVaultProvider = seedVaultProvider;
    this.pipelineProvider = pipelineProvider;
  }

  @Override
  public SyncWalletEndpoint get() {
    return provideSyncWalletEndpoint(seedVaultProvider.get(), pipelineProvider.get());
  }

  public static EngineModule_ProvideSyncWalletEndpointFactory create(
      Provider<SeedVaultDelegate> seedVaultProvider, Provider<ScreeningPipeline> pipelineProvider) {
    return new EngineModule_ProvideSyncWalletEndpointFactory(seedVaultProvider, pipelineProvider);
  }

  public static SyncWalletEndpoint provideSyncWalletEndpoint(SeedVaultDelegate seedVault,
      ScreeningPipeline pipeline) {
    return Preconditions.checkNotNullFromProvides(EngineModule.INSTANCE.provideSyncWalletEndpoint(seedVault, pipeline));
  }
}
