package com.daemonblockint.sync.service;

import com.daemonblockint.sync.engine.interception.SyncWalletEndpoint;
import com.daemonblockint.sync.seedvault.SeedVaultDelegate;
import dagger.MembersInjector;
import dagger.internal.DaggerGenerated;
import dagger.internal.InjectedFieldSignature;
import dagger.internal.QualifierMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

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
public final class SyncWalletService_MembersInjector implements MembersInjector<SyncWalletService> {
  private final Provider<SeedVaultDelegate> seedVaultProvider;

  private final Provider<SyncWalletEndpoint> walletEndpointProvider;

  public SyncWalletService_MembersInjector(Provider<SeedVaultDelegate> seedVaultProvider,
      Provider<SyncWalletEndpoint> walletEndpointProvider) {
    this.seedVaultProvider = seedVaultProvider;
    this.walletEndpointProvider = walletEndpointProvider;
  }

  public static MembersInjector<SyncWalletService> create(
      Provider<SeedVaultDelegate> seedVaultProvider,
      Provider<SyncWalletEndpoint> walletEndpointProvider) {
    return new SyncWalletService_MembersInjector(seedVaultProvider, walletEndpointProvider);
  }

  @Override
  public void injectMembers(SyncWalletService instance) {
    injectSeedVault(instance, seedVaultProvider.get());
    injectWalletEndpoint(instance, walletEndpointProvider.get());
  }

  @InjectedFieldSignature("com.daemonblockint.sync.service.SyncWalletService.seedVault")
  public static void injectSeedVault(SyncWalletService instance, SeedVaultDelegate seedVault) {
    instance.seedVault = seedVault;
  }

  @InjectedFieldSignature("com.daemonblockint.sync.service.SyncWalletService.walletEndpoint")
  public static void injectWalletEndpoint(SyncWalletService instance,
      SyncWalletEndpoint walletEndpoint) {
    instance.walletEndpoint = walletEndpoint;
  }
}
