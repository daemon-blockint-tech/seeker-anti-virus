package com.daemonblockint.sync.ui.viewmodel;

import com.daemonblockint.sync.engine.integrated.IntegratedScanner;
import com.daemonblockint.sync.engine.threatdb.ThreatStore;
import com.daemonblockint.sync.yara.NativeYaraBridge;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata
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
public final class DashboardViewModel_Factory implements Factory<DashboardViewModel> {
  private final Provider<IntegratedScanner> scannerProvider;

  private final Provider<ThreatStore> threatStoreProvider;

  private final Provider<NativeYaraBridge> yaraBridgeProvider;

  public DashboardViewModel_Factory(Provider<IntegratedScanner> scannerProvider,
      Provider<ThreatStore> threatStoreProvider, Provider<NativeYaraBridge> yaraBridgeProvider) {
    this.scannerProvider = scannerProvider;
    this.threatStoreProvider = threatStoreProvider;
    this.yaraBridgeProvider = yaraBridgeProvider;
  }

  @Override
  public DashboardViewModel get() {
    return newInstance(scannerProvider.get(), threatStoreProvider.get(), yaraBridgeProvider.get());
  }

  public static DashboardViewModel_Factory create(Provider<IntegratedScanner> scannerProvider,
      Provider<ThreatStore> threatStoreProvider, Provider<NativeYaraBridge> yaraBridgeProvider) {
    return new DashboardViewModel_Factory(scannerProvider, threatStoreProvider, yaraBridgeProvider);
  }

  public static DashboardViewModel newInstance(IntegratedScanner scanner, ThreatStore threatStore,
      NativeYaraBridge yaraBridge) {
    return new DashboardViewModel(scanner, threatStore, yaraBridge);
  }
}
