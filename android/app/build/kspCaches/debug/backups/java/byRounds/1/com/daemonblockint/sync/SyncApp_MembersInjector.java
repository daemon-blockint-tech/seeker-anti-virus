package com.daemonblockint.sync;

import androidx.hilt.work.HiltWorkerFactory;
import com.daemonblockint.sync.yara.NativeYaraBridge;
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
public final class SyncApp_MembersInjector implements MembersInjector<SyncApp> {
  private final Provider<NativeYaraBridge> yaraBridgeProvider;

  private final Provider<HiltWorkerFactory> workerFactoryProvider;

  public SyncApp_MembersInjector(Provider<NativeYaraBridge> yaraBridgeProvider,
      Provider<HiltWorkerFactory> workerFactoryProvider) {
    this.yaraBridgeProvider = yaraBridgeProvider;
    this.workerFactoryProvider = workerFactoryProvider;
  }

  public static MembersInjector<SyncApp> create(Provider<NativeYaraBridge> yaraBridgeProvider,
      Provider<HiltWorkerFactory> workerFactoryProvider) {
    return new SyncApp_MembersInjector(yaraBridgeProvider, workerFactoryProvider);
  }

  @Override
  public void injectMembers(SyncApp instance) {
    injectYaraBridge(instance, yaraBridgeProvider.get());
    injectWorkerFactory(instance, workerFactoryProvider.get());
  }

  @InjectedFieldSignature("com.daemonblockint.sync.SyncApp.yaraBridge")
  public static void injectYaraBridge(SyncApp instance, NativeYaraBridge yaraBridge) {
    instance.yaraBridge = yaraBridge;
  }

  @InjectedFieldSignature("com.daemonblockint.sync.SyncApp.workerFactory")
  public static void injectWorkerFactory(SyncApp instance, HiltWorkerFactory workerFactory) {
    instance.workerFactory = workerFactory;
  }
}
