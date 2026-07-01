package com.daemonblockint.sync.di;

import com.daemonblockint.sync.yara.NativeYaraBridge;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.Preconditions;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;

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
public final class EngineModule_ProvideNativeYaraBridgeFactory implements Factory<NativeYaraBridge> {
  @Override
  public NativeYaraBridge get() {
    return provideNativeYaraBridge();
  }

  public static EngineModule_ProvideNativeYaraBridgeFactory create() {
    return InstanceHolder.INSTANCE;
  }

  public static NativeYaraBridge provideNativeYaraBridge() {
    return Preconditions.checkNotNullFromProvides(EngineModule.INSTANCE.provideNativeYaraBridge());
  }

  private static final class InstanceHolder {
    private static final EngineModule_ProvideNativeYaraBridgeFactory INSTANCE = new EngineModule_ProvideNativeYaraBridgeFactory();
  }
}
