package com.daemonblockint.sync.di;

import com.daemonblockint.sync.engine.threatdb.ThreatStore;
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
public final class EngineModule_ProvideThreatStoreFactory implements Factory<ThreatStore> {
  @Override
  public ThreatStore get() {
    return provideThreatStore();
  }

  public static EngineModule_ProvideThreatStoreFactory create() {
    return InstanceHolder.INSTANCE;
  }

  public static ThreatStore provideThreatStore() {
    return Preconditions.checkNotNullFromProvides(EngineModule.INSTANCE.provideThreatStore());
  }

  private static final class InstanceHolder {
    private static final EngineModule_ProvideThreatStoreFactory INSTANCE = new EngineModule_ProvideThreatStoreFactory();
  }
}
