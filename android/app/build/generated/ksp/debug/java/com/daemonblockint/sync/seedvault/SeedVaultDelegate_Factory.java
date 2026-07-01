package com.daemonblockint.sync.seedvault;

import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
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
public final class SeedVaultDelegate_Factory implements Factory<SeedVaultDelegate> {
  @Override
  public SeedVaultDelegate get() {
    return newInstance();
  }

  public static SeedVaultDelegate_Factory create() {
    return InstanceHolder.INSTANCE;
  }

  public static SeedVaultDelegate newInstance() {
    return new SeedVaultDelegate();
  }

  private static final class InstanceHolder {
    private static final SeedVaultDelegate_Factory INSTANCE = new SeedVaultDelegate_Factory();
  }
}
