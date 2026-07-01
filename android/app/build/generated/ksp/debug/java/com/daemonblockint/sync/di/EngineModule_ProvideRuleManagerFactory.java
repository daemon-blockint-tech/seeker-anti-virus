package com.daemonblockint.sync.di;

import com.daemonblockint.sync.engine.yara.RuleManager;
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
public final class EngineModule_ProvideRuleManagerFactory implements Factory<RuleManager> {
  @Override
  public RuleManager get() {
    return provideRuleManager();
  }

  public static EngineModule_ProvideRuleManagerFactory create() {
    return InstanceHolder.INSTANCE;
  }

  public static RuleManager provideRuleManager() {
    return Preconditions.checkNotNullFromProvides(EngineModule.INSTANCE.provideRuleManager());
  }

  private static final class InstanceHolder {
    private static final EngineModule_ProvideRuleManagerFactory INSTANCE = new EngineModule_ProvideRuleManagerFactory();
  }
}
