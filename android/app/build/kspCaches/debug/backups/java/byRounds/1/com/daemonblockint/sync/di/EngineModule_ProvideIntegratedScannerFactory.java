package com.daemonblockint.sync.di;

import com.daemonblockint.sync.engine.integrated.IntegratedScanner;
import com.daemonblockint.sync.engine.signatures.SignatureMatcher;
import com.daemonblockint.sync.engine.yara.RuleManager;
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
public final class EngineModule_ProvideIntegratedScannerFactory implements Factory<IntegratedScanner> {
  private final Provider<SignatureMatcher> signatureMatcherProvider;

  private final Provider<RuleManager> ruleManagerProvider;

  public EngineModule_ProvideIntegratedScannerFactory(
      Provider<SignatureMatcher> signatureMatcherProvider,
      Provider<RuleManager> ruleManagerProvider) {
    this.signatureMatcherProvider = signatureMatcherProvider;
    this.ruleManagerProvider = ruleManagerProvider;
  }

  @Override
  public IntegratedScanner get() {
    return provideIntegratedScanner(signatureMatcherProvider.get(), ruleManagerProvider.get());
  }

  public static EngineModule_ProvideIntegratedScannerFactory create(
      Provider<SignatureMatcher> signatureMatcherProvider,
      Provider<RuleManager> ruleManagerProvider) {
    return new EngineModule_ProvideIntegratedScannerFactory(signatureMatcherProvider, ruleManagerProvider);
  }

  public static IntegratedScanner provideIntegratedScanner(SignatureMatcher signatureMatcher,
      RuleManager ruleManager) {
    return Preconditions.checkNotNullFromProvides(EngineModule.INSTANCE.provideIntegratedScanner(signatureMatcher, ruleManager));
  }
}
