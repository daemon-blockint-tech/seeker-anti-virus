package com.daemonblockint.sync.di;

import com.daemonblockint.sync.engine.integrated.IntegratedScanner;
import com.daemonblockint.sync.engine.interception.ScreeningPipeline;
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
public final class EngineModule_ProvideScreeningPipelineFactory implements Factory<ScreeningPipeline> {
  private final Provider<IntegratedScanner> scannerProvider;

  public EngineModule_ProvideScreeningPipelineFactory(Provider<IntegratedScanner> scannerProvider) {
    this.scannerProvider = scannerProvider;
  }

  @Override
  public ScreeningPipeline get() {
    return provideScreeningPipeline(scannerProvider.get());
  }

  public static EngineModule_ProvideScreeningPipelineFactory create(
      Provider<IntegratedScanner> scannerProvider) {
    return new EngineModule_ProvideScreeningPipelineFactory(scannerProvider);
  }

  public static ScreeningPipeline provideScreeningPipeline(IntegratedScanner scanner) {
    return Preconditions.checkNotNullFromProvides(EngineModule.INSTANCE.provideScreeningPipeline(scanner));
  }
}
