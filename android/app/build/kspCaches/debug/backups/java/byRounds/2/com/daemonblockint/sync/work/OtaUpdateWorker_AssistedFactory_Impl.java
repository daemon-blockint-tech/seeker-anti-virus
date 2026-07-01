package com.daemonblockint.sync.work;

import android.content.Context;
import androidx.work.WorkerParameters;
import dagger.internal.DaggerGenerated;
import dagger.internal.InstanceFactory;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

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
public final class OtaUpdateWorker_AssistedFactory_Impl implements OtaUpdateWorker_AssistedFactory {
  private final OtaUpdateWorker_Factory delegateFactory;

  OtaUpdateWorker_AssistedFactory_Impl(OtaUpdateWorker_Factory delegateFactory) {
    this.delegateFactory = delegateFactory;
  }

  @Override
  public OtaUpdateWorker create(Context p0, WorkerParameters p1) {
    return delegateFactory.get(p0, p1);
  }

  public static Provider<OtaUpdateWorker_AssistedFactory> create(
      OtaUpdateWorker_Factory delegateFactory) {
    return InstanceFactory.create(new OtaUpdateWorker_AssistedFactory_Impl(delegateFactory));
  }

  public static dagger.internal.Provider<OtaUpdateWorker_AssistedFactory> createFactoryProvider(
      OtaUpdateWorker_Factory delegateFactory) {
    return InstanceFactory.create(new OtaUpdateWorker_AssistedFactory_Impl(delegateFactory));
  }
}
