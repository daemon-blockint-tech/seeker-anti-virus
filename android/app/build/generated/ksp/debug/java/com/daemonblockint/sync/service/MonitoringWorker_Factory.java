package com.daemonblockint.sync.service;

import android.content.Context;
import androidx.work.WorkerParameters;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata
@QualifierMetadata("dagger.hilt.android.qualifiers.ApplicationContext")
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
public final class MonitoringWorker_Factory implements Factory<MonitoringWorker> {
  private final Provider<Context> contextProvider;

  private final Provider<WorkerParameters> paramsProvider;

  public MonitoringWorker_Factory(Provider<Context> contextProvider,
      Provider<WorkerParameters> paramsProvider) {
    this.contextProvider = contextProvider;
    this.paramsProvider = paramsProvider;
  }

  @Override
  public MonitoringWorker get() {
    return newInstance(contextProvider.get(), paramsProvider.get());
  }

  public static MonitoringWorker_Factory create(Provider<Context> contextProvider,
      Provider<WorkerParameters> paramsProvider) {
    return new MonitoringWorker_Factory(contextProvider, paramsProvider);
  }

  public static MonitoringWorker newInstance(Context context, WorkerParameters params) {
    return new MonitoringWorker(context, params);
  }
}
