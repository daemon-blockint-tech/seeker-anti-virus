package com.daemonblockint.sync.work;

import android.content.Context;
import androidx.work.WorkerParameters;
import com.daemonblockint.sync.engine.signatures.SignatureMatcher;
import com.daemonblockint.sync.engine.threatdb.ThreatStore;
import com.daemonblockint.sync.engine.yara.RuleManager;
import dagger.internal.DaggerGenerated;
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
public final class OtaUpdateWorker_Factory {
  private final Provider<ThreatStore> threatStoreProvider;

  private final Provider<SignatureMatcher> signatureMatcherProvider;

  private final Provider<RuleManager> ruleManagerProvider;

  public OtaUpdateWorker_Factory(Provider<ThreatStore> threatStoreProvider,
      Provider<SignatureMatcher> signatureMatcherProvider,
      Provider<RuleManager> ruleManagerProvider) {
    this.threatStoreProvider = threatStoreProvider;
    this.signatureMatcherProvider = signatureMatcherProvider;
    this.ruleManagerProvider = ruleManagerProvider;
  }

  public OtaUpdateWorker get(Context appContext, WorkerParameters params) {
    return newInstance(appContext, params, threatStoreProvider.get(), signatureMatcherProvider.get(), ruleManagerProvider.get());
  }

  public static OtaUpdateWorker_Factory create(Provider<ThreatStore> threatStoreProvider,
      Provider<SignatureMatcher> signatureMatcherProvider,
      Provider<RuleManager> ruleManagerProvider) {
    return new OtaUpdateWorker_Factory(threatStoreProvider, signatureMatcherProvider, ruleManagerProvider);
  }

  public static OtaUpdateWorker newInstance(Context appContext, WorkerParameters params,
      ThreatStore threatStore, SignatureMatcher signatureMatcher, RuleManager ruleManager) {
    return new OtaUpdateWorker(appContext, params, threatStore, signatureMatcher, ruleManager);
  }
}
