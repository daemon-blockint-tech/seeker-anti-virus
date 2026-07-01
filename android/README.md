# Sync Android App

Native Kotlin Android application for the Sync anti-virus system.

## Architecture

Three Gradle modules:

- **`engine`** — Pure Kotlin JVM library. Ports the entire detection engine
  (behavioral scanner, signature matcher, YARA scanner, risk scorer, report
  generator, transaction decoder, screening pipeline, MWA wallet endpoint,
  threat store, OTA updater) from TypeScript to Kotlin.

- **`yara-native`** — Android library module. Cross-compiles libyara via NDK
  and exposes it through JNI. Falls back to the pure-Kotlin YaraScanner when
  the native library is not available.

- **`app`** — Android application. Jetpack Compose UI, Hilt DI, MWA wallet
  service, Seed Vault delegation, OTA update worker, background monitoring.

## Building

```bash
cd android
./gradlew assembleDebug
```

## Testing

```bash
# JVM unit tests for the engine module
./gradlew :engine:test

# Instrumented tests (require a device/emulator)
./gradlew connectedAndroidTest
```

## Vendoring libyara

```bash
cd yara-native
./setup-libyara.sh
```

This clones YARA v4.5.1 and patches it for Android NDK cross-compilation.
The CMakeLists.txt automatically detects and builds it. Without this step,
a stub implementation is used (no-op scans, project still compiles).

## Key Design Decisions

- **Native Kotlin** — Detection logic is ported to Kotlin (not run via Hermes/JS).
  The TS core remains for cloud/API only.
- **Real YARA via NDK+JNI** — libyara is cross-compiled for arm64-v8a,
  armeabi-v7a, and x86_64. JNI bridge in `yara-native/src/main/cpp/yara_jni.cpp`.
- **Seed Vault delegation** — Sync never custodies keys. All signing is
  delegated to the device's Seed Vault via the `SeedVaultSigner` interface.
- **SQLCipher** — On-device threat DB uses encrypted SQLite (field-level
  AES-256-GCM encryption as fallback when SQLCipher is not configured).
