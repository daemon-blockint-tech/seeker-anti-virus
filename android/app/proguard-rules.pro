# Sync ProGuard Rules

# Keep engine model classes (used via reflection in DI)
-keep class com.daemonblockint.sync.engine.** { *; }
-keep class com.daemonblockint.sync.yara.** { *; }

# Keep SeedVault interface
-keep class com.daemonblockint.sync.engine.interception.SeedVaultSigner { *; }

# Keep JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Kotlin metadata
-keepattributes *Annotation*, InnerClasses, EnclosingMethod, Signature, Exceptions
