package com.daemonblockint.sync.yara

/**
 * Kotlin declarations for the native YARA JNI bridge.
 *
 * The native library `yara_jni` wraps libyara (or a stub when libyara
 * is not yet vendored). Load via [loadLibrary] before use.
 */
object YaraNative {
    private var loaded = false

    /** Load the native library. Safe to call multiple times. */
    fun loadLibrary() {
        if (!loaded) {
            System.loadLibrary("yara_jni")
            nativeInit()
            loaded = true
        }
    }

    /** Unload and finalize the YARA engine. */
    fun finalize() {
        if (loaded) {
            nativeFinalize()
            loaded = false
        }
    }

    /**
     * Compile YARA rule source text into a rules handle.
     * @return opaque handle (0 on failure)
     */
    fun loadRules(rulesText: String): Long = nativeLoadRules(rulesText)

    /**
     * Scan a byte buffer against compiled rules.
     * @return array of matching rule indices, or null if no matches
     */
    fun scan(data: ByteArray, handle: Long): IntArray? = nativeScan(data, handle)

    /** Free a compiled rules handle. */
    fun cleanup(handle: Long) = nativeCleanup(handle)

    // JNI declarations
    @JvmStatic private external fun nativeInit()
    @JvmStatic private external fun nativeFinalize()
    @JvmStatic private external fun nativeLoadRules(rulesText: String): Long
    @JvmStatic private external fun nativeScan(data: ByteArray, handle: Long): IntArray?
    @JvmStatic private external fun nativeCleanup(handle: Long)
}
