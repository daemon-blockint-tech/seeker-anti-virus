// yara_jni.cpp — JNI bridge between Kotlin and libyara (or stub).
//
// Exposes:
//   nativeInit()          → yr_initialize()
//   nativeLoadRules(text) → compile rules into a YR_RULES handle
//   nativeScan(data, h)   → scan bytes, return matching rule indices
//   nativeCleanup(h)      → free a rules handle
//   nativeFinalize()      → yr_finalize()

#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>

#define TAG "YaraNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

extern "C" {
    int yara_initialize(void);
    int yara_finalize(void);
    int yara_load_rules(const char* rules_text, void** handle);
    int yara_scan_bytes(const void* handle, const uint8_t* data, size_t len,
                        int* match_indices, int max_matches);
    void yara_free_rules(void* handle);
}

static bool g_initialized = false;

extern "C" JNIEXPORT void JNICALL
Java_com_daemonblockint_sync_yara_YaraNative_nativeInit(JNIEnv*, jobject) {
    if (!g_initialized) {
        int rc = yara_initialize();
        if (rc != 0) {
            LOGE("yara_initialize failed: %d", rc);
        } else {
            g_initialized = true;
            LOGI("libyara initialized");
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_daemonblockint_sync_yara_YaraNative_nativeFinalize(JNIEnv*, jobject) {
    if (g_initialized) {
        yara_finalize();
        g_initialized = false;
        LOGI("libyara finalized");
    }
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_daemonblockint_sync_yara_YaraNative_nativeLoadRules(
        JNIEnv* env, jobject, jstring rulesText) {
    const char* text = env->GetStringUTFChars(rulesText, nullptr);
    void* handle = nullptr;
    int rc = yara_load_rules(text, &handle);
    env->ReleaseStringUTFChars(rulesText, text);

    if (rc != 0) {
        LOGE("yara_load_rules failed: %d", rc);
        return 0;
    }
    return reinterpret_cast<jlong>(handle);
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_daemonblockint_sync_yara_YaraNative_nativeScan(
        JNIEnv* env, jobject, jbyteArray data, jlong handle) {
    if (handle == 0) return nullptr;

    jsize len = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);

    // Pre-allocate for up to 256 matches (sufficient for our rule set)
    const int MAX_MATCHES = 256;
    int match_indices[MAX_MATCHES];
    int match_count = yara_scan_bytes(
        reinterpret_cast<const void*>(handle),
        reinterpret_cast<const uint8_t*>(bytes),
        static_cast<size_t>(len),
        match_indices, MAX_MATCHES);

    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);

    if (match_count <= 0) {
        return nullptr;
    }

    jintArray result = env->NewIntArray(match_count);
    env->SetIntArrayRegion(result, 0, match_count, match_indices);
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_daemonblockint_sync_yara_YaraNative_nativeCleanup(
        JNIEnv*, jobject, jlong handle) {
    if (handle != 0) {
        yara_free_rules(reinterpret_cast<void*>(handle));
    }
}
