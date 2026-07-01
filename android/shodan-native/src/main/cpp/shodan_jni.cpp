// shodan_jni.cpp — JNI bridge for Shodan threat intelligence lookups.
//
// Ports the ShodanCPP ShodanClient URL-construction logic to Android.
// HTTP requests are delegated to Kotlin via a callback interface, avoiding
// the need for libcurl on Android.
//
// Exposes:
//   nativeSetApiKey(key)          — store the Shodan API key
//   nativeHostInfo(ip, history, minify) — GET /shodan/host/{ip}
//   nativeHostCount(query)        — GET /shodan/host/count
//   nativeHostSearch(query, page) — GET /shodan/host/search
//   nativeApiInfo()               — GET /api-info
//   nativeHoneyScore(ip)          — GET /labs/honeyscore/{ip}
//   nativeDnsResolve(hostnames)   — GET /dns/resolve
//   nativeDnsReverse(ips)         — GET /dns/reverse
//   nativeMyIp()                  — GET /tools/myip
//   nativeProfileInfo()           — GET /account/profile

#include <jni.h>
#include <string>
#include <android/log.h>

#define TAG "ShodanNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static const char* API_URL = "https://api.shodan.io";
static std::string g_api_key;

// Helper: URL-encode a string component
static std::string urlEncode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out += c;
        } else {
            out += '%';
            out += hex[(c >> 4) & 0xF];
            out += hex[c & 0xF];
        }
    }
    return out;
}

// Helper: invoke the Kotlin HTTP callback to perform the actual request
static std::string performRequest(JNIEnv* env, jobject callback, const std::string& url) {
    if (!callback) {
        LOGE("HTTP callback is null");
        return "";
    }

    jclass cls = env->GetObjectClass(callback);
    jmethodID method = env->GetMethodID(cls, "execute", "(Ljava/lang/String;)Ljava/lang/String;");
    env->DeleteLocalRef(cls);

    if (!method) {
        LOGE("Cannot find execute(String) method on callback");
        return "";
    }

    jstring jUrl = env->NewStringUTF(url.c_str());
    jstring jResult = (jstring) env->CallObjectMethod(callback, method, jUrl);
    env->DeleteLocalRef(jUrl);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("HTTP callback threw exception for URL: %s", url.c_str());
        return "";
    }

    std::string result;
    if (jResult) {
        const char* chars = env->GetStringUTFChars(jResult, nullptr);
        if (chars) {
            result = chars;
            env->ReleaseStringUTFChars(jResult, chars);
        }
        env->DeleteLocalRef(jResult);
    }
    return result;
}

extern "C" {

JNIEXPORT void JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeSetApiKey(JNIEnv* env, jobject, jstring key) {
    const char* k = env->GetStringUTFChars(key, nullptr);
    g_api_key = k;
    env->ReleaseStringUTFChars(key, k);
    LOGI("API key set");
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeHostInfo(
        JNIEnv* env, jobject, jobject callback, jstring jIp, jboolean history, jboolean minify) {
    const char* ip = env->GetStringUTFChars(jIp, nullptr);
    std::string url = std::string(API_URL) + "/shodan/host/" + urlEncode(ip) +
        "?key=" + g_api_key +
        "&history=" + (history ? "1" : "0") +
        "&minify=" + (minify ? "1" : "0");
    env->ReleaseStringUTFChars(jIp, ip);
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeHostCount(
        JNIEnv* env, jobject, jobject callback, jstring jQuery) {
    const char* query = env->GetStringUTFChars(jQuery, nullptr);
    std::string url = std::string(API_URL) + "/shodan/host/count?key=" + g_api_key +
        "&query=" + urlEncode(query);
    env->ReleaseStringUTFChars(jQuery, query);
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeHostSearch(
        JNIEnv* env, jobject, jobject callback, jstring jQuery, jint page) {
    const char* query = env->GetStringUTFChars(jQuery, nullptr);
    std::string url = std::string(API_URL) + "/shodan/host/search?key=" + g_api_key +
        "&query=" + urlEncode(query) +
        "&page=" + std::to_string(page) +
        "&minify=1";
    env->ReleaseStringUTFChars(jQuery, query);
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeApiInfo(
        JNIEnv* env, jobject, jobject callback) {
    std::string url = std::string(API_URL) + "/api-info?key=" + g_api_key;
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeHoneyScore(
        JNIEnv* env, jobject, jobject callback, jstring jIp) {
    const char* ip = env->GetStringUTFChars(jIp, nullptr);
    std::string url = std::string(API_URL) + "/labs/honeyscore/" + urlEncode(ip) +
        "?key=" + g_api_key;
    env->ReleaseStringUTFChars(jIp, ip);
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeDnsResolve(
        JNIEnv* env, jobject, jobject callback, jstring jHostnames) {
    const char* hostnames = env->GetStringUTFChars(jHostnames, nullptr);
    std::string url = std::string(API_URL) + "/dns/resolve?hostnames=" +
        urlEncode(hostnames) + "&key=" + g_api_key;
    env->ReleaseStringUTFChars(jHostnames, hostnames);
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeDnsReverse(
        JNIEnv* env, jobject, jobject callback, jstring jIps) {
    const char* ips = env->GetStringUTFChars(jIps, nullptr);
    std::string url = std::string(API_URL) + "/dns/reverse?ips=" +
        urlEncode(ips) + "&key=" + g_api_key;
    env->ReleaseStringUTFChars(jIps, ips);
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeMyIp(
        JNIEnv* env, jobject, jobject callback) {
    std::string url = std::string(API_URL) + "/tools/myip?key=" + g_api_key;
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_daemonblockint_sync_shodan_ShodanNative_nativeProfileInfo(
        JNIEnv* env, jobject, jobject callback) {
    std::string url = std::string(API_URL) + "/account/profile?key=" + g_api_key;
    std::string result = performRequest(env, callback, url);
    return env->NewStringUTF(result.c_str());
}

} // extern "C"
