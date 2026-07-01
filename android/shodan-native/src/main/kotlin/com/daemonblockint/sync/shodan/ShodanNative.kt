package com.daemonblockint.sync.shodan

/**
 * Kotlin declarations for the native Shodan JNI bridge.
 *
 * The native library `shodan_jni` constructs Shodan API URLs in C++ and
 * delegates HTTP requests to a [HttpCallback] provided by the caller.
 * This avoids the need for libcurl on Android.
 */
object ShodanNative {
    private var loaded = false

    /** Load the native library. Safe to call multiple times. */
    fun loadLibrary() {
        if (!loaded) {
            System.loadLibrary("shodan_jni")
            loaded = true
        }
    }

    /** Set the Shodan API key. Must be called before any lookup method. */
    fun setApiKey(key: String) {
        loadLibrary()
        nativeSetApiKey(key)
    }

    /** Get host info for an IP address. Returns raw JSON string. */
    fun hostInfo(callback: HttpCallback, ip: String, history: Boolean = false, minify: Boolean = false): String {
        loadLibrary()
        return nativeHostInfo(callback, ip, history, minify)
    }

    /** Get host count for a query. Returns raw JSON string. */
    fun hostCount(callback: HttpCallback, query: String): String {
        loadLibrary()
        return nativeHostCount(callback, query)
    }

    /** Search hosts. Returns raw JSON string. */
    fun hostSearch(callback: HttpCallback, query: String, page: Int = 1): String {
        loadLibrary()
        return nativeHostSearch(callback, query, page)
    }

    /** Get API info (plan, credits, etc). Returns raw JSON string. */
    fun apiInfo(callback: HttpCallback): String {
        loadLibrary()
        return nativeApiInfo(callback)
    }

    /** Get honeyscore for an IP (0.0 to 1.0). Returns raw JSON string. */
    fun honeyScore(callback: HttpCallback, ip: String): String {
        loadLibrary()
        return nativeHoneyScore(callback, ip)
    }

    /** Resolve DNS hostnames to IPs. Returns raw JSON string. */
    fun dnsResolve(callback: HttpCallback, hostnames: String): String {
        loadLibrary()
        return nativeDnsResolve(callback, hostnames)
    }

    /** Reverse DNS lookup. Returns raw JSON string. */
    fun dnsReverse(callback: HttpCallback, ips: String): String {
        loadLibrary()
        return nativeDnsReverse(callback, ips)
    }

    /** Get your current public IP. Returns raw JSON string. */
    fun myIp(callback: HttpCallback): String {
        loadLibrary()
        return nativeMyIp(callback)
    }

    /** Get account profile info. Returns raw JSON string. */
    fun profileInfo(callback: HttpCallback): String {
        loadLibrary()
        return nativeProfileInfo(callback)
    }

    // JNI declarations
    @JvmStatic private external fun nativeSetApiKey(key: String)
    @JvmStatic private external fun nativeHostInfo(callback: HttpCallback, ip: String, history: Boolean, minify: Boolean): String
    @JvmStatic private external fun nativeHostCount(callback: HttpCallback, query: String): String
    @JvmStatic private external fun nativeHostSearch(callback: HttpCallback, query: String, page: Int): String
    @JvmStatic private external fun nativeApiInfo(callback: HttpCallback): String
    @JvmStatic private external fun nativeHoneyScore(callback: HttpCallback, ip: String): String
    @JvmStatic private external fun nativeDnsResolve(callback: HttpCallback, hostnames: String): String
    @JvmStatic private external fun nativeDnsReverse(callback: HttpCallback, ips: String): String
    @JvmStatic private external fun nativeMyIp(callback: HttpCallback): String
    @JvmStatic private external fun nativeProfileInfo(callback: HttpCallback): String
}

/**
 * Callback interface for the native layer to perform HTTP requests.
 * The Kotlin side implements this using OkHttp or HttpURLConnection.
 */
fun interface HttpCallback {
    /** Execute a GET request to [url] and return the response body as a string. */
    fun execute(url: String): String
}
