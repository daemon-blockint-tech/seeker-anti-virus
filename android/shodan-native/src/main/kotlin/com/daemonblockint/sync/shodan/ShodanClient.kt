package com.daemonblockint.sync.shodan

import org.json.JSONObject

/**
 * Parsed Shodan host information.
 */
data class ShodanHostInfo(
    val ip: String,
    val organization: String?,
    val os: String?,
    val country: String?,
    val countryCode: String?,
    val city: String?,
    val asn: String?,
    val isp: String?,
    val ports: List<Int>,
    val hostnames: List<String>,
    val vulns: List<String>,
    val tags: List<String>,
    val raw: String,
)

/**
 * Parsed Shodan API info.
 */
data class ShodanApiInfo(
    val plan: String?,
    val credits: Int,
    val remainingCredits: Int,
    val scanned: Long,
    val raw: String,
)

/**
 * Parsed honeyscore result.
 */
data class HoneyScoreResult(
    val score: Double,
    val isHoneypot: Boolean,
    val raw: String,
)

/**
 * High-level Shodan client for threat intelligence lookups.
 *
 * Wraps [ShodanNative] with JSON parsing. Requires an [HttpCallback]
 * implementation (typically using OkHttp on Android).
 *
 * Usage:
 *   val client = ShodanClient("YOUR_API_KEY") { url ->
 *       // perform HTTP GET, return body
 *   }
 *   val info = client.hostInfo("8.8.8.8")
 */
class ShodanClient(
    apiKey: String,
    private val http: HttpCallback,
) {
    init {
        ShodanNative.setApiKey(apiKey)
    }

    /** Get host info for an IP address. */
    fun hostInfo(ip: String, history: Boolean = false, minify: Boolean = false): ShodanHostInfo {
        val raw = ShodanNative.hostInfo(http, ip, history, minify)
        return parseHostInfo(raw)
    }

    /** Get API plan info. */
    fun apiInfo(): ShodanApiInfo {
        val raw = ShodanNative.apiInfo(http)
        return parseApiInfo(raw)
    }

    /** Get honeyscore for an IP. */
    fun honeyScore(ip: String): HoneyScoreResult {
        val raw = ShodanNative.honeyScore(http, ip)
        val score = raw.trim().toDoubleOrNull() ?: 0.0
        return HoneyScoreResult(score = score, isHoneypot = score >= 0.5, raw = raw)
    }

    /** Get host count for a search query. */
    fun hostCount(query: String): Int {
        val raw = ShodanNative.hostCount(http, query)
        return runCatching { JSONObject(raw).optInt("total", 0) }.getOrDefault(0)
    }

    /** Resolve DNS hostnames to IPs. Returns map of hostname -> IP. */
    fun dnsResolve(hostnames: String): Map<String, String> {
        val raw = ShodanNative.dnsResolve(http, hostnames)
        return runCatching {
            val obj = JSONObject(raw)
            obj.keys().asSequence().associateWith { obj.optString(it) }
        }.getOrDefault(emptyMap())
    }

    /** Get your current public IP. */
    fun myIp(): String = ShodanNative.myIp(http).trim()

    private fun parseHostInfo(raw: String): ShodanHostInfo {
        val json = JSONObject(raw)
        val portsArr = json.optJSONArray("ports")
        val ports = if (portsArr != null) {
            (0 until portsArr.length()).mapNotNull { portsArr.optInt(it) }
        } else emptyList()

        val hostnamesArr = json.optJSONArray("hostnames")
        val hostnames = if (hostnamesArr != null) {
            (0 until hostnamesArr.length()).mapNotNull { hostnamesArr.optString(it) }
        } else emptyList()

        val vulnsArr = json.optJSONArray("vulns")
        val vulns = if (vulnsArr != null) {
            (0 until vulnsArr.length()).mapNotNull { vulnsArr.optString(it) }
        } else emptyList()

        val tagsArr = json.optJSONArray("tags")
        val tags = if (tagsArr != null) {
            (0 until tagsArr.length()).mapNotNull { tagsArr.optString(it) }
        } else emptyList()

        return ShodanHostInfo(
            ip = json.optString("ip_str", json.optString("ip", "")),
            organization = json.optString("org", null),
            os = json.optString("os", null),
            country = json.optString("country_name", null),
            countryCode = json.optString("country_code", null),
            city = json.optString("city", null),
            asn = json.optString("asn", null),
            isp = json.optString("isp", null),
            ports = ports,
            hostnames = hostnames,
            vulns = vulns,
            tags = tags,
            raw = raw,
        )
    }

    private fun parseApiInfo(raw: String): ShodanApiInfo {
        val json = JSONObject(raw)
        return ShodanApiInfo(
            plan = json.optString("plan", null),
            credits = json.optInt("credits", 0),
            remainingCredits = json.optInt("query_credits", 0),
            scanned = json.optLong("scanned", 0),
            raw = raw,
        )
    }
}
