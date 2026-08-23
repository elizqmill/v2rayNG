package com.v2ray.ang.util

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.net.URLEncoder

/**
 * Per-subscription content transformer used right after the subscription body
 * is fetched and before it is parsed into profiles.
 *
 * Two independent switches driven by the subscription settings:
 *  - [decodeBase64ToText]: whole-body or per-line base64 blobs are decoded to
 *    plain link lists / JSON text.
 *  - [customToLinks]: custom JSON configs (xray outbound objects/arrays,
 *    sing-box style entries) are converted into regular share links so they
 *    can be edited with the normal profile UI.
 */
object SubscriptionContentConverter {

    fun convert(content: String, decodeBase64: Boolean, customToLinks: Boolean): String {
        if (!decodeBase64 && !customToLinks) return content
        return walk(content, decodeBase64, customToLinks)
    }

    private fun walk(input: String, b64: Boolean, j2l: Boolean): String {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return input

        // Whole body is one base64 blob -> decode first and recurse.
        if (b64) {
            tryDecodeBase64(trimmed)?.let { decoded ->
                return walk(decoded, b64, j2l)
            }
        }

        // Whole body is a single JSON value (compact or pretty) -> convert directly.
        if (j2l && (trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
            convertJsonText(trimmed)?.let { return it }
        }

        val res = StringBuilder()
        input.lines().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach

            if (b64) {
                tryDecodeBase64(t)?.let { decoded ->
                    res.append(walk(decoded, b64, j2l)).append("\n")
                    return@forEach
                }
            }

            if (j2l && (t.startsWith("{") || t.startsWith("["))) {
                convertJsonText(t)?.let {
                    res.append(it).append("\n")
                    return@forEach
                }
            }

            res.append(t).append("\n")
        }
        return res.toString().trim()
    }

    /** true if the whole string is one valid JSON value (no trailing junk). */
    private fun isWholeJsonValue(s: String): Boolean = try {
        val tokener = JSONTokener(s)
        tokener.nextValue()
        tokener.nextClean().code == 0
    } catch (_: Throwable) {
        false
    }

    private fun convertJsonText(t: String): String? = try {
        if (t.startsWith("[")) {
            val arr = JSONArray(t)
            val out = StringBuilder()
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val piece = processJson(obj) ?: continue
                out.append(piece).append("\n")
            }
            out.toString().trim().takeIf { it.isNotEmpty() }
        } else {
            processJson(JSONObject(t))
        }
    } catch (_: Throwable) {
        null
    }

    private val PROXY_SCHEMES = arrayOf(
        "vless://", "vmess://", "trojan://", "ss://", "ssr://",
        "hysteria://", "hysteria2://", "hy2://", "tuic://", "socks://",
        "http://", "https://"
    )

    /**
     * Decodes a base64 blob only when the result looks like a config list:
     * strict UTF-8, no control characters, first line starts with a proxy
     * scheme or JSON. Anything else returns null and the text passes through.
     */
    private fun tryDecodeBase64(input: String): String? {
        if (input.length < 10) return null
        val cleaned = input.trim()

        var hasStd = false
        var hasUrl = false
        for (c in cleaned) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == ' ' || c == '\t' ||
                    c == '=' || c == '\r' || c == '\n' -> {}
                c == '+' || c == '/' -> hasStd = true
                c == '-' || c == '_' -> hasUrl = true
                else -> return null
            }
        }
        if (hasStd && hasUrl) return null
        val flag = if (hasUrl) android.util.Base64.URL_SAFE else android.util.Base64.DEFAULT

        return try {
            val data = android.util.Base64.decode(cleaned, flag)
            if (data.isEmpty()) return null
            val decodedRaw = Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(data))
                .toString()
            for (ch in decodedRaw) {
                val cc = ch.code
                if (cc == 0x7f || (cc < 0x20 && cc != 0x09 && cc != 0x0a && cc != 0x0d)) return null
            }
            val decoded = decodedRaw.trimStart()
            val firstLine = decoded.lineSequence().firstOrNull { it.isNotBlank() }?.trimStart() ?: return null
            val looksLikeJson = firstLine.startsWith("{") || firstLine.startsWith("[")
            val looksLikeProxyList = PROXY_SCHEMES.any { firstLine.startsWith(it, ignoreCase = true) }
            if (looksLikeJson || looksLikeProxyList) decoded.trim() else null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    //region JSON outbound -> share link

    private fun processJson(root: JSONObject): String? {
        if (isShadowsocks(root)) {
            return buildShadowsocks(root, root.optString("remarks", ""))
        }

        val protocol = root.optString("protocol", root.optString("type"))
        when (protocol) {
            "vmess" -> return buildVmess(root, root.optString("tag", root.optString("remarks", "")))
            "tuic" -> return buildTuic(root, root.optString("tag", root.optString("remarks", "")))
        }

        val obs = root.optJSONArray("outbounds") ?: return null
        val rem = root.optString("remarks", "")
        for (i in 0 until obs.length()) {
            val ob = obs.optJSONObject(i) ?: continue
            val p = ob.optString("protocol", ob.optString("type"))
            val built = when (p) {
                "vless" -> buildVless(ob, rem)
                "vmess" -> buildVmess(ob, rem)
                "shadowsocks" -> buildShadowsocks(ob, rem)
                "trojan" -> buildTrojan(ob, rem)
                "hysteria2" -> buildHysteria2(ob, rem)
                "tuic" -> buildTuic(ob, rem)
                else -> if (isShadowsocks(ob)) buildShadowsocks(ob, rem) else null
            }
            if (built != null) return built
        }
        return null
    }

    private fun isShadowsocks(obj: JSONObject): Boolean {
        if (obj.has("server") && obj.has("server_port") && obj.has("password") && obj.has("method")) return true
        val servers = obj.optJSONObject("settings")?.optJSONArray("servers")
        if (servers != null && servers.length() > 0) {
            val s = servers.getJSONObject(0)
            if (s.has("address") && s.has("port") && s.has("password") && s.has("method")) return true
        }
        return false
    }

    private fun buildVless(ob: JSONObject, rem: String): String? = try {
        val s = ob.optJSONObject("settings") ?: return null
        val vnext = s.optJSONArray("vnext") ?: return null
        if (vnext.length() == 0) return null
        val vn = vnext.getJSONObject(0)
        val users = vn.optJSONArray("users") ?: return null
        if (users.length() == 0) return null
        val u = users.getJSONObject(0)
        val ss = ob.optJSONObject("streamSettings")
        val rs = ss?.optJSONObject("realitySettings")
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        val fp = rs?.optString("fingerprint", "chrome") ?: "chrome"
        val pbk = rs?.optString("publicKey", "") ?: ""
        val sid = rs?.optString("shortId", "") ?: ""
        val sni = rs?.optString("serverName", "") ?: ""
        val security = ss?.optString("security", "none") ?: "none"
        val type = ss?.optString("network", "tcp") ?: "tcp"
        val params = linkedMapOf(
            "encryption" to u.optString("encryption", "none"),
            "flow" to u.optString("flow", ""),
            "fp" to fp,
            "pbk" to pbk,
            "security" to security,
            "sid" to sid,
            "sni" to sni,
            "type" to type,
        )
        val query = params.filterValues { it.isNotEmpty() }
            .entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}" }
        "vless://${u.getString("id")}@${vn.getString("address")}:${vn.getInt("port")}?$query#$enc"
    } catch (_: Exception) {
        null
    }

    private fun buildVmess(ob: JSONObject, rem: String): String? = try {
        val linkJson = JSONObject()
        linkJson.put("v", "2")

        val settings = ob.optJSONObject("settings")
        val vnext = settings?.optJSONArray("vnext")?.optJSONObject(0)

        val addr = ob.optString("server", vnext?.optString("address", "") ?: "")
        val port = if (ob.has("server_port")) ob.getInt("server_port") else vnext?.optInt("port", 0) ?: 0
        val uuid = ob.optString("uuid", vnext?.optJSONArray("users")?.optJSONObject(0)?.optString("id", "") ?: "")

        linkJson.put("add", addr)
        linkJson.put("port", port.toString())
        linkJson.put("id", uuid)
        linkJson.put("aid", "0")
        linkJson.put("scy", "auto")

        val transport = ob.optJSONObject("transport")
        val stream = ob.optJSONObject("streamSettings")
        val net = transport?.optString("type") ?: stream?.optString("network") ?: "tcp"
        linkJson.put("net", net)

        val tlsObj = ob.optJSONObject("tls")
        val isTls = tlsObj?.optBoolean("enabled") ?: (stream?.optString("security") == "tls")
        linkJson.put("tls", if (isTls) "tls" else "")

        if (net == "ws") {
            val ws = transport ?: stream?.optJSONObject("wsSettings")
            linkJson.put("path", ws?.optString("path"))
            val host = ws?.optJSONObject("headers")?.optString("Host") ?: ws?.optString("headers")
            if (host != null) linkJson.put("host", host)
        }

        val finalRem = if (ob.has("tag")) ob.getString("tag") else ob.optString("remarks", rem)
        linkJson.put("ps", finalRem)

        val base64 = android.util.Base64.encodeToString(linkJson.toString().toByteArray(), android.util.Base64.NO_WRAP)
        "vmess://$base64"
    } catch (_: Exception) {
        null
    }

    private fun buildShadowsocks(ob: JSONObject, rem: String): String? = try {
        val address: String
        val port: Int
        val method: String
        val password: String
        if (ob.has("server")) {
            address = ob.getString("server")
            port = ob.getInt("server_port")
            method = ob.getString("method")
            password = ob.getString("password")
        } else {
            val s = ob.optJSONObject("settings")?.optJSONArray("servers")?.getJSONObject(0) ?: return null
            address = s.getString("address")
            port = s.getInt("port")
            method = s.getString("method")
            password = s.getString("password")
        }
        val credentials = "$method:$password"
        val ui = android.util.Base64.encodeToString(credentials.toByteArray(), android.util.Base64.NO_WRAP)
        val finalRem = ob.optString("remarks", rem)
        val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")
        "ss://$ui@$address:$port#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildTrojan(ob: JSONObject, rem: String): String? = try {
        val server = ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0) ?: return null
        val address = server.optString("address")
        val port = server.optInt("port")
        val password = server.optString("password")

        val ss = ob.optJSONObject("streamSettings")
        val network = ss?.optString("network")
        val security = ss?.optString("security")

        val query = mutableMapOf<String, String>()
        if (!network.isNullOrEmpty()) query["type"] = network

        if (security == "tls" || security == "reality") {
            val tls = ss?.optJSONObject("tlsSettings") ?: ss?.optJSONObject("realitySettings")
            tls?.optString("serverName")?.takeIf { it.isNotEmpty() }?.let {
                query["sni"] = it
                query["host"] = it
            }
        }

        if (network == "ws") {
            val ws = ss?.optJSONObject("wsSettings")
            ws?.optString("path")?.takeIf { it.isNotEmpty() }?.let { query["path"] = it }
            ws?.optJSONObject("headers")?.optString("Host")?.takeIf { it.isNotEmpty() }?.let { query["host"] = it }
        }

        val queryStr = query.entries.sortedBy { it.key }.joinToString("&") {
            "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
        val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""
        val encPass = URLEncoder.encode(password, "UTF-8")
        val encRem = URLEncoder.encode(ob.optString("remarks", rem), "UTF-8").replace("+", "%20")

        "trojan://$encPass@$address:$port$queryString#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildHysteria2(ob: JSONObject, rem: String): String? = try {
        val server = ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0) ?: return null
        val address = server.optString("address")
        val port = server.optInt("port")

        val ss = ob.optJSONObject("streamSettings")
        val hy2 = ss?.optJSONObject("hy2Settings")
        val password = hy2?.optString("password") ?: ""
        val obfs = hy2?.optJSONObject("obfs")
        val obfsType = obfs?.optString("type")
        val obfsPassword = obfs?.optString("password")
        val sni = ss?.optJSONObject("tlsSettings")?.optString("serverName")

        val query = StringBuilder()
        if (!obfsType.isNullOrEmpty()) query.append("&obfs=").append(URLEncoder.encode(obfsType, "UTF-8"))
        if (!obfsPassword.isNullOrEmpty()) query.append("&obfs-password=").append(URLEncoder.encode(obfsPassword, "UTF-8"))
        if (!sni.isNullOrEmpty()) query.append("&sni=").append(URLEncoder.encode(sni, "UTF-8"))

        val queryString = if (query.isNotEmpty()) "?" + query.substring(1) else ""
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")

        "hysteria2://$password@$address:$port/$queryString#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildTuic(ob: JSONObject, rem: String): String? = try {
        val address = ob.optString("server")
        val port = ob.optInt("server_port")
        val uuid = ob.optString("uuid")
        val password = ob.optString("password")

        val query = mutableMapOf<String, String>()
        ob.optString("congestion_control").takeIf { it.isNotEmpty() }?.let { query["congestion_control"] = it }
        ob.optString("udp_relay_mode").takeIf { it.isNotEmpty() }?.let { query["udp_relay_mode"] = it }

        val tls = ob.optJSONObject("tls")
        if (tls != null && tls.optBoolean("enabled", false)) {
            tls.optString("server_name").takeIf { it.isNotEmpty() }?.let { query["sni"] = it }
            tls.optJSONArray("alpn")?.optString(0)?.takeIf { it.isNotEmpty() }?.let { query["alpn"] = it }
            if (tls.optBoolean("insecure", false)) query["allow_insecure"] = "1"
        }

        val queryStr = query.entries.sortedBy { it.key }.joinToString("&") {
            "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
        val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""

        val finalRem = if (ob.has("tag")) ob.getString("tag") else ob.optString("remarks", rem)
        val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")

        "tuic://$uuid:$password@$address:$port$queryString#$encRem"
    } catch (_: Exception) {
        null
    }
    //endregion
}
