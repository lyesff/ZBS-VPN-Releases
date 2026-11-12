package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.constructor.SafeConstructor

/**
 * Converts only a reviewed subset of Clash/Mihomo proxies into sing-box
 * VLESS outbounds. Router DNS/rules/TUN are deliberately not imported.
 * Unknown critical settings are not silently weakened.
 */
internal object ClashYamlAdapter {
    private fun str(m: Map<*, *>, key: String): String? = m[key] as? String
    private fun bool(m: Map<*, *>, key: String): Boolean? = m[key] as? Boolean
    private fun num(m: Map<*, *>, key: String): Int? = (m[key] as? Number)?.toInt()
    private fun fieldsAreSafe(m: Map<*, *>, allowed: Set<String>): Boolean =
        m.keys.all { it is String && it in allowed }

    /** Diagnostic metadata only, never filenames, hosts, UUIDs or YAML values. */
    fun diagnose(raw:String):JSONObject {
        val result=JSONObject().put("format","unknown").put("proxies",0)
            .put("vless",0).put("converted",0).put("providers",false)
        if (raw.length>1_048_576) return result.put("format","too_large")
        val options=LoaderOptions().apply {
            maxAliasesForCollections=10
            codePointLimit=1_048_576
            nestingDepthLimit=30
            isAllowDuplicateKeys=false
        }
        val trimmed=raw.trimStart('\uFEFF',' ','\n','\r','\t')
        if(trimmed.isBlank()) return result.put("format","empty")
        if(trimmed.startsWith("{") || trimmed.startsWith("[")) return result.put("format","json")
        if(trimmed.startsWith("<!DOCTYPE",true) || trimmed.startsWith("<html",true)) return result.put("format","html")
        if(trimmed.startsWith("vless://") || trimmed.startsWith("trojan://") ||
           trimmed.startsWith("vmess://") || trimmed.startsWith("hysteria2://")) return result.put("format","uri_list")
        val parsed=runCatching {Yaml(SafeConstructor(options)).load<Any>(trimmed)}
        if(parsed.isFailure) return result.put("format","yaml_parse_error")
        val root=parsed.getOrNull()
        val map=root as? Map<*, *> ?: return result.put("format",
            if(root is String && trimmed.length>=64 && trimmed.all {it.isLetterOrDigit() || it in "+/=_-\\n\\r"})
                "base64_or_encoded" else "yaml_not_mapping")
        result.put("providers",map.containsKey("proxy-providers"))
        val proxies=map["proxies"] as? List<*>
            ?: return result.put("format",if(map.containsKey("proxy-providers"))"providers_only" else "no_proxies")
        result.put("format","clash_yaml").put("proxies",proxies.size)
            .put("vless",proxies.count{(it as? Map<*, *>)?.get("type")=="vless"})
        val converted=convert(raw)
        result.put("converted",if(converted==null)0 else runCatching{JSONArray(converted).length()}.getOrDefault(0))
        return result
    }

    fun convert(raw: String): String? {
        if (raw.length > 1_048_576 || !Regex("(?m)^\\s*proxies\\s*:").containsMatchIn(raw)) return null
        val loader = LoaderOptions().apply {
            maxAliasesForCollections = 10
            codePointLimit = 1_048_576
            nestingDepthLimit = 30
            isAllowDuplicateKeys = false
        }
        val root = runCatching { Yaml(SafeConstructor(loader)).load<Any>(raw.trimStart('\uFEFF')) as? Map<*, *> }.getOrNull()
            ?: return null
        val entries = root["proxies"] as? List<*> ?: return null
        if (entries.size > 512) return null
        val converted = JSONArray()
        for (entry in entries) {
            val node = entry as? Map<*, *> ?: continue
            if (str(node,"type") != "vless") continue
            val allowed=setOf("name","type","server","port","network","udp","uuid",
                "packet-encoding","tls","servername","client-fingerprint","smux",
                "flow","skip-cert-verify","alpn")
            if (!fieldsAreSafe(node,allowed)) continue
            val host=str(node,"server") ?: continue
            val port=num(node,"port") ?: continue
            val uuid=str(node,"uuid") ?: continue
            if (host.isBlank() || port !in 1..65535 || uuid.isBlank()) continue
            if (node["tls"] != true || bool(node,"skip-cert-verify") == true) continue
            if (str(node,"network") !in listOf(null,"tcp")) continue
            if (str(node,"flow") !in listOf(null,"","xtls-rprx-vision")) continue
            if (str(node,"packet-encoding") !in listOf(null,"","xudp","packetaddr")) continue
            val tls=JSONObject().put("enabled",true)
            str(node,"servername")?.takeIf { it.isNotBlank() }?.let { tls.put("server_name",it) }
            str(node,"client-fingerprint")?.takeIf { it.isNotBlank() }?.let { fp ->
                if (fp !in setOf("chrome","firefox","safari","ios","android","edge","random","randomized")) return@let
                tls.put("utls",JSONObject().put("enabled",true).put("fingerprint",fp))
            }
            if (str(node,"client-fingerprint")?.takeIf { it.isNotBlank() } != null && !tls.has("utls")) continue
            (node["alpn"] as? List<*>)?.let { a ->
                if (a.any { it !is String }) return@let
                tls.put("alpn", JSONArray(a))
            }
            val out=JSONObject().put("type","vless").put("server",host)
                .put("server_port",port).put("uuid",uuid).put("tls",tls)
                .put("tag",str(node,"name") ?: host)
            str(node,"flow")?.takeIf { it.isNotBlank() }?.let { out.put("flow",it) }
            str(node,"packet-encoding")?.takeIf { it.isNotBlank() }?.let { out.put("packet_encoding",it) }
            val smux=node["smux"] as? Map<*, *>
            if (node.containsKey("smux") && smux==null) continue
            if (smux!=null && smux["enabled"]==true) {
                if (!fieldsAreSafe(smux,setOf("enabled","padding","only-tcp","protocol","statistic","max-connections"))) continue
                if (smux["only-tcp"]==true || smux["statistic"]==true) continue
                val proto=str(smux,"protocol") ?: "smux"
                if (proto !in setOf("smux","yamux","h2mux")) continue
                val mux=JSONObject().put("enabled",true).put("protocol",proto)
                bool(smux,"padding")?.let { mux.put("padding",it) }
                num(smux,"max-connections")?.let { if(it in 1..64) mux.put("max_connections",it) }
                out.put("multiplex",mux)
            }
            converted.put(out)
        }
        return converted.takeIf { it.length()>0 }?.toString()
    }
}
