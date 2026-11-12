package dev.autowarp

import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Compatibility profiles affect only the HTTP request for subscriptions.
 * No fake device identifier, authorization token, or private key is sent.
 */
internal val subscriptionClients=listOf("AutoWARP", "Happ-совместимый (эксперимент)")
internal fun subscriptionRequest(url:String, client:String):Request {
    val builder=Request.Builder().url(url).header("Accept", "*/*")
    if(client==subscriptionClients[1]){
        // Unofficial, version-specific request profile. Not a Happ API guarantee.
        builder.header("User-Agent","Happ/3.13.0")
            .header("X-Device-Os","Android")
            .header("X-Device-Locale",Locale.getDefault().language.ifBlank{"ru"}.take(8))
    }else{
        builder.header("User-Agent","AutoWARP/0.1.6")
    }
    return builder.build()
}

/** Detect well-known provider fallback entries without inspecting secrets. */
internal fun placeholderName(name:String):Boolean {
    val n=name.lowercase(Locale.ROOT)
    return listOf("приложение не поддерживается","неподдерживаемое приложение",
        "unsupported app","application not supported","app not supported",
        "не поддерживается клиент","unsupported client").any { n.contains(it) }
}
internal fun providerPlaceholders(items:JSONArray):Int=(0 until items.length()).count {
    placeholderName(items.optJSONObject(it)?.optString("name").orEmpty())
}
internal fun subscriptionStats(items:JSONArray):JSONObject=JSONObject().put("imported",items.length())
    .put("providerPlaceholders",providerPlaceholders(items))

/**
 * Metadata-only classification; never save or log URLs, credential fields,
 * response samples, or raw subscription content.
 */
internal fun subscriptionShape(raw:String):JSONObject {
    val input=raw.trim()
    val isRaw=input.startsWith("{") || input.startsWith("[") || input.contains("://") ||
        input.lineSequence().any { it.trimStart().startsWith("proxies:") || it.trimStart().startsWith("proxy-groups:") || it.trimStart().startsWith("<html",true) }
    val sample=if(isRaw) input else {
        runCatching {
            val compact=input.filterNot(Char::isWhitespace)
            val data=android.util.Base64.decode(compact,android.util.Base64.DEFAULT)
            if(data.size>1048576)"" else String(data,Charsets.UTF_8)
        }.getOrDefault("")
    }
    val shape=when {
        sample.isBlank() -> "unknown"
        sample.startsWith("<!DOCTYPE",true) || sample.startsWith("<html",true) -> "html"
        sample.startsWith("{") || sample.startsWith("[") -> "json"
        sample.lineSequence().any {it.trimStart().startsWith("proxies:") || it.trimStart().startsWith("proxy-groups:")} -> "clash_yaml"
        sample.contains("://") -> if(isRaw)"uri_list" else "base64_uri_list"
        else -> "plain_text"
    }
    fun count(scheme:String)=Regex("(?im)^\\s*"+Regex.escape(scheme)+"://").findAll(sample).count()
    val result=JSONObject().put("shape",shape).put("vless",count("vless"))
        .put("trojan",count("trojan")).put("vmess",count("vmess"))
        .put("hy2",count("hy2")+count("hysteria2"))
    if(shape=="json"){
        val root=runCatching { org.json.JSONTokener(sample).nextValue() }.getOrNull()
        val obj=root as? JSONObject
        val list=root as? JSONArray
        val data=obj?.optJSONObject("data")
        val entries=list ?: obj?.optJSONArray("outbounds") ?: obj?.optJSONArray("servers")
            ?: obj?.optJSONArray("proxies") ?: obj?.optJSONArray("nodes")
            ?: data?.optJSONArray("outbounds") ?: data?.optJSONArray("servers")
            ?: data?.optJSONArray("proxies") ?: data?.optJSONArray("nodes")
        val source=when{
            list!=null->"array"
            obj?.optJSONArray("outbounds")!=null || data?.optJSONArray("outbounds")!=null->"singbox"
            obj?.optJSONArray("servers")!=null || data?.optJSONArray("servers")!=null->"servers"
            obj?.optJSONArray("proxies")!=null || data?.optJSONArray("proxies")!=null->"clash_json"
            obj?.optJSONArray("nodes")!=null || data?.optJSONArray("nodes")!=null->"nodes"
            obj?.has("error")==true || obj?.has("errors")==true || obj?.has("message")==true ||
                obj?.has("detail")==true || data?.has("error")==true->"provider_message"
            obj!=null->"other_object"
            else->"invalid_json"
        }
        result.put("jsonKind",source).put("jsonEntries",entries?.length() ?: 0)
        val counts=mutableMapOf("vless" to 0,"trojan" to 0,"vmess" to 0,"hysteria2" to 0)
        if(entries!=null)for(i in 0 until minOf(entries.length(),512)){
            val item=entries.optJSONObject(i)
            val kind=item?.optString("type")?.lowercase(Locale.ROOT).orEmpty()
            if(counts.containsKey(kind))counts[kind]=counts.getValue(kind)+1
        }
        // Only recognized schema field NAMES are reported; never field values,
        // unknown names or secrets from a provider's JSON response.
        val allowed=setOf("type","protocol","name","tag","server","address",
            "port","server_port","settings","streamSettings","tls","transport",
            "url","config","outbounds","proxies","nodes","id","remarks",
            "uuid","password","ps","add","net","security","cipher")
        val observed=linkedSetOf<String>()
        if(entries!=null)for(i in 0 until minOf(entries.length(),32)){
            val item=entries.optJSONObject(i) ?: continue
            for(key in item.keys())if(key in allowed)observed.add(key)
        }
        result.put("knownFields",JSONArray(observed.sorted()))
        val format=when {
            "streamSettings" in observed || "protocol" in observed -> "xray_like"
            "settings" in observed && "server" !in observed -> "nested_config"
            "url" in observed -> "uri_wrappers"
            "config" in observed -> "config_wrappers"
            "type" in observed && "server" in observed -> "singbox_entries"
            else -> "unknown_entries"
        }
        result.put("entryFormat",format)
        // Shape-only inspection of nested outbound payloads. Do not serialize
        // values or arbitrary keys: they can include private credentials.
        val outboundTypes=mutableMapOf("array" to 0,"object" to 0,"string" to 0,"null" to 0,"other" to 0)
        val nestedFields=linkedSetOf<String>()
        val nestedAllowed=setOf("type","protocol","server","server_port","address","port",
            "settings","streamSettings","tls","transport","tag","outbounds","uuid",
            "password","security","vnext","servers","clients","network","id")
        var nestedEntries=0
        fun inspect(value:Any?){
            when(value){
                is JSONObject->for(key in value.keys())if(key in nestedAllowed)nestedFields.add(key)
                is JSONArray->for(j in 0 until minOf(value.length(),4)){
                    val child=value.optJSONObject(j) ?: continue
                    nestedEntries++
                    for(key in child.keys())if(key in nestedAllowed)nestedFields.add(key)
                }
                // String content can be encoded JSON, encrypted payload or
                // an opaque token. We deliberately do not parse or expose it.
            }
        }
        if(entries!=null)for(i in 0 until minOf(entries.length(),512)){
            val value=entries.optJSONObject(i)?.opt("outbounds") ?: continue
            val kind=when(value){
                is JSONArray->"array"
                is JSONObject->"object"
                is String->"string"
                JSONObject.NULL->"null"
                else->"other"
            }
            outboundTypes[kind]=outboundTypes.getValue(kind)+1
            inspect(value)
        }
        var innerVless=0
        var innerTrojan=0
        var innerOther=0
        fun countOutbound(v:Any?){
            val node=v as? JSONObject ?: return
            val type=node.optString("type").ifBlank { node.optString("protocol") }.lowercase(Locale.ROOT)
            when(type){
                "vless"->innerVless++
                "trojan"->innerTrojan++
                else->innerOther++
            }
        }
        if(entries!=null)for(i in 0 until minOf(entries.length(),512)){
            when(val inner=entries.optJSONObject(i)?.opt("outbounds")){
                is JSONObject->countOutbound(inner)
                is JSONArray->for(j in 0 until minOf(inner.length(),32))countOutbound(inner.opt(j))
            }
        }
        result.put("nestedVless",innerVless).put("nestedTrojan",innerTrojan)
            .put("nestedOther",innerOther)
        result.put("outboundsTypes",JSONObject(outboundTypes as Map<*,*>))
            .put("nestedOutboundFields",JSONArray(nestedFields.sorted()))
            .put("nestedSamples",nestedEntries)
        result.put("jsonVless",counts.getValue("vless"))
            .put("jsonTrojan",counts.getValue("trojan"))
            .put("jsonVmess",counts.getValue("vmess"))
            .put("jsonHy2",counts.getValue("hysteria2"))
    }
    return result
}
