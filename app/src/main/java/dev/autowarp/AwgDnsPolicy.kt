package dev.autowarp

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject

internal data class AwgDnsProvider(val id:String,val name:String,val url:String)

internal object AwgDnsPolicy {
    const val LOCAL_DNS="198.18.0.53"
    val providers=listOf(
        AwgDnsProvider("bezmezhau","Bezmezhau","https://dns.bezmezhau.com/dns-query"),
        AwgDnsProvider("malw","MALW","https://dns.malw.link/dns-query"),
        AwgDnsProvider("webshift","WebShift","https://d.webshiftvpn.ru/dns-query"),
        AwgDnsProvider("xbox","Xbox DNS","https://xbox-dns.ru/dns-query")
    )
    fun customUrl(value:String):HttpUrl? {
        if(value.length !in 1..2048 || value!=value.trim() || value.any {it.isWhitespace() || it.code<32})return null
        val u=value.toHttpUrlOrNull() ?: return null
        if(u.scheme!="https" || u.username.isNotEmpty() || u.password.isNotEmpty() || u.fragment!=null || u.encodedPath=="/")return null
        return u
    }
    fun selected(s:JSONObject):AwgDnsProvider?=when(val id=s.optString("awgDohProvider")){
        "","off"->null
        "custom"->AwgDnsProvider("custom","Свой DoH",customUrl(s.optString("awgDohCustom"))?.toString()
            ?: error("invalid_doh_url"))
        else->providers.firstOrNull{it.id==id} ?: error("invalid_doh_provider")
    }
    fun label(s:JSONObject):String=runCatching{selected(s)?.name ?: "Выключен"}.getOrDefault("Проверьте адрес DoH")
}
