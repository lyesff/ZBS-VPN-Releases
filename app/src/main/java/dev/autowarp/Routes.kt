package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress

val modes=listOf("Авто","WARP","VLESS","VLESS через WARP","WARP через VLESS")
fun nodes(s:JSONObject)=s.map("sources").entries().flatMap { (_,v)->val a=v.getJSONArray("items");(0 until a.length()).map(a::getJSONObject) }.distinctBy { it.getString("id") }
data class Route(val tag:String,val label:String,val kind:String,val warp:Boolean)
data class Plan(val json:String,val routes:List<Route>)
fun endpoints(w:JSONObject):List<Pair<String,Int>>{
    val p=w.getJSONObject("config").getJSONArray("peers").getJSONObject(0)
    val h=p.getString("address");val n=p.getInt("port")
    val all=mutableListOf(h to n)
    if(h.equals("engage.cloudflareclient.com",true)||h.matches(Regex("162[.]159[.](192|193)[.][0-9]{1,3}")))for(host in listOf(h,"162.159.193.1"))for(port in listOf(2408,500,4500))all+=host to port
    return all.distinct()
}
private fun selectedWarp(s:JSONObject)=s.map("wg").optJSONObject(s.optString("warp"))
private fun selectedEndpoints(s:JSONObject,w:JSONObject?)=w?.let(::endpoints).orEmpty().filter { (host,port)->
    val pin=s.optString("endpoint");pin.isBlank() || pin=="$host/$port"
}
private fun selectedNodes(s:JSONObject)=nodes(s).filter { node->
    val pin=s.optString("server");pin.isBlank() || pin==node.getString("id")
}
fun hasProfile(s:JSONObject):Boolean{
    val warp=selectedEndpoints(s,selectedWarp(s)).isNotEmpty()
    val vless=selectedNodes(s).isNotEmpty()
    return when(s.optString("mode","Авто")){
        "Авто"->warp || vless
        "WARP"->warp
        "VLESS"->vless
        "VLESS через WARP","WARP через VLESS"->warp && vless
        else->false
    }
}
fun plan(s:JSONObject,lookup:(String)->Array<InetAddress>):Plan{
    val mode=s.optString("mode","Авто");require(mode in modes)
    val outs=JSONArray();val ends=JSONArray();val routes=mutableListOf<Route>()
    val cache=mutableMapOf<String,String?>()
    fun addr(h:String):String?{if(h !in cache)cache[h]=runCatching { lookup(h).also { require(it.isNotEmpty()&&it.all(::publicIP)) }.first().hostAddress }.getOrNull();return cache[h]}
    val w=selectedWarp(s);var firstWarp:String?=null
    val choices=selectedEndpoints(s,w)
    fun addWarp(host:String,port:Int,tag:String,via:String?=null):Boolean{
        if(w==null)return false
        val c=JSONObject(w.getJSONObject("config").toString()).put("tag",tag)
        val p=c.getJSONArray("peers").getJSONObject(0)
        p.put("address",addr(host) ?: return false).put("port",port)
        if(choices.size>1)p.put("persistent_keepalive_interval",0)
        if(via!=null)c.put("detour",via)
        ends.put(c);return true
    }
    if(w!=null && mode !in listOf("VLESS","WARP через VLESS")){
        for((h,p) in if(mode=="VLESS через WARP")choices.take(1) else choices){
            val tag="w-"+w.getString("id")+"-"+digest("$h/$p")
            if(addWarp(h,p,tag)){if(firstWarp==null)firstWarp=tag;if(mode!="VLESS через WARP")routes+=Route(tag,"$h · $p","WARP",true)}
        }
    }
    if(mode!="WARP")for(node in selectedNodes(s).take(if(mode=="WARP через VLESS")6 else 32)){
        val tag="v-"+node.getString("id");val label=node.getString("name")
        val c=JSONObject(node.getJSONObject("config").toString())
        c.put("server",addr(c.getString("server")) ?: continue).put("tag",tag)
        when(mode){
            "VLESS через WARP"->{val t="$tag-vw";c.put("tag",t).put("detour",firstWarp ?: continue);outs.put(c);routes+=Route(t,label,mode,false)}
            "WARP через VLESS"->{val ep=choices.firstOrNull() ?: continue;val t="wv-"+node.getString("id");if(addWarp(ep.first,ep.second,t,tag)){outs.put(c);routes+=Route(t,label,mode,true)}}
            else->{outs.put(c);routes+=Route(tag,label,c.optString("type","VLESS").uppercase(),false)}
        }
    }
    require(routes.isNotEmpty()){"Нет подходящего профиля"}
    val sel=obj("type" to "selector","tag" to "vpn","outbounds" to JSONArray(routes.map { it.tag }),"interrupt_exist_connections" to true)
    val outputs=arr(sel);for(i in 0 until outs.length())outputs.put(outs.get(i))
    val ipv6=s.optBoolean("ipv6",true);val addresses=arr("172.19.0.1/30");if(ipv6)addresses.put("fdfe:ca7e::1/126")
    val dns=s.optString("dns","1.1.1.1");require(dns in listOf("1.1.1.1","9.9.9.9"))
    val conf=obj("log" to obj("disabled" to true),"inbounds" to arr(obj("type" to "tun","tag" to "tun","stack" to "mixed","mtu" to 1280,"address" to addresses,"auto_route" to true)),
        "outbounds" to outputs,"endpoints" to ends,"route" to obj("final" to "vpn","auto_detect_interface" to true,"rules" to arr(obj("port" to 53,"action" to "hijack-dns"))),
        "dns" to obj("final" to "secure","strategy" to if(ipv6)"prefer_ipv4" else "ipv4_only","servers" to arr(obj("type" to "tls","tag" to "secure","server" to dns,"detour" to "vpn","tls" to obj("enabled" to true,"server_name" to if(dns=="1.1.1.1")"one.one.one.one" else "dns.quad9.net")))),
        "experimental" to obj("clash_api" to JSONObject()))
    return Plan(conf.toString(),routes)
}

// Only choices that can change the eligible routes enter the identity.
// Health samples and transfer counters must not trigger a rebuild.
fun routeSelectionKey(s:JSONObject)=listOf(
    s.optString("mode","Авто"),s.optString("warp"),s.optString("endpoint"),s.optString("server"),
    selectedWarp(s)?.optString("id").orEmpty(),selectedNodes(s).joinToString(","){it.getString("id")}
).joinToString("|")

/**
 * Build a temporary core exclusively for explicit VLESS preflight checks.
 * It has NO TUN inbound and does not modify Android VPN routing.
 * Names, hosts and credentials never enter the health log.
 */
fun scanPlan(s:JSONObject, lookup:(String)->Array<InetAddress>, limit:Int=24):Plan {
    val list=nodes(s).take(limit.coerceIn(1,24))
    val routes=mutableListOf<Route>()
    val outs=arr(obj("type" to "direct","tag" to "direct"))
    val cache=mutableMapOf<String,String?>()
    for(node in list){
        val cfg=JSONObject(node.getJSONObject("config").toString())
        val host=cfg.getString("server")
        val resolved=cache.getOrPut(host){
            runCatching{lookup(host).also{require(it.isNotEmpty() && it.all(::publicIP))}.first().hostAddress}.getOrNull()
        } ?: continue
        val tag="v-"+node.getString("id")
        cfg.put("server",resolved).put("tag",tag)
        outs.put(cfg)
        routes+=Route(tag,node.getString("name"),cfg.optString("type","VLESS").uppercase(),false)
    }
    require(routes.isNotEmpty()){"Нет доступных VLESS-узлов для проверки"}
    return Plan(obj(
        "log" to obj("disabled" to true),
        "outbounds" to outs,
        "route" to obj("final" to "direct","auto_detect_interface" to true)
    ).toString(),routes)
}
