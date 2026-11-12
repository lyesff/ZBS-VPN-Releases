package dev.autowarp

import org.json.JSONObject
import java.util.Base64

/**
 * Locally derives an experimental AWG v3 quick-config from the *selected*
 * registered WARP profile. Never requests credentials from a third party.
 *
 * The conservative preset is NOT proof that the endpoint works. In particular,
 * this does not claim to reproduce router-specific I1/I2 obfuscation chains.
 */
internal object AmneziaWarpGenerator {
    private val keyPattern = Regex("^[A-Za-z0-9+/]{43}=$")
    private fun validKey(s:String):Boolean =
        keyPattern.matches(s) && runCatching { Base64.getDecoder().decode(s).size == 32 }.getOrDefault(false)

    fun generate(state:JSONObject):String {
        val selected=state.optString("warp")
        require(selected.isNotBlank()) { "no_warp_profile" }
        val profile=state.map("wg").optJSONObject(selected)
            ?: throw IllegalArgumentException("no_warp_profile")
        val original=profile.optString("ini")
        require(original.length in 50..65536) { "missing_warp_config" }

        val fields=linkedMapOf<String,MutableMap<String,String>>()
        var section=""
        for(line in original.lineSequence()){
            val item=line.substringBefore('#').trim()
            if(item.isEmpty())continue
            if(item.startsWith("[")){
                require(item in setOf("[Interface]","[Peer]") && item !in fields) { "invalid_sections" }
                section=item
                fields[item]=linkedMapOf()
            }else{
                require(section.isNotEmpty()) { "missing_section" }
                val (key,value)=item.split('=',limit=2).takeIf {it.size==2}
                    ?: throw IllegalArgumentException("invalid_entry")
                val k=key.trim()
                val v=value.trim()
                require(k.isNotEmpty() && v.isNotEmpty() && !fields.getValue(section).containsKey(k)) { "invalid_entry" }
                fields.getValue(section)[k]=v
            }
        }
        val iface=fields["[Interface]"] ?: throw IllegalArgumentException("missing_interface")
        val peer=fields["[Peer]"] ?: throw IllegalArgumentException("missing_peer")
        val privateKey=iface["PrivateKey"].orEmpty()
        val publicKey=peer["PublicKey"].orEmpty()
        require(validKey(privateKey) && validKey(publicKey)) { "invalid_keys" }
        val addresses=iface["Address"].orEmpty()
        require(addresses.isNotBlank() && addresses.length<256 && addresses.split(',').all {
            it.trim().matches(Regex("[a-fA-F0-9:.]+(?:/[0-9]{1,3})?"))
        }) { "invalid_addresses" }
        val allowed=peer["AllowedIPs"].orEmpty()
        require(allowed.isNotBlank() && allowed.length<256 &&
            allowed.split(',').all { it.trim().matches(Regex("[a-fA-F0-9:.]+/[0-9]{1,3}")) }
        ) { "invalid_allowed_ips" }

        // Use the user's selected endpoint if present; otherwise keep the
        // endpoint from their registered WARP profile.
        val explicit=state.optString("endpoint").takeIf {it.isNotBlank()}
        if(explicit!=null)require(endpoints(profile).any { (host,port)->"$host/$port"==explicit }) {
            "unknown_endpoint"
        }
        val endpoint=if(explicit!=null){
            val host=explicit.substringBeforeLast('/')
            val port=explicit.substringAfterLast('/')
            if(':' in host)"[$host]:$port" else "$host:$port"
        }else peer["Endpoint"].orEmpty()
        require(endpoint.isNotBlank() && endpoint.length<280 &&
            !endpoint.contains('\n') && !endpoint.contains('\r')) { "invalid_endpoint" }
        val keepalive=peer["PersistentKeepalive"].orEmpty().ifBlank { "25" }
        val keepaliveSeconds=keepalive.toIntOrNull() ?: -1
        require(keepaliveSeconds in 0..65535) { "invalid_keepalive" }

        return buildString {
            appendLine("[Interface]")
            appendLine("PrivateKey = $privateKey")
            appendLine("Address = $addresses")
            appendLine("MTU = 1280")
            appendLine("S1 = 0")
            appendLine("S2 = 0")
            appendLine("S3 = 0")
            appendLine("S4 = 0")
            appendLine("Jc = 4")
            appendLine("Jmin = 40")
            appendLine("Jmax = 70")
            appendLine("H1 = 1")
            appendLine("H2 = 2")
            appendLine("H3 = 3")
            appendLine("H4 = 4")
            appendLine("RandomTrailers = on")
            appendLine("DisableCookies = on")
            appendLine()
            appendLine("[Peer]")
            appendLine("PublicKey = $publicKey")
            appendLine("Endpoint = $endpoint")
            appendLine("AllowedIPs = $allowed")
            appendLine("PersistentKeepalive = $keepalive")
        }
    }
}
