package dev.autowarp

import kotlin.random.Random

/** Bounded WARP endpoint exploration; a different IP is never proof of country. */
internal object AwgEndpointPicker {
    const val LIMIT=8
    private val endpointLine=Regex("(?m)^[ \\t]*Endpoint[ \\t]*=[^\\r\\n]*")
    internal val ranges=listOf("188.114.96", "188.114.97", "188.114.98", "188.114.99",
        "162.159.192", "162.159.193", "162.159.195", "8.34.146", "8.39.214",
        "8.39.204", "8.6.112", "8.35.211", "8.39.125", "8.47.69")

    fun candidates(resolved:String,enabled:Boolean,random:Random=Random.Default):List<String> {
        val original=awgConfiguredEndpoint(resolved) ?: return emptyList()
        val host=original.substringBeforeLast(':')
        // Imported third-party AWG servers must never be sent to Cloudflare.
        val octets=host.split('.')
        val cloudflare=octets.size==4 && octets.all {part->part.toIntOrNull()?.let {it in 0..255}==true} &&
            host.substringBeforeLast('.') in ranges
        if(!enabled || !cloudflare)return listOf(resolved)
        val alternatives=ranges.shuffled(random).map {prefix->
            // Router-style WARP ingress exploration, one per known /24.
            "$prefix.${random.nextInt(1,255)}:4500"
        }
        return (listOf(original)+alternatives).distinct().take(LIMIT).map {replace(resolved,it)}
    }

    fun isCloudflare(resolved:String):Boolean {
        val endpoint=awgConfiguredEndpoint(resolved) ?: return false
        return endpoint.substringBeforeLast(':').substringBeforeLast('.') in ranges
    }

    fun replace(quick:String,endpoint:String):String {
        require(awgConfiguredEndpoint("Endpoint = $endpoint") == endpoint)
        val matches=endpointLine.findAll(quick).toList()
        require(matches.size==1)
        return quick.replaceRange(matches.single().range,"Endpoint = $endpoint")
    }

    /** Compare inside Store.edit's lock so a newer imported profile wins. */
    fun savedQuick(current:String,original:String,selected:String):String? {
        if(current!=original)return null
        val endpoint=awgConfiguredEndpoint(selected) ?: return null
        return replace(original,endpoint).takeIf {it!=original}
    }
}
