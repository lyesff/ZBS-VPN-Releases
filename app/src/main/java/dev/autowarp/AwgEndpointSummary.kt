package dev.autowarp

/** Public endpoint only; never render the quick-config or neighbouring keys. */
internal fun awgConfiguredEndpoint(quick:String):String? {
    val matches=Regex("(?m)^[ \\t]*Endpoint[ \\t]*=[ \\t]*([^\\r\\n]+)")
        .findAll(quick).toList()
    if(matches.size!=1)return null
    val value=matches.single().groupValues[1].substringBefore('#').trim()
    if(value.length>280)return null
    if(!value.matches(Regex("(?:[A-Za-z0-9][A-Za-z0-9.-]*|\\[[0-9A-Fa-f:.]+\\]):[0-9]{1,5}")))return null
    val port=value.substringAfterLast(':').toIntOrNull() ?: return null
    return value.takeIf {port in 1..65535}
}
