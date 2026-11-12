package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject

/**
 * Shareable diagnostics: never serialize full profile JSON, WARP registration,
 * WireGuard keys, URLs, UUIDs, or native exception messages.
 * Endpoint and profile names are intentionally omitted.
 */
fun diagnosticReport(s: JSONObject, state: String): JSONObject {
    val selected=s.map("wg").optJSONObject(s.optString("warp"))
    val peer=selected?.optJSONObject("config")?.optJSONArray("peers")?.optJSONObject(0)
    val reserved=peer?.optJSONArray("reserved")
    val health=s.map("health")
    val checks=JSONArray()
    for ((tag, result) in health.entries().sortedByDescending { it.second.optLong("at",0) }.take(30)) {
        val code=result.optString("error").takeIf {
            it.matches(Regex("probe_(timeout|cancelled|dns|tls_certificate|transport|trace_body|trace_ip|warp_not_confirmed|http_[0-9]{3}|unknown)|awg_(?:tun_create_failed|ipc_config_failed|endpoint_dns_failed|device_start_failed|no_handshake|https_timeout|tcp_timeout|tls_timeout|http_timeout|invalid_file|invalid_config|tunnel_failed|not_confirmed|https_failed|verified:[0-9]{1,5})"))
        }.orEmpty()
        checks.put(obj(
            "kind" to when {
                tag.startsWith("w-")->"WARP"
                tag.startsWith("v-")->"VLESS"
                else->"other"
            },
            "latency_ms" to result.optLong("ms",-1),
            "error" to code,
            "tested_at" to result.optLong("at",0)
        ))
    }
    val eventExport=JSONArray()
    val history=s.optJSONArray("eventLog")
    val knownEvents=setOf("start","network_wifi","network_cellular","network_other",
        "network_missing","core_start","core_ready","probe_start","probe_ok","probe_fail",
        "route_switch","route_online","route_failed","recover","stopped","core_failed",
        "scan_start","scan_done","awg_probe_start","awg_probe_ok","awg_probe_fail",
        "awg_doh_start","awg_doh_ready","awg_doh_failed")
    if(history!=null)for(i in maxOf(0,history.length()-40) until history.length()){
        val item=history.optJSONObject(i) ?: continue
        val code=item.optString("code")
        if(code !in knownEvents)continue
        val kind=item.optString("kind").takeIf {it in setOf("WARP","VLESS","other")}.orEmpty()
        val error=item.optString("error").takeIf {
            it.matches(Regex("probe_(?:timeout|cancelled|dns|tls_certificate|tls_handshake|network_unreachable|host_unreachable|connection_refused|connection_reset|connection_closed|transport|trace_body|trace_ip|warp_not_confirmed|http_[0-9]{3}|unknown)"))
        }.orEmpty()
        eventExport.put(obj("at" to item.optLong("at",0L),"event" to code,
            "kind" to kind,"attempt" to item.optInt("index",0).coerceIn(0,32),
            "total" to item.optInt("total",0).coerceIn(0,32),
            "latency_ms" to item.optLong("ms",-1L).coerceIn(-1L,60000L),"error" to error))
    }
    return obj(
        "version" to "0.2.1.1",
        "state" to state,
        "mode" to s.optString("mode","Авто"),
        "warp_profile_present" to (selected!=null),
        "warp_registration_saved" to s.has("registeredConf"),
        "warp_keys_present" to s.has("keys"),
        "awg_profile_present" to s.has("awgQuick"),
        "awg_doh_provider" to s.optString("awgDohProvider","off").takeIf{
            it=="off" || it=="custom" || AwgDnsPolicy.providers.any{p->p.id==it}
        }.orEmpty(),
        "nested_probe" to s.optJSONObject("nestedProbeResult")?.let {result->obj(
            "status" to AwgNestedResult.safe(result.optString("code")),
            "outer_country" to AwgRegionPolicy.country(result.optString("outerCountry")),
            "inner_country" to AwgRegionPolicy.country(result.optString("innerCountry")),
            "outer_speedtest_country" to AwgRegionPolicy.country(result.optString("outerMetaCountry")),
            "inner_speedtest_country" to AwgRegionPolicy.country(result.optString("innerMetaCountry")),
            "inner_speedtest_node" to AwgNodePolicy.code(result.optString("innerMetaColo"))
        )}.let {it ?: JSONObject()},
        "awg_last_probe" to s.optString("awgProbeStatus").takeIf { it.matches(Regex("awg_(?:invalid_file|invalid_config|tun_create_failed|ipc_config_failed|endpoint_dns_failed|device_start_failed|no_handshake|https_timeout|tcp_timeout|tls_timeout|http_timeout|tunnel_failed|not_confirmed|https_failed|verified:[0-9]{1,5})")) }.orEmpty(),
        "reserved_present" to (reserved!=null),
        "reserved_length_valid" to (reserved?.length()==3),
        "vless_nodes_count" to nodes(s).size,
        "last_checks" to checks,
        "recent_events" to eventExport,
        "limitations" to "HTTPS probes do not directly measure WireGuard handshake or UDP packet reception"
    )
}
