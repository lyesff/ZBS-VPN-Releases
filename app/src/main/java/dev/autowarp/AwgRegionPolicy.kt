package dev.autowarp

import java.util.Locale

internal data class AwgVerifiedTrace(val ip:String,val country:String,val colo:String="")
internal data class AwgVerifiedConnection(val ip:String,val latency:Long,val country:String,val colo:String="")

/** GeoIP classification of the HTTPS request, never a physical-server claim. */
internal object AwgRegionPolicy {
    private val known=Locale.getISOCountries().toSet()+setOf("XK")
    fun country(raw:String):String=raw.trim().uppercase(Locale.ROOT).takeIf {it in known}.orEmpty()
    fun enforce(code:String,excludeRussia:Boolean){
        if(!excludeRussia)return
        val normalized=country(code)
        if(normalized=="RU")throw AwgVerifyFailure("awg_vpn_region_ru",AwgVerifyStage.TRACE)
        if(normalized.isBlank())throw AwgVerifyFailure("awg_vpn_region_unknown",AwgVerifyStage.TRACE)
    }
    fun rejection(code:String)=code=="awg_vpn_region_ru" || code=="awg_vpn_region_unknown" || code=="awg_vpn_node_rejected"
    fun reason(code:String)=when(code){
        "awg_vpn_region_ru"->Reason.REGION_RU
        "awg_vpn_region_unknown"->Reason.REGION_UNKNOWN
        else->Reason.NO_EXIT
    }
    fun label(code:String):String {
        val normalized=country(code)
        return if(normalized.isBlank())"Не определена" else
            Locale("",normalized).getDisplayCountry(Locale.forLanguageTag("ru"))+" ($normalized)"
    }
}
