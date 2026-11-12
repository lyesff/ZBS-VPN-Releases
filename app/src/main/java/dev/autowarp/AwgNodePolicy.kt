package dev.autowarp

import java.util.Locale

/** A bounded allowlist; unknown nodes fail closed when this option is enabled. */
internal object AwgNodePolicy {
    private val european=setOf("AMS","ARN","ATH","BUD","FRA","HEL","KBP","KIV",
        "PRG","RIX","SOF","TLL","VIE","VNO","WAW","ZRH","CDG","LHR","DUB",
        "CPH","OSL","MAD","BCN","LIS","MXP","FCO","GVA","MRS","MAN","ZAG","BEG")
    fun code(raw:String):String=raw.trim().uppercase(Locale.ROOT)
        .takeIf {it.matches(Regex("[A-Z]{3}"))}.orEmpty()
    fun accepted(raw:String)=code(raw) in european
    fun enforce(raw:String,enabled:Boolean){
        if(enabled && !accepted(raw))throw AwgVerifyFailure("awg_vpn_node_rejected",AwgVerifyStage.TRACE)
    }
}
