package dev.autowarp

/** Stable IDs stored independently from the profile and its credentials. */
internal enum class AwgConnectMode(val id:String,val label:String) {
    AUTO("auto","Авто"), QUIC("quic","QUIC"), I1("i1","Встроенная I1"),
    DNS("dns","DNS"), STUN("stun","STUN"), PROFILE("profile","Из профиля");

    companion object {
        const val AUTO_TIMEOUT_MS=100_000L
        fun selected(id:String)=entries.firstOrNull{it.id==id} ?: AUTO
        fun plan(mode:AwgConnectMode,imported:Boolean,lastSuccess:String):List<AwgConnectMode> {
            if(mode!=AUTO)return listOf(mode)
            val baseline=if(imported)listOf(PROFILE,I1,QUIC,DNS,STUN)
                else listOf(I1,QUIC,DNS,STUN,PROFILE)
            val cached=entries.firstOrNull{it.id==lastSuccess && it!=AUTO}
            return if(cached==null)baseline else listOf(cached)+baseline.filter{it!=cached}
        }
    }
}
