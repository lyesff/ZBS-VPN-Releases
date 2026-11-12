package dev.autowarp

enum class Phase { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

enum class Reason(val text:String) {
    IDLE("Отключено"), START("Подключение…"), VERIFY("Проверка защищённого маршрута…"),
    NETWORK("Ожидание сети"), ONLINE("Подключено"), RECOVER("Восстановление соединения…"),
    STOP("Отключение…"), REVOKED("Разрешение VPN отозвано"),
    NO_PROFILE("Нет доступного профиля"), CORE("Не удалось запустить ядро VPN"),
    START_TIMEOUT("Истекло время запуска VPN"), NO_EXIT("Маршрут не прошёл проверку HTTPS"), LOST("VPN-служба завершилась"),
    REGION_RU("Геолокация РФ отклонена"), REGION_UNKNOWN("Не удалось определить страну IP"),
    TIMEOUT("VPN-служба принудительно остановлена"), DENIED("Android не разрешил запуск VPN")
}
data class Live(val phase:Phase=Phase.DISCONNECTED,val reason:Reason=Reason.IDLE,
                val route:String="",val kind:String="",val ip:String="",val ms:Long=-1,
                val start:Long=0,val up:Long=0,val down:Long=0,val country:String=""){
    val state get()=reason.text
    val running get()=phase==Phase.CONNECTING || phase==Phase.CONNECTED
}

// All publishers (worker, revoke callback and main thread) pass this same gate.
// A late successful probe cannot reverse a pending stop.
class VpnSession(private val publish:(Live)->Unit){
    @Volatile var value=Live()
        private set
    @Synchronized fun update(next:Live):Boolean{
        val allowed=when(value.phase){
            Phase.DISCONNECTED,Phase.ERROR->next.phase in setOf(Phase.CONNECTING,Phase.DISCONNECTING)
            Phase.CONNECTING,Phase.CONNECTED->next.phase in setOf(Phase.CONNECTING,Phase.CONNECTED,Phase.DISCONNECTING)
            Phase.DISCONNECTING->next.phase in setOf(Phase.DISCONNECTED,Phase.ERROR)
        }
        if(!allowed)return false
        if(next.phase==Phase.CONNECTED && (next.ip.isBlank()||next.ms<0||next.start<=0))return false
        value=next;publish(next);return true
    }
    fun beginStop(reason:Reason)=update(Live(Phase.DISCONNECTING,reason))
    fun finish(reason:Reason)=update(if(reason in setOf(Reason.IDLE,Reason.REVOKED))Live(reason=reason) else Live(Phase.ERROR,reason))
}
