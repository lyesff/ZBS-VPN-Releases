package dev.autowarp

/** Startup may publish resources after Stop. Such resources must be closed immediately. */
internal class AwgResourceOwner<T:Any,E:Any>(
    private val closeTun:(T)->Unit,
    private val closeEngine:(E)->Unit
){
    private val lock=Any()
    private var closed=false
    private var tun:T?=null
    private var engine:E?=null
    fun engine():E?=synchronized(lock){engine}
    fun installTun(value:T):Boolean {
        val accepted=synchronized(lock){if(closed)false else {check(tun==null);tun=value;true}}
        if(!accepted)closeTun(value)
        return accepted
    }
    fun installEngine(value:E):Boolean {
        val accepted=synchronized(lock){if(closed)false else {check(engine==null);engine=value;true}}
        if(!accepted)closeEngine(value)
        return accepted
    }
    fun close(){
        val pair=synchronized(lock){
            if(closed)return
            closed=true
            (tun to engine).also {tun=null;engine=null}
        }
        try{pair.second?.let(closeEngine)}finally{pair.first?.let(closeTun)}
    }
}
