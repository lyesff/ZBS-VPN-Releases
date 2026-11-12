package dev.autowarp

import android.app.Activity
import android.content.*
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow

internal object VpnIpc {
    const val QUERY="dev.autowarp.QUERY"
    const val UPDATE="dev.autowarp.UPDATE"
    const val CONTROL="dev.autowarp.CONTROL"
    const val PERMISSION="dev.autowarp.permission.INTERNAL"
    fun intent(c:Context,action:String)=Intent(action).setPackage(c.packageName).addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
    fun encode(v:Live)=Bundle().apply {
        putString("phase",v.phase.name);putString("reason",v.reason.name)
        putString("route",v.route);putString("kind",v.kind);putString("ip",v.ip);putString("country",v.country)
        putLong("ms",v.ms);putLong("start",v.start);putLong("up",v.up);putLong("down",v.down)
        putLong("stamp",SystemClock.elapsedRealtimeNanos())
    }
    fun decode(b:Bundle)=Live(Phase.valueOf(b.getString("phase")!!),Reason.valueOf(b.getString("reason")!!),
        b.getString("route").orEmpty(),b.getString("kind").orEmpty(),b.getString("ip").orEmpty(),b.getLong("ms"),b.getLong("start"),b.getLong("up"),b.getLong("down"),b.getString("country").orEmpty())
    fun register(c:Context,r:BroadcastReceiver,f:IntentFilter){
        ContextCompat.registerReceiver(c,r,f,PERMISSION,null,ContextCompat.RECEIVER_NOT_EXPORTED)
    }
}

// A read-only query never starts or binds the service. On resume and after a
// remote process death the final receiver gets either the service snapshot or no reply.
internal class VpnObserver(private val c:Context,private val onSnapshot:(Live)->Unit){
    val synced=MutableStateFlow(false)
    private val main=Handler(Looper.getMainLooper())
    private var generation=0
    private var active=false
    private var stamp=0L
    private var current=Live()
    private fun accept(b:Bundle){
        val t=b.getLong("stamp");if(t<stamp)return
        stamp=t;current=VpnIpc.decode(b);onSnapshot(current);synced.value=true
    }
    private val push=object:BroadcastReceiver(){override fun onReceive(c:Context,i:Intent){i.extras?.let(::accept)}}
    private val query=object:Runnable{
        override fun run(){
            if(!active)return
            val ticket=generation;val sent=SystemClock.elapsedRealtimeNanos()
            c.sendOrderedBroadcast(VpnIpc.intent(c,VpnIpc.QUERY),VpnIpc.PERMISSION,object:BroadcastReceiver(){
                override fun onReceive(ctx:Context,i:Intent){
                    if(!active || ticket!=generation)return
                    val reply=getResultExtras(false)
                    if(resultCode==Activity.RESULT_OK && reply!=null)accept(reply)
                    else if(stamp<=sent){
                        val gone=current.running || current.phase==Phase.DISCONNECTING
                        current=if(gone)Live(Phase.ERROR,Reason.LOST) else if(current.phase==Phase.ERROR)current else Live()
                        stamp=sent;onSnapshot(current);synced.value=true
                    }
                    main.postDelayed(queryTask(),2500)
                }
            },main,Activity.RESULT_CANCELED,null,null)
        }
    }
    private fun queryTask():Runnable=query
    fun start(){if(active)return;active=true;generation++;VpnIpc.register(c,push,IntentFilter(VpnIpc.UPDATE));query.run()}
    fun stop(){if(!active)return;active=false;generation++;main.removeCallbacks(query);c.unregisterReceiver(push);synced.value=false}
}
