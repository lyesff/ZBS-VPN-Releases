package dev.autowarp

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.*
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.net.*
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.OsConstants
import io.nekohasekai.libbox.*
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.net.NetworkInterface as NetIf
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.TimeUnit

private class Strings(private val values:List<String>):StringIterator{
    private var i=0
    override fun hasNext()=i<values.size
    override fun next()=values[i++]
    override fun len()=values.size-i
}
class Tunnel:VpnService(),PlatformInterface,CommandServerHandler{
    companion object {
        // Only the UI process reads this mirror. The service owns VpnSession.
        val live=MutableStateFlow(Live())
        fun cmd(c:Context,a:String){
            if(a=="START" || a=="SCAN")c.startForegroundService(Intent(c,Tunnel::class.java).setAction(a))
            else c.sendBroadcast(VpnIpc.intent(c,VpnIpc.CONTROL).putExtra("command",a),VpnIpc.PERMISSION)
        }
    }
    private val main=Handler(Looper.getMainLooper())
    private var previous=Phase.DISCONNECTED
    private val session=VpnSession { value->
        if(previous!=value.phase)Log.i("AutoWARP.Lifecycle","$previous -> ${value.phase} (${value.reason})")
        previous=value.phase
        sendBroadcast(VpnIpc.intent(this,VpnIpc.UPDATE).putExtras(VpnIpc.encode(value)),VpnIpc.PERMISSION)
    }
    private val control=object:BroadcastReceiver(){
        override fun onReceive(c:Context,i:Intent){
            if(i.action==VpnIpc.QUERY){setResult(android.app.Activity.RESULT_OK,null,VpnIpc.encode(session.value));return}
            when(i.getStringExtra("command")){
                "STOP"->stop(Reason.IDLE)
                "RELOAD"->submit { if(running)rebuild(true) }
                "CHECK"->submit { if(running && selected!=null && time()-lastSweep>=60000)monitor(true) }
            }
        }
    }
    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }
    private val store by lazy { Store.get(this) }
    private fun journal(code:String,kind:String="",index:Int=0,total:Int=0,ms:Long=-1L,error:String="") {
        runCatching { store.recordEvent(code,kind,index,total,ms,error) }
    }
    private val worker=ScheduledThreadPoolExecutor(1).apply { removeOnCancelPolicy=true }
    private var core:CommandServer?=null
    private var fd:ParcelFileDescriptor?=null
    @Volatile private var net:Network?=null
    @Volatile private var listener:InterfaceUpdateListener?=null
    private val closing=AtomicBoolean()
    private val stopping get()=closing.get()
    private val pendingProbe=AtomicReference<ProbeToken?>()
    private val finished=AtomicBoolean()
    private var registered=false
    private var watching=false
    @Volatile private var destroyed=false
    private var selectionKey=""
    private var startedAt=0L
    private fun submit(task:()->Unit){
        if(!stopping)runCatching { worker.execute { if(!stopping)try{task()}catch(_:Exception){stop(Reason.CORE)} } }
    }
    private var running=false
    private var scanning=false
    private var routes=emptyList<Route>()
    private var selected:Route?=null
    private var cursor=0
    private var nextCheck=0L
    private var lastSweep=-60000L
    private var switched=-60000L
    private var failed=0
    private var totals=longArrayOf(0,0,0)
    private fun time()=SystemClock.elapsedRealtime()
    private fun physical()=cm.allNetworks.filter { val cap=cm.getNetworkCapabilities(it)
        cap?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)==true && cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
        .sortedByDescending { val c=cm.getNetworkCapabilities(it);(if(it==cm.activeNetwork)4 else 0)+(if(c?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)==true)2 else 0)+(if(c?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true)1 else 0) }
    private fun networkEvent()=submit { if(running)rebuild(false) }
    private val callback=object:ConnectivityManager.NetworkCallback(){
        override fun onAvailable(network:Network)=networkEvent()
        override fun onLost(network:Network)=networkEvent()
        override fun onLinkPropertiesChanged(network:Network,p:LinkProperties)=networkEvent()
    }
    override fun onCreate(){
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("vpn","VPN",NotificationManager.IMPORTANCE_LOW))
        val open=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
        startForeground(11,android.app.Notification.Builder(this,"vpn").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("ZBS VPN").setContentText("Служба VPN активна").setContentIntent(open).setOngoing(true).build())
        VpnIpc.register(this,control,IntentFilter(VpnIpc.QUERY).apply { addAction(VpnIpc.CONTROL) })
        registered=true
    }
    override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int{
        if(stopping)return START_NOT_STICKY
        if(intent?.action=="STOP"){stop(Reason.IDLE);return START_NOT_STICKY}
        if(intent?.action=="SCAN"){
            if(running || scanning || session.value.running) return START_NOT_STICKY
            scanning=true
            submit { scanVless() }
            return START_NOT_STICKY
        }
        if(!session.value.running){
            journal("start")
            session.update(Live(Phase.CONNECTING,Reason.START))
            submit {
                if(!hasProfile(store.read())){stop(Reason.NO_PROFILE);return@submit}
                if(prepare(this)!=null){stop(Reason.DENIED);return@submit}
                running=true
                cm.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback)
                watching=true
                worker.scheduleWithFixedDelay({if(!stopping)try{tick()}catch(_:Exception){stop(Reason.CORE)}},1,2,TimeUnit.SECONDS)
                rebuild(true)
            }
        }
        return START_STICKY
    }
    @Synchronized private fun install(p:ParcelFileDescriptor?):Int{
        val fresh=requireNotNull(p)
        if(stopping){fresh.close();error("stopping")}
        val old=fd;fd=fresh;old?.close();return fresh.fd
    }
    @Synchronized private fun closeTun(){val old=fd;fd=null;old?.close()}
    @Synchronized private fun hasTun()=fd?.fileDescriptor?.valid()==true
    private fun rebuild(force:Boolean){
        if(stopping)return
        val n=physical().firstOrNull();if(n==net&&!force){notifyInterface();return}
        net=n;routes=emptyList();selected=null;startedAt=0
        journal(when{
            n==null->"network_missing"
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true->"network_wifi"
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true->"network_cellular"
            else->"network_other"
        })
        try{
            val s=store.read()
            if(!hasProfile(s)){stop(Reason.NO_PROFILE);return}
            session.update(Live(Phase.CONNECTING,if(n==null)Reason.NETWORK else Reason.START))
            setUnderlyingNetworks(n?.let { arrayOf(it) } ?: emptyArray());notifyInterface()
            if(n==null){main.removeCallbacks(startDeadline);return}
            main.removeCallbacks(startDeadline)
            main.postDelayed(startDeadline,60000)
            val plan=plan(s,n::getAllByName)
            if(stopping)return
            journal("core_start")
            Libbox.setup(SetupOptions().apply { basePath=noBackupFilesDir.path;workingPath=filesDir.path;tempPath=cacheDir.path;fixAndroidStack=true })
            Libbox.checkConfig(plan.json)
            val engine=core ?: Libbox.newCommandServer(this,this).also { core=it }
            if(stopping)return
            engine.startOrReloadService(plan.json,OverrideOptions())
            if(stopping)return
            check(hasTun())
            journal("core_ready")
            selectionKey=routeSelectionKey(s)
            routes=plan.routes;val r=routes.find { it.tag==s.optString("lastRoute") } ?: routes.first()
            if(routeSelectionKey(store.read())!=selectionKey){submit { rebuild(true) };return}
            selected=r;engine.chooseRoute(r.tag);failed=0;cursor=0;totals=longArrayOf(0,0,0)
            session.update(Live(Phase.CONNECTING,Reason.VERIFY));monitor(s.optBoolean("switch",true),true)
        }catch(_:Exception){journal("core_failed");stop(Reason.CORE)}
    }
    private fun scanVless(){
        var done=0
        var total=0
        var completed=false
        try {
            // A preflight scan never creates a TUN or changes the device's VPN.
            // Keep the existing VPN lifecycle separate from this standalone core.
            val underlying=physical().firstOrNull() ?: error("no_network")
            // Mirror the working VPN initialization path: interface binding and
            // auto-detection must be ready before the standalone core starts.
            net=underlying
            notifyInterface()
            val snapshot=store.read()
            val plan=scanPlan(snapshot,underlying::getAllByName)
            total=plan.routes.size
            store.edit { it.put("scan",obj("running" to true,"done" to 0,"total" to total)) }
            Libbox.setup(SetupOptions().apply {
                basePath=noBackupFilesDir.path;workingPath=filesDir.path;tempPath=cacheDir.path;fixAndroidStack=true
            })
            Libbox.checkConfig(plan.json)
            val engine=Libbox.newCommandServer(this,this)
            core=engine
            engine.startOrReloadService(plan.json,OverrideOptions())
            for(route in plan.routes){
                if(stopping)break
                probe(route)
                done++
                store.edit { it.put("scan",obj("running" to true,"done" to done,"total" to total)) }
            }
            completed=!stopping
        }catch(e:Exception){
            Log.w("AutoWARP.Scan","Preflight failed (details withheld)")
        }finally{
            runCatching {
                store.edit { it.put("scan",obj("running" to false,"done" to done,"total" to total,
                    "status" to if(completed)"finished" else if(stopping)"cancelled" else "failed")) }
            }
            scanning=false
            stop(Reason.IDLE)
        }
    }

    private fun probe(r:Route):JSONObject?{
        if(stopping)return null
        val index=routes.indexOfFirst { it.tag==r.tag }.let { if(it<0)0 else it+1 }
        journal("probe_start",if(r.warp)"WARP" else "VLESS",index,routes.size)
        val token=Libbox.newProbeToken()
        pendingProbe.set(token)
        var errorCode="probe_unknown"
        val v=try{
            if(stopping)return null
            try {
                JSONObject(core!!.probeRoute(r.tag,r.warp,token))
            } catch(e:Exception) {
                // Only allow known, non-sensitive codes into diagnostics.
                val known=Regex("probe_(?:timeout|cancelled|dns|tls_certificate|tls_handshake|network_unreachable|host_unreachable|connection_refused|connection_reset|connection_closed|transport|trace_body|trace_ip|warp_not_confirmed|http_[0-9]{3})")
                errorCode=known.find(e.message.orEmpty())?.value ?: "probe_unknown"
                null
            }
        }finally{pendingProbe.compareAndSet(token,null);token.cancel()}
        if(stopping)return null
        journal(if(v!=null)"probe_ok" else "probe_fail",if(r.warp)"WARP" else "VLESS",index,routes.size,v?.optLong("ms",-1L) ?: -1L,errorCode)
        store.edit { s->val h=s.map("health");val old=h.map(r.tag);val history=old.optJSONArray("history") ?: JSONArray()
            if(history.length()>=12)history.remove(0);history.put(v?.getLong("ms") ?: -1)
            h.put(r.tag,obj("ms" to (v?.getLong("ms") ?: -1L),"at" to System.currentTimeMillis(),"history" to history,"error" to if(v==null)errorCode else ""))
            if(h.length()>256)h.keys().asSequence().minByOrNull { h.getJSONObject(it).optLong("at") }?.let(h::remove)
            s.put("health",h) }
        return v
    }
    private fun monitor(sweep:Boolean,initial:Boolean=false){
        if(stopping)return
        val old=selected ?: return
        if(routeSelectionKey(store.read())!=selectionKey){submit { rebuild(true) };return}
        val result=linkedMapOf<Route,JSONObject>()
        probe(old)?.let { result[old]=it };failed=if(old in result)0 else failed+1
        val s=store.read();val auto=s.optBoolean("switch",true)
        if(sweep || auto && failed>=3 && time()-lastSweep>=15000){
            lastSweep=time()
            val candidates=warpProbeOrder(routes,old,store.read().map("health"),initial,cursor)
            cursor+=minOf(6,routes.size)
            for(r in candidates){if(stopping)return;if(r!=old)probe(r)?.let {result[r]=it}}
        }
        val h=store.read().map("health")
        fun score(r:Route):Double=warpHealthScore(h.optJSONObject(r.tag),s.optBoolean("stable",true))
        val best=result.keys.minByOrNull(::score)
        val route=if(auto && best!=null && (initial||time()-switched>=60000) && (old !in result && (initial||failed>=3) || old in result && score(best)+100<score(old)))best else old
        if(stopping)return
        if(routeSelectionKey(store.read())!=selectionKey){submit { rebuild(true) };return}
        if(route!=old){core!!.chooseRoute(route.tag);selected=route;switched=time();failed=0;store.edit { it.put("lastRoute",route.tag) };journal("route_switch",if(route.warp)"WARP" else "VLESS")}
        val value=result[route]
        if(value==null){
            if(initial){journal("route_failed");stop(Reason.NO_EXIT);return}
            journal("recover")
            session.update(Live(Phase.CONNECTING,Reason.RECOVER))
        }else{
            check(hasTun() && core!=null)
            main.removeCallbacks(startDeadline)
            if(startedAt==0L)startedAt=time()
            journal("route_online",if(route.warp)"WARP" else "VLESS",ms=value.getLong("ms"))
            session.update(Live(Phase.CONNECTED,Reason.ONLINE,route.label,route.kind,value.getString("ip"),value.getLong("ms"),startedAt))
        }
        nextCheck=time()+s.optInt("seconds",30).coerceIn(15,300)*1000
    }
    private fun tick(){
        if(!running||stopping||net==null)return
        if(selected==null)return
        if(time()>=nextCheck)monitor(store.read().optBoolean("switch",true)&&time()-lastSweep>=60000)
        if(stopping||session.value.phase!=Phase.CONNECTED)return
        val a=JSONArray(core!!.transferTotals());val now=time();val elapsed=(now-totals[2]).coerceAtLeast(1)
        if(totals[2]>0)session.update(session.value.copy(up=(a.getLong(0)-totals[0]).coerceAtLeast(0)*1000/elapsed,down=(a.getLong(1)-totals[1]).coerceAtLeast(0)*1000/elapsed))
        totals=longArrayOf(a.getLong(0),a.getLong(1),now)
    }
    // The deadline runs on Android's main looper, independently of native DNS,
    // probes, startup and teardown. This process hosts the VPN service only.
    private val startDeadline=Runnable { stop(Reason.START_TIMEOUT) }
    private val deadline=Runnable { finishStop(Reason.TIMEOUT,true) }
    private fun stop(reason:Reason){
        if(!closing.compareAndSet(false,true))return
        journal("stopped")
        main.removeCallbacks(startDeadline)
        main.postDelayed(deadline,8000)
        session.beginStop(if(reason==Reason.IDLE)Reason.STOP else reason)
        // No JNI or FD close on the Android main looper: the watchdog must
        // remain runnable even if a platform or native call stops responding.
        Thread({
            pendingProbe.getAndSet(null)?.cancel()
            runCatching { closeTun() }
        },"vpn-cancel").apply { isDaemon=true;start() }
        worker.queue.clear()
        worker.execute {
            running=false
            if(watching)runCatching { cm.unregisterNetworkCallback(callback) }
            listener=null
            val engine=core;core=null
            var broken=false
            if(engine!=null){
                try{engine.closeService()}catch(_:Exception){broken=true}
                try{engine.close()}catch(_:Exception){broken=true}
            }
            runCatching { closeTun() }
            routes=emptyList();selected=null
            main.post { finishStop(reason,broken) }
        }
        worker.shutdown()
    }
    private fun finishStop(reason:Reason,terminate:Boolean){
        if(!finished.compareAndSet(false,true))return
        main.removeCallbacks(deadline)
        if(registered){unregisterReceiver(control);registered=false}
        stopForeground(STOP_FOREGROUND_REMOVE)
        if(!destroyed)stopSelf()
        session.finish(reason)
        if(terminate){
            Log.w("AutoWARP.Lifecycle","Terminating private VPN process after native cleanup: ${reason.name}")
            if(android.app.Application.getProcessName()!="$packageName:vpn")return
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }
    override fun onRevoke(){stop(Reason.REVOKED)}
    override fun onDestroy(){destroyed=true;stop(Reason.IDLE);super.onDestroy()}
    override fun openTun(o:TunOptions):Int{
        val b=Builder().setSession("ZBS VPN").setMtu(o.mtu).setMetered(false)
        val a=o.inet4Address;while(a.hasNext())a.next().let {b.addAddress(it.address(),it.prefix())}
        val v=o.inet6Address;val v6=v.hasNext();while(v.hasNext())v.next().let {b.addAddress(it.address(),it.prefix())}
        b.addRoute("0.0.0.0",0);if(v6)b.addRoute("::",0);b.addDnsServer("172.19.0.2");b.setUnderlyingNetworks(net?.let { arrayOf(it) });return install(b.establish())
    }
    override fun autoDetectInterfaceControl(fd:Int){check(protect(fd))}
    override fun usePlatformAutoDetectInterfaceControl()=true
    override fun useProcFS()=false
    override fun underNetworkExtension()=false
    override fun includeAllNetworks()=false
    override fun localDNSTransport():LocalDNSTransport?=null
    override fun readWIFIState():WIFIState?=null
    override fun clearDNSCache()=Unit
    override fun sendNotification(n:io.nekohasekai.libbox.Notification)=Unit
    override fun systemCertificates():StringIterator=Strings(emptyList())
    override fun findConnectionOwner(proto:Int,src:String,sp:Int,dst:String,dp:Int)=ConnectionOwner().apply {
        userId=cm.getConnectionOwnerUid(proto,java.net.InetSocketAddress(src,sp),java.net.InetSocketAddress(dst,dp)) }
    override fun getInterfaces():NetworkInterfaceIterator{
        val items=physical().mapNotNull { n->val p=cm.getLinkProperties(n) ?: return@mapNotNull null
            val ni=NetIf.getByName(p.interfaceName ?: return@mapNotNull null) ?: return@mapNotNull null
            io.nekohasekai.libbox.NetworkInterface().apply { name=ni.name;index=ni.index;mtu=runCatching {ni.mtu}.getOrDefault(1500)
                flags=OsConstants.IFF_RUNNING or OsConstants.IFF_UP;addresses=Strings(p.linkAddresses.map {it.toString()});dnsServer=Strings(p.dnsServers.mapNotNull {it.hostAddress})
                val c=cm.getNetworkCapabilities(n);type=when{c?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true->Libbox.InterfaceTypeWIFI;c?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true->Libbox.InterfaceTypeCellular;else->Libbox.InterfaceTypeOther} }
        }.iterator()
        return object:NetworkInterfaceIterator{override fun hasNext()=items.hasNext();override fun next()=items.next()}
    }
    private fun notifyInterface(){val n=net;val name=n?.let(cm::getLinkProperties)?.interfaceName;listener?.updateDefaultInterface(name.orEmpty(),name?.let {NetIf.getByName(it)?.index} ?: -1,false,false)}
    override fun startDefaultInterfaceMonitor(l:InterfaceUpdateListener){listener=l;notifyInterface()}
    override fun closeDefaultInterfaceMonitor(l:InterfaceUpdateListener){listener=null}
    override fun getSystemProxyStatus()=SystemProxyStatus()
    override fun setSystemProxyEnabled(enabled:Boolean){check(!enabled)}
    override fun serviceReload(){submit { if(running)rebuild(true) }}
    override fun serviceStop(){stop(Reason.IDLE)}
    override fun writeDebugMessage(message:String)=Unit
}
