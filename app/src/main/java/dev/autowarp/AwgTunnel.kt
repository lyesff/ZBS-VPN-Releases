package dev.autowarp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.os.PowerManager
import android.os.Build
import androidx.core.content.ContextCompat
import org.json.JSONObject
import android.util.Log
import io.nekohasekai.awglab.Awglab
import io.nekohasekai.awglab.AndroidVPN
import io.nekohasekai.awglab.AndroidVPNPreparation
import io.nekohasekai.awglab.NestedProbe
import io.nekohasekai.awglab.SocketProtector
import io.nekohasekai.awglab.VPNNetworkDialer
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.net.InetAddress
import okhttp3.Request
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Isolated, opt-in Android VpnService backed by real AWG v3 userspace.
 * Unlike the old sing-box path, this service never starts a second engine.
 * It reports CONNECTED only after HTTPS over Android's VPN Network
 * confirms warp=on/plus, not after the AWG handshake alone.
 */
class AwgTunnel:VpnService(),SocketProtector{
    companion object{
        fun start(c:Context,appOnly:Boolean=false,routerI1:Boolean=false,nestedTest:Boolean=false,maskVariant:String=""){
            c.startForegroundService(Intent(c,AwgTunnel::class.java)
                .setAction("START_AWG").putExtra("AWG_APP_ONLY",appOnly)
                .putExtra("AWG_ROUTER_I1",routerI1).putExtra("AWG_NESTED_TEST",nestedTest)
                .putExtra("AWG_MASK_VARIANT",maskVariant))
        }
    }
    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }
    private val store by lazy { Store.get(this) }
    private val main=Handler(Looper.getMainLooper())
    private val worker=Executors.newSingleThreadScheduledExecutor()
    private val closing=AtomicBoolean(false)
    private val preparing=AtomicReference<AndroidVPNPreparation?>(null)
    private val nestedProbe=AtomicReference<NestedProbe?>(null)
    private val dohClient=AtomicReference<AwgDohClient?>(null)
    private val dohFailureLogged=AtomicBoolean(false)
    private var registered=false
    private var goControlStarted=false
    @Volatile private var lastAppOnly=false
    @Volatile private var lastRouterI1=false
    @Volatile private var lastMaskVariant=""
    private var networkCallbackRegistered=false
    private var backgroundReceiverRegistered=false
    @Volatile private var lastNotificationState:Pair<Phase,Reason>?=null
    @Volatile private var lastSuspended:Boolean?=null
    private var preferredNetworkHandle=0L
    private val wifiProbeRunning=AtomicBoolean(false)
    @Volatile private var lastWifiProbeAt=0L
    private val wifiProbeCooldownMs=12_000L
    private val networkChangeCheck=Runnable {
        if(closing.get())return@Runnable
        val phase=session.value.phase
        if(phase!=Phase.CONNECTED && phase!=Phase.CONNECTING)return@Runnable
        val old=underlyingPhysical ?: return@Runnable
        val selected=physical()
        if(selected==null){
            if(phase==Phase.CONNECTED){
                journal("awg_vpn_network_wait")
                session.update(Live(Phase.CONNECTING,Reason.NETWORK))
            }
        }else if(selected!=old){
            journal("awg_vpn_network_changed")
            session.update(Live(Phase.CONNECTING,Reason.RECOVER))
            stop(Reason.RECOVER,restart=true,preferred=selected)
        }else if(phase==Phase.CONNECTED &&
            cm.getNetworkCapabilities(old)?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true){
            // Android may keep Wi-Fi unvalidated while VPN is active.
            val wifi=cm.allNetworks.firstOrNull { candidate ->
                candidate!=old && cm.getNetworkCapabilities(candidate)?.let { caps ->
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                }==true
            }
            val now=SystemClock.elapsedRealtime()
            if(wifi!=null && now-lastWifiProbeAt>=wifiProbeCooldownMs &&
                wifiProbeRunning.compareAndSet(false,true)){
                lastWifiProbeAt=now
                runCatching{worker.execute{
                    try{
                        if(probePhysicalWifi(wifi) && !closing.get()){
                            main.post {
                                if(!closing.get() && session.value.phase==Phase.CONNECTED &&
                                    underlyingPhysical==old && cm.allNetworks.contains(wifi)){
                                    journal("awg_vpn_wifi_preferred")
                                    session.update(Live(Phase.CONNECTING,Reason.RECOVER))
                                    stop(Reason.RECOVER,restart=true,preferred=wifi)
                                }
                            }
                        }else {
                            journal("awg_vpn_wifi_probe_failed")
                            // Wi-Fi capability events are not guaranteed to fire again.
                            // Retest infrequently while mobile remains the active path.
                            scheduleWifiRetry()
                        }
                    }finally{wifiProbeRunning.set(false)}
                }}.onFailure{wifiProbeRunning.set(false)}
            }
        }
    }
    // Keep the self-referential callback outside its own initializer:
    // Kotlin cannot infer the recursive property type inside that lambda.
    private fun scheduleWifiRetry(){
        main.postDelayed(networkChangeCheck,30_000L)
    }
    private val physicalCallback=object:ConnectivityManager.NetworkCallback(){
        private fun changed(){
            if(closing.get())return
            main.removeCallbacks(networkChangeCheck)
            main.postDelayed(networkChangeCheck,900)
        }
        override fun onAvailable(network:Network)=changed()
        override fun onLost(network:Network)=changed()
        override fun onCapabilitiesChanged(network:Network,caps:NetworkCapabilities){
            if(network==underlyingPhysical && !closing.get()){
                val suspended=!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
                if(lastSuspended!=suspended){
                    lastSuspended=suspended
                    journal(if(suspended)"awg_vpn_network_suspended" else "awg_vpn_network_resumed")
                }
            }
            changed()
        }
        override fun onBlockedStatusChanged(network:Network,blocked:Boolean){
            if(network==underlyingPhysical && !closing.get()){
                journal(if(blocked)"awg_vpn_network_blocked" else "awg_vpn_network_unblocked")
                recordBackgroundState()
            }
        }
    }
    private val backgroundReceiver=object:BroadcastReceiver(){
        override fun onReceive(context:Context,intent:Intent){
            if(closing.get())return
            when(intent.action){
                Intent.ACTION_SCREEN_OFF->journal("awg_screen_off")
                Intent.ACTION_SCREEN_ON->journal("awg_screen_on")
                PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED->{
                    val power=getSystemService(PowerManager::class.java)
                    journal(if(power.isDeviceIdleMode)"awg_idle_enter" else "awg_idle_exit")
                }
            }
            recordBackgroundState()
        }
    }
    private val checking=AtomicBoolean(false)
    @Volatile private var underlyingPhysical:Network?=null
    private val resources=AwgResourceOwner<ParcelFileDescriptor,AndroidVPN>(
        closeTun={it.close()},closeEngine={it.stop()})
    private val session=VpnSession { state->
        sendBroadcast(VpnIpc.intent(this,VpnIpc.UPDATE).putExtras(VpnIpc.encode(state)),VpnIpc.PERMISSION)
        updateNotification(state)
    }
    private val control=object:BroadcastReceiver(){
        override fun onReceive(context:Context,intent:Intent){
            if(intent.action==VpnIpc.QUERY){
                setResult(android.app.Activity.RESULT_OK,null,VpnIpc.encode(session.value))
                return
            }
            when(intent.getStringExtra("command")){
                "STOP"->{journal("awg_vpn_user_stop");stop(Reason.IDLE)}
                "CHECK"->checkCurrentRoute()
                "REFRESH_NOTIFICATION"->{updateNotification(session.value,force=true);recordBackgroundState()}
            }
        }
    }
    // gomobile maps Go int to Java long; Android's VpnService accepts int.
    override fun protect(fd:Long):Boolean {
        if(fd !in 0..Int.MAX_VALUE.toLong() || closing.get())return false
        val network=underlyingPhysical ?: return false
        val ok=awgBindAndProtect(bind={
            // Duplicate owns only the Java-side handle. Never adopt/close Go's FD.
            // Both handles refer to the same kernel UDP socket.
            ParcelFileDescriptor.fromFd(fd.toInt()).use { copy ->
                network.bindSocket(copy.fileDescriptor)
            }
        },protect={super.protect(fd.toInt())})
        journal(if(ok)"awg_vpn_udp_bound" else "awg_vpn_udp_bind_failed")
        return ok
    }
    private fun notification(state:Live):Notification{
        val open=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this,"vpn")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("ZBS VPN")
            .setContentText(state.state)
            .setCategory(Notification.CATEGORY_SERVICE).setOnlyAlertOnce(true)
            .setContentIntent(open).setOngoing(true).build()
    }
    private fun updateNotification(state:Live,force:Boolean=false){
        val key=state.phase to state.reason
        if(!force && lastNotificationState==key)return
        lastNotificationState=key
        runCatching{getSystemService(NotificationManager::class.java).notify(11,notification(state))}
    }
    private fun recordBackgroundState(){
        runCatching{
            val power=getSystemService(PowerManager::class.java)
            val manager=getSystemService(NotificationManager::class.java)
            val notifications=manager.areNotificationsEnabled() &&
                manager.getNotificationChannel("vpn")?.importance!=NotificationManager.IMPORTANCE_NONE
            val exempt=power.isIgnoringBatteryOptimizations(packageName)
            val network=underlyingPhysical ?: physical()
            val caps=network?.let{cm.getNetworkCapabilities(it)}
            val type=when{
                network==null->"none"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true->"wifi"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true->"cellular"
                else->"other"
            }
            store.edit{it.put("awgBackgroundState",JSONObject()
                .put("at",System.currentTimeMillis()).put("elapsed_ms",SystemClock.elapsedRealtime())
                .put("sdk",Build.VERSION.SDK_INT).put("interactive",power.isInteractive)
                .put("idle",power.isDeviceIdleMode).put("power_save",power.isPowerSaveMode)
                .put("battery_exempt",exempt).put("notifications_allowed",notifications).put("network",type))}
            journal(if(exempt)"awg_battery_exempt" else "awg_battery_optimized")
            journal(if(notifications)"awg_notifications_enabled" else "awg_notifications_disabled")
        }
    }
    override fun onCreate(){
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("vpn","VPN",NotificationManager.IMPORTANCE_LOW).apply{
                setSound(null,null);enableVibration(false)
            })
        startForeground(11,notification(Live(Phase.CONNECTING,Reason.START)))
        VpnIpc.register(this,control,IntentFilter(VpnIpc.QUERY).apply {addAction(VpnIpc.CONTROL)})
        registered=true
        try{
            ContextCompat.registerReceiver(this,backgroundReceiver,IntentFilter().apply{
                addAction(Intent.ACTION_SCREEN_OFF);addAction(Intent.ACTION_SCREEN_ON)
                addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
            },ContextCompat.RECEIVER_NOT_EXPORTED)
            backgroundReceiverRegistered=true
            journal("awg_background_monitor_started")
        }catch(_:Exception){journal("awg_background_monitor_unavailable")}
        recordBackgroundState()
        try{
            val request=NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(request,physicalCallback)
            networkCallbackRegistered=true
        }catch(_:Exception){journal("awg_vpn_network_monitor_unavailable")}
    }
    override fun onStartCommand(i:Intent?,flags:Int,startId:Int):Int{
        if(i?.action!="START_AWG" || closing.get())return START_NOT_STICKY
        if(session.value.running)return START_STICKY
        session.update(Live(Phase.CONNECTING,Reason.START))
        val appOnly=i?.getBooleanExtra("AWG_APP_ONLY",false) ?: false
        val routerI1=i?.getBooleanExtra("AWG_ROUTER_I1",false) ?: false
        val nestedTest=i?.getBooleanExtra("AWG_NESTED_TEST",false) ?: false
        preferredNetworkHandle=i?.getLongExtra("AWG_PHYSICAL_NETWORK",0L) ?: 0L
        lastAppOnly=appOnly
        lastRouterI1=routerI1
        val maskVariant=i?.getStringExtra("AWG_MASK_VARIANT").orEmpty()
        lastMaskVariant=maskVariant
        worker.execute{
            try{if(nestedTest)runNestedTest(routerI1) else runPrototype(appOnly,routerI1,maskVariant)}
            catch(_:Exception){if(!closing.get())stop(Reason.NO_EXIT)}
        }
        return START_STICKY
    }
    private fun journal(code:String,error:String="",index:Int=0,latency:Long=-1L){
        runCatching {store.recordEvent(code,"WARP",index=index,error=error,latency=latency)}
    }
    // Probe a returning Wi-Fi on the physical Network, bypassing the VPN.
    private fun probePhysicalWifi(network:Network):Boolean=runCatching {
        val conn=network.openConnection(URL("https://one.one.one.one/cdn-cgi/trace")) as HttpsURLConnection
        conn.connectTimeout=3500
        conn.readTimeout=3500
        conn.instanceFollowRedirects=false
        try{conn.responseCode==200}finally{conn.disconnect()}
    }.getOrDefault(false)
    private fun physical():Network? = cm.allNetworks
        .filter{n->
            val caps=cm.getNetworkCapabilities(n)
            caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)==true &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        .sortedByDescending{n->
            val caps=cm.getNetworkCapabilities(n)
            (if(preferredNetworkHandle!=0L && n.networkHandle==preferredNetworkHandle)16 else 0)+
                (if(n==cm.activeNetwork)4 else 0)+
                (if(caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)==true)2 else 0)+
                (if(caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))1 else 0)
        }.firstOrNull()
    private fun ipv4(quick:String):String{
        val raw=Regex("(?m)^\\s*Address\\s*=\\s*([^\r\n]+)").find(quick)
            ?.groupValues?.get(1) ?: error("no_awg_address")
        for(candidate in raw.split(",")){
            val ip=candidate.trim().substringBefore('/')
            val address=runCatching{InetAddresses.parseNumericAddress(ip)}.getOrNull()
            if(address is Inet4Address)return address.hostAddress.orEmpty()
        }
        error("no_ipv4_address")
    }
    private fun resolveEndpoint(quick:String,network:Network):String{
        val match=Regex("(?m)^\\s*Endpoint\\s*=\\s*([^\r\n]+)").find(quick)
            ?: error("no_endpoint")
        val endpoint=match.groupValues[1].trim()
        val host=endpoint.substringBeforeLast(":").removePrefix("[").removeSuffix("]")
        val port=endpoint.substringAfterLast(":").toIntOrNull() ?: error("bad_port")
        require(port in 1..65535)
        // Resolve via the physical Network BEFORE establishing Android VPN.
        // Never use the VPN network for endpoint DNS.
        val address=network.getAllByName(host).firstOrNull {
            it is Inet4Address && publicIP(it)
        } ?: error("no_public_ipv4_endpoint")
        return quick.replaceRange(match.range,"Endpoint = ${address.hostAddress}:$port")
    }
    private fun runNestedTest(routerI1:Boolean){
        store.nestedProbeResult("awg_nested_running","","","")
        journal("awg_nested_start")
        try{
            if(prepare(this)!=null)error("permission_revoked")
            if(cm.allNetworks.any {cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true}){
                store.nestedProbeResult("awg_nested_failed","","","")
                journal("awg_vpn_failed","awg_vpn_existing_vpn");return
            }
            val network=physical() ?: error("no_physical_network")
            underlyingPhysical=network
            val state=store.read()
            val saved=state.optString("awgQuick")
            val outer=if(routerI1){
                val signature=assets.open("warp-router-i1.cps").bufferedReader().use{it.readText().trim()}
                AwgMasking.withI1(saved,signature)
            }else saved
            val outerConfig=resolveEndpoint(outer,network)
            val innerConfig=resolveEndpoint(state.optString("nestedWarpQuick"),network)
            if(closing.get())return
            val probe=Awglab.newNestedProbe()
            if(!nestedProbe.compareAndSet(null,probe)){probe.close();error("nested_already_active")}
            if(closing.get()){nestedProbe.getAndSet(null)?.close();return}
            val outcome=probe.run(outerConfig,innerConfig,this)
            if(closing.get())return
            val outerCountry=AwgRegionPolicy.country(probe.outerCountry())
            val innerCountry=AwgRegionPolicy.country(probe.innerCountry())
            journal("awg_nested_outer_country","awg_country_"+outerCountry.ifBlank{"unknown"})
            journal("awg_vpn_trace_node","awg_colo_"+AwgNodePolicy.code(probe.outerColo()).ifBlank{"unknown"})
            if(innerCountry.isNotBlank()){
                journal("awg_nested_inner_country","awg_country_"+innerCountry)
                journal("awg_vpn_trace_node","awg_colo_"+AwgNodePolicy.code(probe.innerColo()).ifBlank{"unknown"})
            }
            val outerMeta=AwgRegionPolicy.country(probe.outerMetaCountry())
            val innerMeta=AwgRegionPolicy.country(probe.innerMetaCountry())
            val innerMetaColo=AwgNodePolicy.code(probe.innerMetaColo())
            journal("awg_nested_outer_meta","awg_country_"+outerMeta.ifBlank{"unknown"})
            journal("awg_nested_inner_meta","awg_country_"+innerMeta.ifBlank{"unknown"})
            if(innerMetaColo.isNotBlank())journal("awg_nested_meta_node","awg_colo_"+innerMetaColo)
            store.nestedProbeResult(outcome,outerCountry,innerCountry,probe.exitIP(),outerMeta,innerMeta,innerMetaColo)
            journal("awg_nested_done",outcome)
        }catch(_:Exception){
            if(!closing.get()){
                store.nestedProbeResult("awg_nested_failed","","","")
                journal("awg_nested_done","awg_nested_failed")
            }
        }finally{
            runCatching{nestedProbe.getAndSet(null)?.close()}
            // This experiment never establishes Android TUN or CONNECTED.
            if(!closing.get())stop(Reason.IDLE)
        }
    }
    private fun runPrototype(appOnly:Boolean,routerI1:Boolean,maskVariant:String){
        // Diagnostics retain their explicit legacy arguments; the home screen
        // supplies a stable mode ID. Auto selection belongs to the service so
        // leaving/recreating the Activity cannot stop it or launch another VPN.
        val mode=AwgConnectMode.entries.firstOrNull{it.id==maskVariant}
        val policy=store.read()
        val network=physical()
        val caps=network?.let{cm.getNetworkCapabilities(it)}
        val cacheKey=when{
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true->"awgLastMaskWifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true->"awgLastMaskCellular"
            else->"awgLastMaskOther"
        }
        val plan=if(mode==null)listOf(if(routerI1)AwgConnectMode.I1 else AwgConnectMode.PROFILE)
            else AwgConnectMode.plan(mode,policy.optBoolean("awgImported"),policy.optString(cacheKey))
        val deadline=SystemClock.elapsedRealtime()+AwgConnectMode.AUTO_TIMEOUT_MS
        val timeout=Runnable{if(!closing.get() && session.value.phase==Phase.CONNECTING)stop(Reason.START_TIMEOUT)}
        if(mode==AwgConnectMode.AUTO)main.postDelayed(timeout,AwgConnectMode.AUTO_TIMEOUT_MS)
        try{
            for((index,candidate) in plan.withIndex()){
                if(closing.get())return
                if(mode==AwgConnectMode.AUTO && SystemClock.elapsedRealtime()>=deadline){
                    stop(Reason.START_TIMEOUT);return
                }
                if(index>0){
                    journal("awg_vpn_mask_retry",index=index+1)
                    session.update(Live(Phase.CONNECTING,Reason.START))
                }
                // Every attempt owns a fresh TUN, UDP session and random I1.
                goControlStarted=false
                dohFailureLogged.set(false)
                val variant=if(candidate in listOf(AwgConnectMode.QUIC,AwgConnectMode.DNS,AwgConnectMode.STUN))candidate.id else ""
                val failure=runAttempt(appOnly,candidate==AwgConnectMode.I1,variant)
                if(closing.get())return
                if(failure==null){
                    if(session.value.phase==Phase.CONNECTED){
                        // Only final Android HTTPS verification may teach Auto.
                        // Do not associate a result with a different physical network.
                        if(underlyingPhysical==network)runCatching{store.edit{it.put(cacheKey,candidate.id)}}
                    }
                    return
                }
                runCatching{dohClient.getAndSet(null)?.close()}
                runCatching{resources.releaseAttempt()}
                underlyingPhysical=null
                if(mode!=AwgConnectMode.AUTO || failure!=Reason.NO_EXIT || index==plan.lastIndex){
                    stop(failure);return
                }
                // Wait for Android to remove our failed VPN before the next
                // protected preflight. Never start over an existing VPN.
                val removedBy=SystemClock.elapsedRealtime()+3000L
                while(!closing.get() && SystemClock.elapsedRealtime()<removedBy &&
                    cm.allNetworks.any{cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true}){
                    Thread.sleep(100)
                }
            }
        }catch(_:Exception){
            if(!closing.get())stop(Reason.NO_EXIT)
        }finally{main.removeCallbacks(timeout)}
    }
    /** null means a verified connection (or a completed app-only diagnostic). */
    private fun runAttempt(appOnly:Boolean,routerI1:Boolean,maskVariant:String):Reason?{
        journal("awg_vpn_start")
        journal(if(appOnly)"awg_vpn_scope_app" else "awg_vpn_scope_all")
        val maskEvent=when(maskVariant){
            "quic"->"awg_vpn_mask_quic"
            "dns"->"awg_vpn_mask_dns"
            "stun"->"awg_vpn_mask_stun"
            else->if(routerI1)"awg_vpn_mask_router_i1" else "awg_vpn_mask_original"
        }
        journal(maskEvent)
        try{
            if(prepare(this)!=null)error("permission_revoked")
            val network=physical() ?: error("no_physical_network")
            val quick=store.read().optString("awgQuick")
            require(Awglab.validateQuickFile(quick))
            require(maskVariant in setOf("","quic","dns","stun")) { "awg_mask_unknown_variant" }
            val effective=if(maskVariant.isNotEmpty()){
                AwgMasking.withI1(quick,AwgMaskPackets.signature(maskVariant))
            }else if(routerI1){
                val signature=assets.open("warp-router-i1.cps").bufferedReader().use{it.readText().trim()}
                AwgMasking.withI1(quick,signature)
            }else quick
            require(Awglab.validateQuickFile(effective))
            val resolved=resolveEndpoint(effective,network)
            val address=ipv4(resolved)
            if(closing.get())return null
            underlyingPhysical=network
            // Compare the same protected transport before Android changes routes.
            // Never run a netstack probe through an already established VPN.
            val existingVPN=cm.allNetworks.any {n->
                cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
            }
            if(existingVPN){
                journal("awg_vpn_failed","awg_vpn_existing_vpn")
                return Reason.DENIED
            }
            val policy=store.read()
            val dnsProvider=AwgDnsPolicy.selected(policy)
            // Bootstrap ONLY the resolver hostname on the physical network,
            // before synthetic DNS is installed. All user DNS travels in WARP.
            val dnsURL=dnsProvider?.url?.toHttpUrl()
            val dnsBootstrap=try{dnsURL?.let {url->
                network.getAllByName(url.host).filterIsInstance<Inet4Address>()
                    .also {require(it.isNotEmpty())}
            }.orEmpty()}catch(_:Exception){
                journal("awg_doh_failed")
                throw AwgVerifyFailure("awg_vpn_doh_failed",AwgVerifyStage.TRACE)
            }
            // Use the saved endpoint. Experimental node/country selection is
            // retired; a foreign colo did not guarantee foreign IP GeoIP.
            val preparedSession=Awglab.prepareAndroidVPN(resolved,this)
            if(!preparing.compareAndSet(null,preparedSession)){
                preparedSession.close()
                error("awg_prepare_already_active")
            }
            if(closing.get())return null
            journal("awg_vpn_transport_preflight_start")
            val outcome=runCatching{preparedSession.probeWarp()}.getOrDefault("awg_https_failed")
            if(closing.get())return null
            journal("awg_vpn_transport_preflight",outcome)
            // Keep the isolated non-WARP CI adapter path. It cannot pass the
            // mandatory final Android warp=on/plus verifier below.
            if(!outcome.startsWith("awg_verified:") && outcome!="awg_not_confirmed")
                throw AwgVerifyFailure("awg_vpn_preflight_failed",AwgVerifyStage.TRACE)
            val prepared=preparing.get() ?: return null
            if(closing.get())return null
            verifyRegion(prepared.countryCode())
            verifyNode(prepared.coloCode())
            setUnderlyingNetworks(arrayOf(network))
            // IPv4 only: Android blocks unconfigured IPv6 for routed apps,
            // instead of silently allowing IPv6 traffic to bypass WARP.
            val builder=Builder().setSession(
                if(appOnly)"ZBS VPN · тест только приложения" else "ZBS VPN · AmneziaWG")
                .setMtu(1280).setMetered(false).setBlocking(true)
                .addAddress(address,32).addRoute("0.0.0.0",0)
                .addDnsServer(if(dnsProvider==null)"1.1.1.1" else AwgDnsPolicy.LOCAL_DNS)
                .setUnderlyingNetworks(arrayOf(network))
            if(appOnly)builder.addAllowedApplication(packageName)
            val pfd=builder.establish() ?: error("tun_establish_failed")
            if(!resources.installTun(pfd))return null
            journal("awg_vpn_tun")
            if(closing.get())return null
            // Android routes are active, but the AWG frontend is still the
            // same private netstack. Isolate route activation from IP handoff.
            journal("awg_vpn_transport_state",prepared.transportState())
            journal("awg_vpn_post_tun_start")
            val afterTUN=runCatching{prepared.probeWarpAfterTUN()}
                .getOrDefault("awg_https_failed")
            if(closing.get())return null
            journal("awg_vpn_post_tun",afterTUN)
            journal("awg_vpn_post_tun_udp",prepared.postTUNUDPState())
            verifyRegion(prepared.countryCode())
            verifyNode(prepared.coloCode())
            journal("awg_vpn_transport_state",prepared.transportState())
            // Native Go code consumes this detached duplicate, even on error.
            val dns=if(dnsURL==null)null else {
                val vpn=cm.allNetworks.firstOrNull {n->
                    cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
                } ?: throw AwgVerifyFailure("awg_vpn_doh_failed",AwgVerifyStage.TRACE)
                AwgDohClient(dnsURL,dnsBootstrap,vpn.socketFactory){
                    if(!closing.get() && dohFailureLogged.compareAndSet(false,true))journal("awg_doh_failed")
                }
            }
            if(dns!=null){
                dohClient.set(dns)
                if(closing.get()){dohClient.getAndSet(null)?.close();return null}
                journal("awg_doh_start")
            }
            val dup=ParcelFileDescriptor.dup(pfd.fileDescriptor)
            val rawFd=dup.detachFd()
            val engine=if(dns==null)prepared.start(rawFd.toLong()) else prepared.startWithDNS(rawFd.toLong(),dns)
            preparing.compareAndSet(prepared,null)
            runCatching{prepared.close()}
            if(!resources.installEngine(engine))return null
            if(closing.get())return null
            dohClient.get()?.let{dns->
                // Check HTTPS DNS through WARP before advertising CONNECTED.
                // No direct/system fallback is allowed on failure.
                if(!Awglab.checkDNS(dns)){
                    journal("awg_doh_failed")
                    throw AwgVerifyFailure("awg_vpn_doh_failed",AwgVerifyStage.TRACE)
                }
                journal("awg_doh_ready")
            }
            journal("awg_vpn_udp_reused")
            journal("awg_vpn_session_reused")
            session.update(Live(Phase.CONNECTING,Reason.VERIFY))
            // HTTPS verification is mandatory. Handshake alone does NOT prove
            // any app traffic can traverse this system VPN.
            var verified:AwgVerifiedConnection?=null
            var deepestFailure:AwgVerifyFailure?=null
            var handshakeLogged=false
            for(attempt in 0 until 3){
                if(closing.get())return null
                if(engine.hasHandshake() && !handshakeLogged){
                    journal("awg_vpn_handshake")
                    handshakeLogged=true
                }
                try{
                    verified=verifyHTTPS()
                    journal("awg_vpn_tcp_bound",awgTCPFlowCode(engine.tcpFlowCounters()))
                    journal("awg_vpn_tcp_data",awgTCPDataCode(engine.tcpDataCounters(),engine.tcpFlowCounters()))
                    break
                }catch(e:AwgVerifyFailure){
                    deepestFailure=awgDeeperFailure(deepestFailure,e)
                    journal("awg_vpn_verify_attempt",e.code,attempt+1)
                    journal("awg_vpn_tcp_bound",awgTCPFlowCode(engine.tcpFlowCounters()))
                    journal("awg_vpn_tcp_data",awgTCPDataCode(engine.tcpDataCounters(),engine.tcpFlowCounters()))
                    if(AwgRegionPolicy.rejection(e.code))break
                    if(engine.udpLoopCount()>0L){
                        deepestFailure=AwgVerifyFailure("awg_vpn_udp_loop",AwgVerifyStage.TRACE)
                        break
                    }
                }
                if(!closing.get())Thread.sleep(1000)
            }
            if(verified==null){
                if(!closing.get() && engine.udpLoopCount()==0L &&
                    !AwgRegionPolicy.rejection(deepestFailure?.code.orEmpty()))
                    goTLSControl(engine,"awg_vpn_go_after")
                if(closing.get())return null
                // Snapshot only aggregate packet counts, never UAPI/keys/traffic.
                // This pinpoints a missing Android->TUN path vs no decrypted response.
                val counts=runCatching{
                    engine.packetCounters().split(",").map{it.toLongOrNull() ?: 0L}
                }.getOrDefault(emptyList())
                val flow=if(counts.size!=4)"awg_flow_unknown"
                    else when{
                        counts[0]==0L -> "awg_flow_no_tun_in"
                        counts[1]==0L -> "awg_flow_no_tun_out"
                        else -> "awg_flow_bidirectional"
                    }
                journal("awg_vpn_flow",flow)
                journal("awg_vpn_udp_flow",awgUDPFlowCode(engine.packetCounters(),engine.udpLoopCount()))
                journal("awg_vpn_failed",deepestFailure?.code ?: "awg_vpn_http_failed")
                return AwgRegionPolicy.reason(deepestFailure?.code.orEmpty())
            }
            if(closing.get())return null
            if(appOnly){
                // This diagnostic never advertises a connected system VPN.
                // Both TLS controls and the actual Android verifier are kept.
                journal("awg_vpn_app_only_verified")
                stop(Reason.IDLE)
                return null
            }
            journal("awg_vpn_verified")
            val start=SystemClock.elapsedRealtime()
            session.update(Live(Phase.CONNECTED,Reason.ONLINE,
                "AmneziaWG · Android","WARP",verified.ip,
                verified.latency.coerceAtLeast(0L),start,country=verified.country))
            Log.i("AutoWARP.AWG","System VPN verified via HTTPS")
            if(!closing.get()){
                startTrafficUpdates(engine)
                startRouteWatchdog()
            }
        }catch(e:AwgVerifyFailure){
            journal("awg_vpn_failed",e.code)
            return AwgRegionPolicy.reason(e.code)
        }catch(_:Exception){
            journal("awg_vpn_failed","awg_vpn_start_failed")
            return if(prepare(this)!=null)Reason.REVOKED else Reason.NO_EXIT
        }finally{
            runCatching{preparing.getAndSet(null)?.close()}
        }
        return null
    }
    private fun verifyRegion(raw:String){
        val country=AwgRegionPolicy.country(raw)
        journal("awg_vpn_exit_country","awg_country_"+country.ifBlank{"unknown"})
    }
    private fun verifyNode(raw:String){
        val code=AwgNodePolicy.code(raw)
        journal("awg_vpn_trace_node","awg_colo_"+code.ifBlank{"unknown"})
    }
    private fun checkCurrentRoute(){
        if(closing.get() || session.value.phase!=Phase.CONNECTED ||
            !checking.compareAndSet(false,true))return
        journal("awg_vpn_check_start")
        runCatching{worker.execute{
            try{
                if(closing.get() || session.value.phase!=Phase.CONNECTED)return@execute
                dohClient.get()?.let{dns->
                    if(!Awglab.checkDNS(dns))throw AwgVerifyFailure("awg_vpn_doh_failed",AwgVerifyStage.TRACE)
                }
                val result=verifyHTTPS()
                val current=session.value
                if(!closing.get() && current.phase==Phase.CONNECTED &&
                    session.update(current.copy(ip=result.ip,ms=result.latency,country=result.country))){
                    journal("awg_vpn_check_ok",latency=result.latency)
                }
            }catch(e:AwgVerifyFailure){
                if(!closing.get()){
                    journal("awg_vpn_check_failed",e.code)
                    stop(AwgRegionPolicy.reason(e.code))
                }
            }catch(_:Exception){
                if(!closing.get()){
                    journal("awg_vpn_check_failed","awg_https_failed")
                    stop(Reason.NO_EXIT)
                }
            }finally{checking.set(false)}
        }}.onFailure{checking.set(false)}
    }
    private fun startTrafficUpdates(engine:AndroidVPN){
        val meter=AwgTrafficMeter()
        meter.sample(engine.trafficBytes(),SystemClock.elapsedRealtime())
        runCatching{worker.scheduleWithFixedDelay({
            if(!closing.get() && session.value.phase==Phase.CONNECTED)runCatching{
                val rate=meter.sample(engine.trafficBytes(),SystemClock.elapsedRealtime())
                val current=session.value
                if(rate!=null && !closing.get() && current.phase==Phase.CONNECTED){
                    // VpnSession rejects a late update after STOP/revoke.
                    session.update(current.copy(down=rate.download,up=rate.upload))
                }
            }
        },1,1,TimeUnit.SECONDS)}
    }
    // End-to-end health check: a stale UDP socket cannot remain CONNECTED.
    private fun startRouteWatchdog(){
        var failures=0
        runCatching{worker.scheduleWithFixedDelay({
            if(!closing.get() && session.value.phase==Phase.CONNECTED &&
                checking.compareAndSet(false,true)){
                try{
                    val verified=verifyHTTPS()
                    failures=0
                    val current=session.value
                    if(!closing.get() && current.phase==Phase.CONNECTED)
                        session.update(current.copy(ip=verified.ip,ms=verified.latency,country=verified.country))
                }catch(e:Exception){
                    failures++
                    journal("awg_vpn_watchdog_failed",if(e is AwgVerifyFailure)e.code else "awg_vpn_start_failed",index=failures)
                    recordBackgroundState()
                    if(failures>=2 && !closing.get()){
                        session.update(Live(Phase.CONNECTING,Reason.RECOVER))
                        stop(Reason.RECOVER,restart=true)
                    }
                }finally{checking.set(false)}
            }
        },25,25,TimeUnit.SECONDS)}
    }
    private fun goTLSControl(engine:AndroidVPN,event:String,selected:Network?=null){
        if(closing.get())return
        val vpn=selected ?: cm.allNetworks.firstOrNull {n->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
        }
        if(vpn==null){journal(event,"awg_control_no_network");return}
        val dialer=object:VPNNetworkDialer {
            @Volatile private var socket:Socket?=null
            override fun open():Long {
                if(closing.get())return -1L
                close()
                return try {
                    // Exactly the socket factory/source-port reservation used
                    // by OkHttp; no separate native bind to the assigned IP.
                    val factory=AwgDiagnosticSocketFactory(vpn.socketFactory){port->
                        engine.setDiagnosticPort(port.toLong())
                    }
                    val candidate=factory.createSocket()
                    socket=candidate
                    candidate.connect(InetSocketAddress(
                        InetAddress.getByAddress(byteArrayOf(1,1,1,1)),443),6500)
                    // Retain the Java Socket until Go has closed its own copy.
                    ParcelFileDescriptor.fromSocket(candidate).detachFd().toLong()
                }catch(_:SocketTimeoutException){-3L}
                 catch(_:Exception){if(socket==null)-2L else -4L}
            }
            override fun close(){
                val owned=socket
                socket=null
                runCatching{owned?.close()}
            }
        }
        val result=runCatching{engine.probeSystemTLS(dialer)}
            .getOrDefault("awg_control_stopped")
        if(!closing.get())journal(event,result)
    }
    private fun verifyHTTPS():AwgVerifiedConnection{
        val vpn=cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
        } ?: throw AwgVerifyFailure("awg_vpn_no_network",AwgVerifyStage.TCP)
        val engine=resources.engine()
            ?: throw AwgVerifyFailure("awg_vpn_start_failed",AwgVerifyStage.TCP)
        if(!goControlStarted){
            goControlStarted=true
            goTLSControl(engine,"awg_vpn_go_before",vpn)
        }
        if(closing.get())throw AwgVerifyFailure("awg_vpn_start_failed",AwgVerifyStage.TCP)
        engine.setDiagnosticPort(0)
        val started=SystemClock.elapsedRealtime()
        var stage=AwgVerifyStage.TCP
        val factory=AwgDiagnosticSocketFactory(vpn.socketFactory){port ->
            engine.setDiagnosticPort(port.toLong())
        }
        val client=awgVerificationClient(factory){next ->
            stage=next
            journal(if(next==AwgVerifyStage.TLS)"awg_vpn_tcp_connected" else "awg_vpn_tls_ready")
        }
        try {
            val request=Request.Builder().url("https://one.one.one.one/cdn-cgi/trace")
                .header("Accept","text/plain").header("Connection","close").build()
            client.newCall(request).execute().use {response ->
                stage=AwgVerifyStage.TRACE
                val trace=awgVerifiedTrace(response)
                val flow=engine.tcpFlowCounters().split(",").map{it.toLongOrNull() ?: 0L}
                if(flow.size!=14 || (0..3).any{flow[it]==0L})
                    throw AwgVerifyFailure("awg_vpn_wrong_path",AwgVerifyStage.TRACE)
                verifyRegion(trace.country)
                verifyNode(trace.colo)
                return AwgVerifiedConnection(trace.ip,SystemClock.elapsedRealtime()-started,trace.country,trace.colo)
            }
        }catch(e:AwgVerifyFailure){throw e}
         catch(e:Exception){throw awgVerifyFailure(stage,e)}
        finally {
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }
    private fun stop(reason:Reason,restart:Boolean=false,preferred:Network?=null){
        if(!closing.compareAndSet(false,true))return
        if(restart)journal("awg_vpn_recovery_start")
        session.beginStop(if(reason==Reason.IDLE)Reason.STOP else reason)
        // Native shutdown may block; run it outside the Android main thread.
        Thread({
            runCatching{dohClient.getAndSet(null)?.close()}
            runCatching{
                nestedProbe.getAndSet(null)?.let {probe->
                    probe.close()
                    store.nestedProbeResult("awg_nested_stopped","","","")
                    journal("awg_nested_done","awg_nested_stopped")
                }
            }
            runCatching{preparing.getAndSet(null)?.close()}
            runCatching{resources.close()}
            main.post{
                session.finish(reason)
                if(registered){runCatching{unregisterReceiver(control)};registered=false}
                main.removeCallbacks(networkChangeCheck)
                if(networkCallbackRegistered){
                    runCatching{cm.unregisterNetworkCallback(physicalCallback)}
                    networkCallbackRegistered=false
                }
                if(backgroundReceiverRegistered){
                    runCatching{unregisterReceiver(backgroundReceiver)}
                    backgroundReceiverRegistered=false
                }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                if(restart && reason==Reason.RECOVER){
                    // Build a fresh TUN + engine; never reuse Wi-Fi-bound sockets.
                    val app=applicationContext
                    val appOnly=lastAppOnly
                    val routerI1=lastRouterI1
                    val maskVariant=lastMaskVariant
                    main.postDelayed({
                        if(runCatching{prepare(app)}.getOrNull()==null && physical()!=null){
                            runCatching{
                                app.startForegroundService(Intent(app,AwgTunnel::class.java)
                                    .setAction("START_AWG")
                                    .putExtra("AWG_APP_ONLY",appOnly)
                                    .putExtra("AWG_ROUTER_I1",routerI1)
                                    .putExtra("AWG_MASK_VARIANT",maskVariant)
                                    .putExtra("AWG_PHYSICAL_NETWORK",preferred?.networkHandle ?: 0L))
                            }
                        }
                    },1000)
                }
            }
        },"awg-stop").apply{isDaemon=true;start()}
    }
    override fun onRevoke(){journal("awg_vpn_permission_revoked");stop(Reason.REVOKED)}
    override fun onDestroy(){journal("awg_vpn_service_destroyed");stop(Reason.IDLE);worker.shutdownNow();super.onDestroy()}
}


