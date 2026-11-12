package dev.autowarp

import android.app.ActivityManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import io.nekohasekai.awglab.Awglab
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.*
import java.net.InetAddress
import java.net.Inet4Address
import java.net.Proxy
import java.util.concurrent.TimeUnit

/** CI only: one disposable Cloudflare registration; never imports user keys. */
internal object RealWarpScenario {
    fun run(){
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        val cm=context.getSystemService(ConnectivityManager::class.java)
        val am=context.getSystemService(ActivityManager::class.java)
        val store=Store.get(context)
        fun noVPN()=cm.allNetworks.none {
            cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
        } && am.getRunningServices(100).none {it.service.className==AwgTunnel::class.java.name}
        fun awaitStop():Boolean {
            val until=SystemClock.elapsedRealtime()+15000
            while(!noVPN() && SystemClock.elapsedRealtime()<until)SystemClock.sleep(250)
            return noVPN()
        }
        // The preceding mock test stops asynchronously. Do not start a probe
        // until both its Android VPN and native service have actually stopped.
        assertTrue("warp_ci_previous_vpn_not_stopped",awaitStop())
        val physical=requireNotNull(cm.activeNetwork){"warp_ci_no_physical_network"}
        assertTrue("warp_ci_no_physical_network",
            cm.getNetworkCapabilities(physical)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)==true)
        assertFalse("warp_ci_existing_credentials",store.read().has("keys") || store.read().has("reg"))
        try {
            try {Warp.activate(store)}catch(_:Exception){
                // Registration failures must not leak request/response bodies,
                // generated keys, device IDs, tokens or exception causes.
                fail("warp_ci_registration_failed; system VPN was not tested")
            }
            println("warp_ci_registration_ready")
            val generated=try {AmneziaWarpGenerator.generate(store.read())}
                catch(_:Exception){throw AssertionError("warp_ci_generation_failed")}
            val quick=pinEndpoint(generated,physical)
            assertTrue("warp_ci_invalid_quick",Awglab.validateQuickFile(quick))
            store.saveAWG(quick)
            val baseline=try {Awglab.probeWarp(quick)}
                catch(_:Exception){throw AssertionError("warp_ci_baseline_native_failed")}
            val safeBaseline=baseline.takeIf {it.matches(Regex("awg_[a-z_]+|awg_verified:[0-9]{1,5}"))}
                ?: "awg_unknown"
            println("warp_ci_baseline:$safeBaseline")
            assertTrue("warp_ci_baseline_failed:$safeBaseline; system VPN was not tested",
                baseline.startsWith("awg_verified:"))
            // ProbeWarp closes its native device before returning: never run
            // the two clients concurrently with the same WARP identity.
            assertTrue("warp_ci_vpn_before_system_test",noVPN())
            store.clearEvents()
            assertEquals("Unexpected CI target package","dev.autowarp",context.packageName)
            val consent=ParcelFileDescriptor.AutoCloseInputStream(
                instrumentation.uiAutomation.executeShellCommand(
                    "appops set dev.autowarp ACTIVATE_VPN allow"
                )
            ).bufferedReader().use{it.readText()}
            assertTrue("warp_ci_consent_command_failed",consent.isBlank())
            assertNull("warp_ci_consent_missing",VpnService.prepare(context))
            // Same disposable identity and pinned endpoint, sequential services.
            // Original full/app-only controls run first; the third adds only I1.
            for((appOnly,routerI1) in listOf(false to false,true to false,true to true)){
                val scope=if(routerI1)"app_only_i1" else if(appOnly)"app_only" else "system"
                val scopeEvent=if(appOnly)"awg_vpn_scope_app" else "awg_vpn_scope_all"
                val maskEvent=if(routerI1)"awg_vpn_mask_router_i1" else "awg_vpn_mask_original"
                store.clearEvents()
                ActivityScenario.launch(MainActivity::class.java).use {scenario ->
                    scenario.onActivity{AwgTunnel.start(it,appOnly,routerI1)}
                    val until=SystemClock.elapsedRealtime()+90000
                    var preflight=false
                    var transportReused=false
                var sessionReused=false
                var postTUN=false
                var postUDP=false
                    var goControlResult:String?=null
                    var verified=false
                    var globalVerified=false
                    var scopeObserved=false
                    var maskObserved=false
                    var failed=false
                    while(SystemClock.elapsedRealtime()<until){
                        val events=store.read().optJSONArray("eventLog")
                        if(events!=null)for(i in 0 until events.length()){
                            val event=events.optJSONObject(i)
                            if(event?.optString("code")=="awg_vpn_udp_reused")transportReused=true
                            if(event?.optString("code")=="awg_vpn_session_reused")sessionReused=true
                            if(event?.optString("code")=="awg_vpn_post_tun" &&
                                event.optString("error").startsWith("awg_verified:"))postTUN=true
                            if(event?.optString("code")=="awg_vpn_post_tun_udp" &&
                                event.optString("error")=="awg_post_udp_bidirectional")postUDP=true
                            if(event?.optString("code")=="awg_vpn_transport_preflight" &&
                                event.optString("error").startsWith("awg_verified:"))preflight=true
                            if(event?.optString("code")=="awg_vpn_go_before")
                                goControlResult=event.optString("error")
                            if(event?.optString("code")==scopeEvent)
                                scopeObserved=true
                            if(event?.optString("code")==maskEvent)maskObserved=true
                            when(event?.optString("code")){
                                "awg_vpn_verified"->{globalVerified=true;if(!appOnly)verified=true}
                                "awg_vpn_app_only_verified"->if(appOnly)verified=true
                                "awg_vpn_failed"->failed=true
                            }
                        }
                        if(verified || failed)break
                        SystemClock.sleep(250)
                    }
                    val journal=safeJournal(store)
                    println("warp_ci_"+scope+"_journal:$journal")
                    // Production requires warp=on/plus AND matching TCP flow
                    // through this TUN; TLS/handshake alone never satisfies this.
                    assertTrue("warp_ci_scope_missing_"+scope+":" + journal,scopeObserved)
                    assertTrue("warp_ci_mask_missing_"+scope+":" + journal,maskObserved)
                    if(appOnly)assertFalse("warp_ci_app_only_claimed_global_vpn:$journal",globalVerified)
                    assertTrue("warp_ci_transport_not_reused:$journal",transportReused)
                    assertTrue("warp_ci_session_not_reused:$journal",sessionReused)
                    assertTrue("warp_ci_post_tun_netstack_failed:$journal",postTUN)
                    assertTrue("warp_ci_post_tun_udp_failed:$journal",postUDP)
                    val recorded=store.read().optJSONArray("eventLog")
                    val binds=if(recorded==null)0 else (0 until recorded.length()).count {
                        recorded.optJSONObject(it)?.optString("code")=="awg_vpn_udp_bound"
                    }
                    assertEquals("warp_ci_udp_reprotected_after_tun",1,binds)
                    assertTrue("warp_ci_protected_preflight_failed:$journal",preflight)
                    val controlOutcome=goControlResult ?: "missing"
                    println("warp_ci_"+scope+"_go_control:"+controlOutcome)
                    println("warp_ci_"+scope+"_android:"+(if(verified)"verified" else "failed"))
                    // The mandatory product verdict remains real Android HTTPS,
                    // warp=on/plus and exact native TUN flow correlation.
                    assertTrue("warp_ci_system_failed_after_verified_baseline:$journal",verified)
                    // A network timeout in an earlier auxiliary request is a
                    // comparison result, not a failed Android VPN verdict.
                    // Missing/broken socket binding or routing evidence still
                    // fails; the deterministic mock also requires Go HTTPS.
                    val acceptable=setOf("awg_control_verified","awg_control_tcp_timeout",
                        "awg_control_tls_timeout","awg_control_http_timeout")
                    assertTrue("warp_ci_go_control_unexpected:$journal",
                        controlOutcome in acceptable)
                    if(!appOnly){
                        Tunnel.cmd(context,"CHECK")
                        val checkUntil=SystemClock.elapsedRealtime()+25000
                        var outcome=""
                        while(SystemClock.elapsedRealtime()<checkUntil){
                            val events=store.read().optJSONArray("eventLog")
                            if(events!=null)for(i in 0 until events.length()){
                                when(events.optJSONObject(i)?.optString("code")){
                                    "awg_vpn_check_ok"->outcome="ok"
                                    "awg_vpn_check_failed"->outcome="failed"
                                }
                            }
                            if(outcome.isNotEmpty())break
                            SystemClock.sleep(250)
                        }
                        assertEquals("warp_ci_manual_check_did_not_confirm_HTTPS:"+safeJournal(store),"ok",outcome)
                        assertTrue("warp_ci_manual_check_stopped_vpn",cm.allNetworks.any {
                            cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
                        })
                        println("warp_ci_manual_check_verified")
                    }
                    println("warp_ci_"+scope+"_verified:real_WARP_HTTPS_on_emulator")
                }
                Tunnel.cmd(context,"STOP")
                assertTrue("warp_ci_"+scope+"_not_stopped",awaitStop())
            }
        }finally{
            Tunnel.cmd(context,"STOP")
            val stopped=awaitStop()
            println(if(stopped)"warp_ci_vpn_stopped" else "warp_ci_vpn_stop_failed")
            removeRegistration(store,physical)
            // The disposable emulator is also destroyed by the workflow.
            store.edit {s->
                for(key in listOf("keys","reg","registeredConf","wg","warp","awgQuick","retry"))s.remove(key)
            }
        }
    }

    private fun pinEndpoint(quick:String,physical:Network):String {
        try {
            val match=Regex("(?m)^\\s*Endpoint\\s*=\\s*([^\r\n]+)").find(quick)
                ?: throw IllegalArgumentException()
            val endpoint=match.groupValues[1].trim()
            val host=endpoint.substringBeforeLast(':').removePrefix("[").removeSuffix("]")
            val port=endpoint.substringAfterLast(':').toInt()
            require(port in 1..65535)
            val ip=physical.getAllByName(host).first {it is Inet4Address && publicIP(it)}
            // One physical-network DNS lookup; both engines use this exact
            // IPv4:port. The address/config is deliberately never printed.
            return quick.replaceRange(match.range,"Endpoint = ${ip.hostAddress}:$port")
        }catch(_:Exception){throw AssertionError("warp_ci_endpoint_resolution_failed")}
    }

    private fun removeRegistration(store:Store,physical:Network){
        val reg=store.read().optJSONObject("reg") ?: return
        val id=reg.optString("id")
        val token=reg.optString("token")
        if(!id.matches(Regex("[A-Za-z0-9-]{1,80}")) || token.isBlank()){
            println("warp_ci_registration_cleanup_invalid_metadata")
            return
        }
        val client=OkHttpClient.Builder().proxy(Proxy.NO_PROXY)
            .socketFactory(physical.socketFactory)
            .dns(object:Dns {
                override fun lookup(hostname:String):List<InetAddress> =
                    physical.getAllByName(hostname).toList()
            })
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
            .connectTimeout(10,TimeUnit.SECONDS).readTimeout(10,TimeUnit.SECONDS)
            .callTimeout(10,TimeUnit.SECONDS).build()
        try {
            val request=Request.Builder()
                .url("https://api.devices.cloudflare.com/v0a4005/reg/$id")
                .header("Authorization","Bearer $token").delete().build()
            client.newCall(request).execute().use {response->
                println(if(response.isSuccessful || response.code==404)
                    "warp_ci_registration_removed" else "warp_ci_registration_cleanup_rejected")
            }
        }catch(_:Exception){println("warp_ci_registration_cleanup_failed")}
        finally{client.connectionPool.evictAll();client.dispatcher.executorService.shutdown()}
    }

    private fun safeJournal(store:Store):String {
        val events=store.read().optJSONArray("eventLog") ?: return "no_events"
        return (0 until events.length()).joinToString(" | "){i->
            val event=events.optJSONObject(i)
            val code=event?.optString("code").orEmpty()
            val error=event?.optString("error").orEmpty()
            // Even if a future event schema changes, no free-form value may
            // enter test XML/logcat artifacts alongside real credentials.
            val safeCode=code.takeIf{it.matches(Regex("awg_[a-z0-9_]+"))} ?: "other"
            val safeError=error.takeIf{it.matches(Regex("awg_[a-z_]+"))}.orEmpty()
            "$safeCode:$safeError"
        }
    }
}
