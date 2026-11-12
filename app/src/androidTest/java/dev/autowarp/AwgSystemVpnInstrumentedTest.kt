package dev.autowarp

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.nekohasekai.awglab.Awglab
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.FixMethodOrder
import org.junit.Assume.assumeTrue
import org.junit.runners.MethodSorters
import org.junit.runner.RunWith

/** Exercises the actual production service on Android. No user profile is used. */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class AwgSystemVpnInstrumentedTest {
    @Test fun aGomobileOutcomeMarshalling(){
        // Exercises the actual generated JNI/cgo string+error return frame.
        // Invalid input never creates a socket or handles user credentials.
        // Stress is regression coverage, not a deterministic crash reproducer.
        repeat(4096){
            assertEquals("awg_invalid_file",Awglab.probeWarp("invalid"))
        }
    }
    @Test fun aMockVpnServiceReachesRealTLSAndHTTP(){
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        val cm=context.getSystemService(ConnectivityManager::class.java)
        assertFalse("Unexpected pre-existing VPN in clean emulator",cm.allNetworks.any{
            cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
        })
        val quick=instrumentation.context.assets.open("awg-ci.conf").bufferedReader().use{it.readText()}
        assertTrue("Synthetic fixture rejected",Awglab.validateQuickFile(quick))
        // The host peer relays to real public HTTPS. warp=off is expected and
        // deliberately must NOT be treated as a working WARP VPN.
        val baseline=Awglab.probeWarp(quick)
        assertTrue("Mock AWG baseline did not complete HTTPS: $baseline",
            baseline=="awg_not_confirmed" || baseline.startsWith("awg_verified:"))
        println("Mock AWG baseline reached public HTTPS; this is not WARP proof")
        val store=Store.get(context)
        store.saveAWG(quick)
        store.clearEvents()
        // connectedDebugAndroidTest installs the target APK after workflow setup.
        // Grant consent only after that installation, using the instrumentation
        // shell on the disposable emulator. Production permission flow is unchanged.
        assertEquals("Unexpected CI target package","dev.autowarp",context.packageName)
        val consentOutput=ParcelFileDescriptor.AutoCloseInputStream(
            instrumentation.uiAutomation.executeShellCommand(
                "appops set dev.autowarp ACTIVATE_VPN allow"
            )
        ).bufferedReader().use{it.readText()}
        assertTrue("CI VPN authorization command failed: $consentOutput",consentOutput.isBlank())
        assertNull("CI VPN authorization was not applied",VpnService.prepare(context))
        ActivityScenario.launch(MainActivity::class.java).use {scenario ->
            try {
                scenario.onActivity{AwgTunnel.start(it)}
                val deadline=SystemClock.elapsedRealtime()+90000
                var preflight=false
                var transportReused=false
                var sessionReused=false
                var postTUN=false
                var postUDP=false
                var goControl=false
                var tls=false
                var http=false
                var stopped=false
                var firstFailure:String?=null
                var firstFlow:String?=null
                var firstData:String?=null
                var verified=false
                while(SystemClock.elapsedRealtime()<deadline){
                    val events=store.read().optJSONArray("eventLog")
                    if(events!=null)for(i in 0 until events.length()){
                        val event=events.optJSONObject(i) ?: continue
                        val code=event.optString("code")
                        val error=event.optString("error")
                        if(code=="awg_vpn_udp_reused")transportReused=true
                        if(code=="awg_vpn_session_reused")sessionReused=true
                        if(code=="awg_vpn_post_tun" && error=="awg_not_confirmed")postTUN=true
                        if(code=="awg_vpn_post_tun_udp" && error=="awg_post_udp_bidirectional")postUDP=true
                        if(code=="awg_vpn_transport_preflight" && error=="awg_not_confirmed")preflight=true
                        if(code=="awg_vpn_go_before" && error=="awg_control_not_warp")goControl=true
                        if(code=="awg_vpn_tls_ready")tls=true
                        if(code=="awg_vpn_verify_attempt" && event.optInt("index")==1)firstFailure=error
                        if(code=="awg_vpn_tcp_bound" && firstFlow==null)firstFlow=error
                        if(code=="awg_vpn_tcp_data" && firstData==null)firstData=error
                        if(code=="awg_vpn_verified")verified=true
                        http=verified || firstFailure=="awg_vpn_warp_missing"
                        if(code=="awg_vpn_failed" || code=="awg_vpn_verified")stopped=true
                    }
                    val correlated=verified || firstFlow=="awg_tcp_android_ack" && firstData=="awg_data_server_data"
                    if(stopped || tls && http && correlated)break
                    SystemClock.sleep(250)
                }
                val journal=safeJournal(store)
                println("CI synthetic-AWG service journal: $journal")
                assertTrue("System VPN did not hand off its preflight socket. $journal",transportReused)
                assertTrue("System VPN restarted the checked AWG session. $journal",sessionReused)
                assertTrue("Same netstack did not finish HTTPS after VPN route activation. $journal",postTUN)
                assertTrue("Post-TUN control did not exchange UDP. $journal",postUDP)
                val recorded=store.read().optJSONArray("eventLog")
                val binds=if(recorded==null)0 else (0 until recorded.length()).count {
                    recorded.optJSONObject(it)?.optString("code")=="awg_vpn_udp_bound"
                }
                assertEquals("UDP must be bound/protected once before TUN",1,binds)
                assertTrue("Protected UDP preflight did not finish HTTPS before TUN. $journal",preflight)
                assertTrue("Go TLS control did not finish HTTPS through the same mock TUN. $journal",goControl)
                assertTrue("Production Android VpnService did not finish TLS. $journal",tls)
                assertTrue("Production Android VpnService did not validate the HTTP trace. $journal",http)
                assertTrue("HTTPS was not correlated with data through this TUN. $journal",
                    verified || firstFlow=="awg_tcp_android_ack" && firstData=="awg_data_server_data")
                println("Android VpnService -> AWG -> public TLS/HTTP succeeded; real WARP remains untested")
            }finally{Tunnel.cmd(context,"STOP")}
        }
    }
    @Test fun bRealWarpUsesSameProfileForProbeAndSystemVPN(){
        // The real backend is an explicitly enabled network investigation,
        // not a prerequisite for running the deterministic mock locally.
        assumeTrue("Real WARP scenario is disabled",
            InstrumentationRegistry.getArguments().getString("autowarpRealWarp")=="true")
        RealWarpScenario.run()
    }
    private fun safeJournal(store:Store):String {
        // Never dump Store.read(): it contains the synthetic quick-config and
        // would contain real credentials outside this clean CI installation.
        val events=store.read().optJSONArray("eventLog") ?: return "no events"
        return (0 until events.length()).joinToString(" | "){i ->
            val event=events.optJSONObject(i) ?: JSONObject()
            event.optString("code")+":"+event.optString("error")
        }
    }
}
