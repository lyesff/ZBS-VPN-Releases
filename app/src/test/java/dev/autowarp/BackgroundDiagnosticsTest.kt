package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BackgroundDiagnosticsTest {
    @Test fun automaticRecoveryCauseSurvivesStoragePolicyAndExport(){
        val sequence=listOf("awg_screen_off","awg_vpn_watchdog_failed","awg_screen_on",
            "awg_vpn_recovery_start","awg_vpn_start","awg_vpn_verified")
        val events=JSONArray()
        sequence.forEachIndexed{i,code->
            assertTrue("Storage must accept $code",VpnJournalPolicy.accepts(code,"WARP"))
            events.put(JSONObject().put("code",code).put("kind","WARP").put("at",1000L+i)
                .put("elapsed_ms",500L+i).put("index",2)
                .put("error",if(code=="awg_vpn_watchdog_failed")"awg_vpn_tcp_timeout" else ""))
        }
        val report=diagnosticReport(JSONObject().put("eventLog",events),"Подключено","test-version")
        val exported=report.getJSONArray("recent_events")
        assertEquals(sequence,(0 until exported.length()).map{exported.getJSONObject(it).getString("event")})
        assertEquals("awg_vpn_tcp_timeout",exported.getJSONObject(1).getString("error"))
        assertEquals(501L,exported.getJSONObject(1).getLong("elapsed_ms"))
        assertEquals("test-version",report.getString("version"))
        assertTrue(eventText(events.getJSONObject(1)).contains("таймаут"))
    }
    @Test fun exportKeepsTheCauseBeforeALongNativeStartupTrace(){
        val events=JSONArray().put(JSONObject().put("code","awg_vpn_network_changed").put("kind","WARP"))
        repeat(100){events.put(JSONObject().put("code","awg_vpn_tcp_connected").put("kind","WARP"))}
        val report=diagnosticReport(JSONObject().put("eventLog",events),"Подключено")
        assertEquals(101,report.getJSONArray("recent_events").length())
        assertEquals("awg_vpn_network_changed",report.getJSONArray("recent_events").getJSONObject(0).getString("event"))
    }
    @Test fun newDiagnosticsNeverExportUnknownCodesErrorsOrNetworkIdentifiers(){
        val secret="SECRET_SSID_HOST_OR_TOKEN"
        val state=JSONObject().put("awgQuick",secret).put("eventLog",JSONArray()
            .put(JSONObject().put("code",secret).put("kind","WARP"))
            .put(JSONObject().put("code","awg_vpn_watchdog_failed").put("kind",secret).put("error",secret)))
            .put("awgBackgroundState",JSONObject().put("network",secret).put("ssid",secret)
                .put("interactive",false).put("idle",true).put("battery_exempt",true)
                .put("power_save",false).put("notifications_allowed",false).put("sdk",37))
        assertFalse(VpnJournalPolicy.accepts(secret,"WARP"))
        assertFalse(VpnJournalPolicy.accepts("awg_screen_on",secret))
        val report=diagnosticReport(state,"Подключено")
        assertFalse(report.toString().contains(secret))
        assertTrue(report.getJSONObject("background_state").getBoolean("idle"))
        assertTrue(report.getJSONObject("background_state").getBoolean("battery_exempt"))
        assertEquals(37,report.getJSONObject("background_state").getInt("sdk"))
        assertEquals(1,report.getJSONArray("recent_events").length())
        assertEquals("",report.getJSONArray("recent_events").getJSONObject(0).getString("error"))
    }
    @Test fun allNewBackgroundSignalsHaveReadableLabels(){
        for(code in listOf("awg_screen_off","awg_screen_on","awg_idle_enter","awg_idle_exit",
            "awg_vpn_network_blocked","awg_vpn_network_suspended","awg_vpn_network_changed",
            "awg_vpn_recovery_start","awg_battery_exempt","awg_notifications_disabled")){
            assertTrue(VpnJournalPolicy.accepts(code,"WARP"))
            assertFalse(eventText(JSONObject().put("code",code)).contains(code))
        }
    }
}
