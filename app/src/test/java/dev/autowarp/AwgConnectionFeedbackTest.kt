package dev.autowarp

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AwgConnectionFeedbackTest {
    @Test fun onlyPublicEndpointFieldIsDisplayed(){
        val quick="[Interface]\nPrivateKey = synthetic-secret\n[Peer]\n"+
            "PublicKey = other-synthetic-secret\nEndpoint = engage.cloudflareclient.com:2408 # note\n"
        assertEquals("engage.cloudflareclient.com:2408",awgConfiguredEndpoint(quick))
        assertEquals("162.159.193.1:500",awgConfiguredEndpoint("Endpoint=162.159.193.1:500"))
        assertEquals("[2606:4700::1]:2408",awgConfiguredEndpoint("Endpoint=[2606:4700::1]:2408"))
    }
    @Test fun malformedOrAmbiguousEndpointNeverFallsBackToRawConfig(){
        for(quick in listOf("PrivateKey = synthetic-secret","Endpoint = host:0",
            "Endpoint = host:65536","Endpoint = host:2408 private-key",
            "Endpoint = user@host:2408","Endpoint = host:2408\nEndpoint = other:500")){
            assertNull(awgConfiguredEndpoint(quick))
        }
    }
    @Test fun manualCheckHasVisibleStartSuccessAndFailure(){
        fun event(code:String)=JSONObject().put("code",code)
        assertTrue(eventText(event("awg_vpn_check_start")).contains("проверяем"))
        val ok=eventText(event("awg_vpn_check_ok").put("ms",291))
        assertTrue(ok.contains("HTTPS и WARP подтверждены"))
        assertTrue(ok.contains("291 мс"))
        val failed=eventText(event("awg_vpn_check_failed").put("error","awg_vpn_tcp_timeout"))
        assertTrue(failed.contains("не прошла"))
        assertTrue(failed.contains("таймаут"))
        assertFalse(eventText(event("awg_vpn_check_failed").put("error","synthetic-secret")).contains("synthetic-secret"))
    }
}
