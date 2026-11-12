package dev.autowarp

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AwgVerificationJournalTest {
    @Test fun appOnlySuccessIsShownAsACompletedApplicationTest(){
        val text=eventText(JSONObject().put("code","awg_vpn_app_only_verified"))
        assertTrue(text.contains("для AutoWARP"))
        assertTrue(text.contains("проверочный VPN отключается"))
        assertNotEquals(eventText(JSONObject().put("code","awg_vpn_verified")),text)
    }

    @Test fun goControlDoesNotClaimSystemVPNIsConnected(){
        val event=JSONObject().put("code","awg_vpn_go_before").put("error","awg_control_verified")
        val text=eventText(event)
        assertTrue(text.contains("Контроль Go TLS"))
        assertTrue(text.contains("до проверки"))
        assertTrue(text.contains("не статус VPN"))
        assertFalse(text.contains("AWG VPN: HTTPS и WARP подтверждены"))
    }
    @Test fun goControlAfterFailureDistinguishesTLSFromTCP(){
        val event=JSONObject().put("code","awg_vpn_go_after").put("error","awg_control_tls_timeout")
        val text=eventText(event)
        assertTrue(text.contains("после сбоя"))
        assertTrue(text.contains("TCP есть"))
        assertTrue(text.contains("TLS"))
    }

    @Test fun individualFailureDoesNotClaimTunnelWasStopped(){
        val event=JSONObject().put("code","awg_vpn_verify_attempt").put("index",1)
            .put("error","awg_vpn_tls_timeout")
        val text=eventText(event)
        assertTrue(text.contains("#1"))
        assertTrue(text.contains("TCP подключён"))
        assertTrue(text.contains("TLS"))
        assertFalse(text.contains("туннель остановлен"))
    }
    @Test fun finalTlsFailureIsNotReportedAsTcpTimeout(){
        val event=JSONObject().put("code","awg_vpn_failed").put("error","awg_vpn_tls_timeout")
        val text=eventText(event)
        assertTrue(text.contains("TCP подключён"))
        assertTrue(text.contains("туннель остановлен"))
        assertFalse(text.contains("таймаут подключения TCP"))
    }
}
