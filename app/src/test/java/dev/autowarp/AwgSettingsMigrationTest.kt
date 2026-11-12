package dev.autowarp

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AwgSettingsMigrationTest {
    @Test fun retiresFiltersAndUnavailablePresetWithoutChangingProfileOrOtherDNS(){
        val profile="synthetic AWG profile with exact bytes\n"
        val s=JSONObject().put("awgQuick",profile).put("awgImported",true)
            .put("awgEuropeanNode",true).put("awgExcludeRussia",true)
            .put("awgDohProvider","webshift").put("awgDohCustom","https://dns.example/dns-query")
        AwgSettingsMigration.apply(s)
        assertFalse(s.has("awgEuropeanNode"))
        assertFalse(s.has("awgExcludeRussia"))
        assertEquals(profile,s.getString("awgQuick"))
        assertTrue(s.getBoolean("awgImported"))
        assertEquals("webshift",s.getString("awgDohProvider"))
        assertEquals("https://dns.example/dns-query",s.getString("awgDohCustom"))
        val once=s.toString()
        AwgSettingsMigration.apply(s)
        assertEquals(once,s.toString())
    }
    @Test fun removedPresetBecomesOffRatherThanAnotherThirdPartyProvider(){
        val s=JSONObject().put("awgDohProvider","zapret")
        AwgSettingsMigration.apply(s)
        assertEquals("off",s.getString("awgDohProvider"))
        assertNull(AwgDnsPolicy.selected(s))
        assertFalse(AwgDnsPolicy.providers.any{it.id=="zapret"})
        assertTrue(AwgDnsPolicy.providers.any{it.id=="xbox"})
    }
    @Test fun oldJournalEventsUseCurrentNeutralMaskName(){
        val event=JSONObject().put("code","awg_vpn_mask_router_i1").put("kind","WARP")
        val text=eventText(event)
        assertTrue(text.contains("I1"))
        assertFalse(text.contains("Zapret",ignoreCase=true))
        assertFalse(text.contains("Manager",ignoreCase=true))
    }
}
