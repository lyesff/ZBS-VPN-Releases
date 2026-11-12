package dev.autowarp

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AwgDnsPolicyTest {
    @Test fun defaultsToExistingDNSAndPreservesProfiles(){
        val s=JSONObject().put("awgQuick","synthetic-profile")
        assertNull(AwgDnsPolicy.selected(s))
        s.put("awgDohProvider","bezmezhau")
        assertEquals("https://dns.bezmezhau.com/dns-query",AwgDnsPolicy.selected(s)?.url)
        assertEquals("synthetic-profile",s.getString("awgQuick"))
    }
    @Test fun validatesCustomEndpointsAndKeepsQueryTokensOutOfLabels(){
        for(url in listOf("http://dns.example/dns-query","https://user:pass@dns.example/dns-query",
            "https://dns.example/dns-query#fragment","https://dns.example/"," https://dns.example/dns-query")){
            assertNull(url,AwgDnsPolicy.customUrl(url))
        }
        val url="https://dns.example:444/dns-query?token=synthetic"
        assertNotNull(AwgDnsPolicy.customUrl(url))
        val s=JSONObject().put("awgDohProvider","custom").put("awgDohCustom",url)
        assertEquals(url,AwgDnsPolicy.selected(s)?.url)
        assertEquals("Свой DoH",AwgDnsPolicy.label(s))
    }
    @Test fun invalidSavedSelectionDoesNotSilentlyFallBack(){
        try{AwgDnsPolicy.selected(JSONObject().put("awgDohProvider","missing"));fail("accepted unknown provider")}
        catch(_:IllegalStateException){}
    }
}
