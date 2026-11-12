package dev.autowarp

import org.junit.Assert.*
import org.junit.Test

class AwgNestedResultTest {
    @Test fun countryDisagreementNeverClaimsForeignVpnWorks(){
        assertEquals("awg_nested_geo_disagree",AwgNestedResult.safe("awg_nested_geo_disagree"))
        val text=AwgNestedResult.text("awg_nested_geo_disagree")
        assertTrue(text.contains("разные страны"))
        assertTrue(text.contains("не подтверждён"))
    }
    @Test fun preparationFailuresPersistSafeActionableReasons(){
        assertEquals("awg_nested_reg_http_403",AwgNestedResult.preparationFailure(IllegalStateException("Cloudflare HTTP 403")))
        assertEquals("awg_nested_reg_http_429",AwgNestedResult.preparationFailure(IllegalStateException("Cloudflare HTTP 429")))
        assertEquals("awg_nested_reg_wait",AwgNestedResult.preparationFailure(IllegalStateException("Пауза регистрации")))
        assertEquals("awg_nested_reg_timeout",AwgNestedResult.preparationFailure(java.net.SocketTimeoutException("synthetic-secret")))
        assertEquals("awg_nested_reg_dns",AwgNestedResult.preparationFailure(java.net.UnknownHostException("synthetic-secret")))
        assertEquals("awg_nested_reg_tls",AwgNestedResult.preparationFailure(javax.net.ssl.SSLException("synthetic-secret")))
        assertEquals("awg_nested_reg_format",AwgNestedResult.preparationFailure(org.json.JSONException("synthetic-secret")))
        for(message in listOf("Cloudflare HTTP 403 synthetic-secret","Cloudflare HTTP 999","private_key=synthetic-secret")){
            val code=AwgNestedResult.preparationFailure(IllegalStateException(message))
            assertEquals("awg_nested_prepare_failed",code)
            assertFalse(AwgNestedResult.text(code).contains("synthetic-secret"))
        }
        assertTrue(AwgNestedResult.text("awg_nested_reg_http_403").contains("403"))
        assertTrue(AwgNestedResult.text("awg_nested_prepared").contains("Второй профиль готов"))
        assertTrue(AwgNestedResult.text("awg_nested_launch_blocked").contains("заблокирован"))
    }
    @Test fun outcomeCannotExposeNativeExceptionsOrConfig(){
        assertEquals("awg_nested_failed",AwgNestedResult.safe("private_key=synthetic-secret"))
        assertFalse(AwgNestedResult.text("synthetic-secret").contains("synthetic-secret"))
        assertTrue(AwgNestedResult.text("awg_nested_verified").contains("не системный VPN"))
        assertTrue(AwgNestedResult.text("awg_nested_region_ru").contains("осталась РФ"))
    }
    @Test fun exitIpMetadataIsNumericAndNeverResolvedAsHostname(){
        assertEquals("203.0.113.9",AwgNestedResult.numericIP("203.0.113.9"))
        assertEquals("2001:db8::1",AwgNestedResult.numericIP("2001:db8::1"))
        for(value in listOf("","deadbeef","localhost","203.0.113.999","203.0.113.9\nsecret","1.2.3")){
            assertEquals("",AwgNestedResult.numericIP(value))
        }
    }
}
