package dev.autowarp

import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.MediaType
import org.junit.Assert.*
import org.junit.Test

class AwgRegionPolicyTest {
    private fun trace(body:String):AwgVerifiedTrace {
        val response=Response.Builder().request(Request.Builder().url("https://one.one.one.one/").build())
            .protocol(Protocol.HTTP_1_1).code(200).message("OK")
            .body(ResponseBody.create(null as MediaType?,body)).build()
        return response.use {awgVerifiedTrace(it)}
    }
    @Test fun preservesHttpsWarpValidationWhileExtractingCountry(){
        assertEquals(AwgVerifiedTrace("203.0.113.9","DE"),trace("ip=203.0.113.9\nwarp=on\nloc=DE\n"))
        assertEquals("RU",trace("ip=203.0.113.9\nwarp=plus\nloc=ru\n").country)
        for(body in listOf("ip=203.0.113.9\nwarp=off\nloc=DE\n","ip=invalid\nwarp=on\nloc=DE\n")){
            assertTrue(runCatching{trace(body)}.exceptionOrNull() is AwgVerifyFailure)
        }
    }
    @Test fun missingInvalidAndDuplicateCountryStayUnknown(){
        for(extra in listOf("","loc=XX\n","loc=ZZ\n","loc=synthetic-secret\n","loc=RU\nloc=DE\n")){
            assertEquals("",trace("ip=203.0.113.9\nwarp=on\n"+extra).country)
        }
    }
    @Test fun optInPolicyRejectsRussiaAndUnknownWithoutRetryingSameRoute(){
        for(code in listOf("RU","ru")){
            val failure=runCatching{AwgRegionPolicy.enforce(code,true)}.exceptionOrNull() as AwgVerifyFailure
            assertEquals("awg_vpn_region_ru",failure.code)
            assertTrue(AwgRegionPolicy.rejection(failure.code))
            assertEquals(Reason.REGION_RU,AwgRegionPolicy.reason(failure.code))
        }
        for(code in listOf("","XX","ZZ","invalid")){
            val failure=runCatching{AwgRegionPolicy.enforce(code,true)}.exceptionOrNull() as AwgVerifyFailure
            assertEquals("awg_vpn_region_unknown",failure.code)
        }
        AwgRegionPolicy.enforce("DE",true)
        AwgRegionPolicy.enforce("US",true) // Excluding Russia does not imply Europe.
        AwgRegionPolicy.enforce("RU",false)
        AwgRegionPolicy.enforce("",false)
    }
    @Test fun rejectionCannotBeReplacedByLateConnectedOrTrafficUpdate(){
        val session=VpnSession{}
        session.update(Live(Phase.CONNECTING,Reason.START))
        val connected=Live(Phase.CONNECTED,Reason.ONLINE,ip="203.0.113.9",ms=1,start=1,country="RU")
        session.update(connected)
        session.beginStop(Reason.REGION_RU)
        assertFalse(session.update(connected.copy(up=500,down=1000)))
        session.finish(Reason.REGION_RU)
        assertEquals(Phase.ERROR,session.value.phase)
        assertEquals(Reason.REGION_RU,session.value.reason)
    }
}
