package dev.autowarp

import okhttp3.MediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import org.junit.Assert.*
import org.junit.Test

class AwgNodePolicyTest {
    private fun trace(extra:String):AwgVerifiedTrace {
        val response=Response.Builder().request(Request.Builder().url("https://one.one.one.one/").build())
            .protocol(Protocol.HTTP_1_1).code(200).message("OK")
            .body(ResponseBody.create(null as MediaType?,"ip=203.0.113.9\nwarp=on\nloc=RU\n"+extra)).build()
        return response.use {awgVerifiedTrace(it)}
    }
    @Test fun europeanNodeAndRussianGeoIpAreIndependent(){
        val metadata=trace("colo=HEL\n")
        assertEquals("RU",metadata.country)
        assertEquals("HEL",metadata.colo)
        AwgNodePolicy.enforce(metadata.colo,true)
        AwgRegionPolicy.enforce(metadata.country,false)
        assertTrue(runCatching{AwgRegionPolicy.enforce(metadata.country,true)}.isFailure)
    }
    @Test fun russianUnknownAndUnlistedNodesFailClosed(){
        for(code in listOf("DME","LED","SVX","KJA","","XYZ","H3L","HEL\nsecret")){
            val error=runCatching{AwgNodePolicy.enforce(code,true)}.exceptionOrNull() as AwgVerifyFailure
            assertEquals("awg_vpn_node_rejected",error.code)
            assertTrue(AwgRegionPolicy.rejection(error.code))
            AwgNodePolicy.enforce(code,false)
        }
        AwgNodePolicy.enforce(" fra ",true)
    }
    @Test fun duplicateAndInvalidColoCannotPass(){
        for(extra in listOf("","colo=HEL\ncolo=DME\n","colo=HEL\ncolo=HEL\n","colo=synthetic-secret\n")){
            assertEquals("",trace(extra).colo)
        }
    }
}
