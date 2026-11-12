package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class WarpSelectionTest {
    private fun warp(i:Int)=Route("w-$i","WARP-$i","WARP",true)
    @Test fun startupChecksAllSixWarpEndpoints(){
        val routes=(0 until 6).map(::warp)
        val chosen=warpProbeOrder(routes,routes[0],JSONObject(),true,0)
        assertEquals(6,chosen.size)
        assertEquals(routes.toSet(),chosen.toSet())
    }
    @Test fun scanNeverProbesBeyondSixCandidates(){
        val routes=(0 until 20).map(::warp)
        assertEquals(6,warpProbeOrder(routes,routes[0],JSONObject(),true,0).size)
        assertEquals(6,warpProbeOrder(routes,routes[0],JSONObject(),false,10).size)
    }
    @Test fun knownGoodWarpCandidateIsPrioritizedButStillMustBeProbed(){
        val routes=(0 until 6).map(::warp)
        val health=JSONObject().put(routes[5].tag,JSONObject().put("at",System.currentTimeMillis()).put("ms",120))
        val candidates=warpProbeOrder(routes,routes[0],health,true,0)
        assertEquals(routes[0],candidates[0])
        assertEquals(routes[5],candidates[1])
    }
    @Test fun failuresNeverLookLikeGoodLatency(){
        val broken=JSONObject().put("history",JSONArray().put(-1).put(-1))
        assertEquals(Double.POSITIVE_INFINITY,warpHealthScore(broken,true),0.0)
        val mixed=JSONObject().put("history",JSONArray().put(-1).put(100))
        assertTrue(warpHealthScore(mixed,true)>100.0)
    }
}
