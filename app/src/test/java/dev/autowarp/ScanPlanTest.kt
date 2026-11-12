package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

class ScanPlanTest {
    private fun sample(id:String)=JSONObject()
        .put("id",id).put("name","Sample")
        .put("config",JSONObject().put("type","vless").put("server","example.org")
            .put("server_port",443).put("uuid","00000000-0000-4000-8000-000000000001")
            .put("tls",JSONObject().put("enabled",true).put("server_name","example.org")))
    @Test fun scanHasNoTunOrVpnRoute() {
        val profiles=JSONArray().put(sample("one")).put(sample("two"))
        val state=JSONObject().put("sources",JSONObject().put("test",JSONObject().put("items",profiles)))
        val plan=scanPlan(state,{ arrayOf(InetAddress.getByName("1.1.1.1")) })
        val json=JSONObject(plan.json)
        assertFalse(json.has("inbounds"))
        assertFalse(json.has("endpoints"))
        assertEquals("direct",json.getJSONObject("route").getString("final"))
        assertEquals(2,plan.routes.size)
        assertEquals(3,json.getJSONArray("outbounds").length())
        assertEquals("v-one",plan.routes.first().tag)
    }
    @Test fun scanIsCapped() {
        val profiles=JSONArray()
        repeat(40){profiles.put(sample("node-$it"))}
        val state=JSONObject().put("sources",JSONObject().put("test",JSONObject().put("items",profiles)))
        val plan=scanPlan(state,{arrayOf(InetAddress.getByName("1.1.1.1"))},100)
        assertEquals(24,plan.routes.size)
    }
}
