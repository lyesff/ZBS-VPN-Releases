package dev.autowarp

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class AmneziaWarpGeneratorTest {
    private fun fixture():JSONObject {
        val privateKey=Base64.getEncoder().encodeToString(ByteArray(32){(it+1).toByte()})
        val publicKey=Base64.getEncoder().encodeToString(ByteArray(32){(it+2).toByte()})
        val ini="""
            [Interface]
            PrivateKey = $privateKey
            Address = 172.16.0.2/32, 2606:4700:110:8abc::2/128
            MTU = 1280

            [Peer]
            PublicKey = $publicKey
            Endpoint = engage.cloudflareclient.com:2408
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
            Reserved = 1, 2, 3
        """.trimIndent()
        val p=JSONObject().put("id","warp-test").put("ini",ini)
          .put("config",JSONObject().put("peers",org.json.JSONArray()
            .put(JSONObject().put("address","engage.cloudflareclient.com").put("port",2408))))
        return JSONObject().put("warp","warp-test")
            .put("wg",JSONObject().put("warp-test",p))
    }

    @Test fun generatesSecureAWGFromRegisteredWARPProfile() {
        val state=fixture()
        val original=state.map("wg").getJSONObject("warp-test").getString("ini")
        val conf=AmneziaWarpGenerator.generate(state)
        assertTrue(conf.contains("Jc = 4"))
        assertTrue(conf.contains("H4 = 4"))
        assertTrue(conf.contains("RandomTrailers = on"))
        assertTrue(conf.contains("DisableCookies = on"))
        assertTrue(conf.contains("Endpoint = engage.cloudflareclient.com:2408"))
        assertTrue(conf.contains("Address = 172.16.0.2/32"))
        assertFalse(conf.contains("Reserved ="))
        assertFalse(conf.contains("I1 ="))
        assertEquals(original,state.map("wg").getJSONObject("warp-test").getString("ini"))
    }
    @Test fun honorsPinnedEndpointIfPresent() {
        val state=fixture()
        val profile=state.map("wg").getJSONObject("warp-test")
        profile.getJSONObject("config").getJSONArray("peers").getJSONObject(0)
            .put("address","162.159.193.1")
        state.put("endpoint","162.159.193.1/4500")
        assertTrue(AmneziaWarpGenerator.generate(state).contains("Endpoint = 162.159.193.1:4500"))
    }
    @Test fun rejectsMissingProfileOrInjectedEndpoint() {
        assertThrows(IllegalArgumentException::class.java){
            AmneziaWarpGenerator.generate(JSONObject())
        }
        val state=fixture().put("endpoint","1.2.3.4/4500")
        assertThrows(IllegalArgumentException::class.java){
            AmneziaWarpGenerator.generate(state)
        }
    }
}
