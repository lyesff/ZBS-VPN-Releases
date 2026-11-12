package dev.autowarp

import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test

class ClashYamlAdapterTest {
    private val example="""
        mode: rule
        dns:
          enable: true
        proxies:
          - name: United Kingdom
            type: vless
            server: example.org
            port: 2083
            network: tcp
            udp: true
            uuid: 42e17584-457e-49ec-a916-c5a426b2bbac
            packet-encoding: xudp
            tls: true
            servername: ''
            client-fingerprint: firefox
            smux:
              enabled: true
              padding: true
              only-tcp: false
              protocol: smux
              statistic: false
              max-connections: 4
    """.trimIndent()

    @Test fun convertsMihomoVlessAndRetainsKeyTransportSettings() {
        val converted=ClashYamlAdapter.convert(example)
        assertNotNull(converted)
        val nodes=JSONArray(converted)
        assertEquals(1,nodes.length())
        val node=nodes.getJSONObject(0)
        assertEquals("vless",node.getString("type"))
        assertEquals("xudp",node.getString("packet_encoding"))
        assertEquals("firefox",node.getJSONObject("tls").getJSONObject("utls").getString("fingerprint"))
        val mux=node.getJSONObject("multiplex")
        assertEquals("smux",mux.getString("protocol"))
        assertTrue(mux.getBoolean("padding"))
        assertEquals(4,mux.getInt("max_connections"))
        assertFalse(node.has("dns"))
        assertFalse(node.has("tun"))
    }

    @Test fun skipsUnsafeOrUnsupportedNodesInsteadOfWeakeningSecurity() {
        assertNull(ClashYamlAdapter.convert(example.replace("tls: true","tls: false")))
        assertNull(ClashYamlAdapter.convert(example.replace("network: tcp","network: xhttp")))
        assertNull(ClashYamlAdapter.convert(example.replace("tls: true","tls: true\n    skip-cert-verify: true")))
        assertNull(ClashYamlAdapter.convert(example.replace("type: vless","type: shadowsocks")))
    }

    @Test fun rejectsNonYamlAndOversizedPayloads() {
        assertNull(ClashYamlAdapter.convert("vless://not-yaml"))
        assertNull(ClashYamlAdapter.convert("a".repeat(1_048_577)))
    }
    @Test fun diagnosesFileWithoutLeakingServerDetails() {
        val d=ClashYamlAdapter.diagnose(example)
        assertEquals("clash_yaml",d.getString("format"))
        assertEquals(1,d.getInt("proxies"))
        assertEquals(1,d.getInt("vless"))
        assertEquals(1,d.getInt("converted"))
        assertFalse(d.toString().contains("example.org"))
        assertFalse(d.toString().contains("42e17584"))
    }

    @Test fun diagnosesProviderFilesThatHaveNoEmbeddedServers() {
        val d=ClashYamlAdapter.diagnose("""
            proxy-providers:
              remote:
                type: http
                url: https://example.org/private-link
        """.trimIndent())
        assertEquals("providers_only",d.getString("format"))
        assertEquals(0,d.getInt("converted"))
        assertFalse(d.toString().contains("private-link"))
    }

    @Test fun distinguishesMalformedYamlAndUnrelatedDocumentShapes() {
        assertEquals("yaml_parse_error",ClashYamlAdapter.diagnose("proxies: [broken").getString("format"))
        assertEquals("json",ClashYamlAdapter.diagnose("{\"proxies\":[]}").getString("format"))
        assertEquals("html",ClashYamlAdapter.diagnose("<html>not a subscription</html>").getString("format"))
        assertEquals("empty",ClashYamlAdapter.diagnose("  ").getString("format"))
        assertEquals("yaml_not_mapping",ClashYamlAdapter.diagnose("- first\n- second").getString("format"))
    }

    @Test fun importsSameYamlFromWindowsEncodings() {
        for (charset in listOf(Charsets.UTF_8, Charsets.UTF_16LE, Charsets.UTF_16BE)) {
            val bom=when(charset){
                Charsets.UTF_16LE->byteArrayOf(0xFF.toByte(),0xFE.toByte())
                Charsets.UTF_16BE->byteArrayOf(0xFE.toByte(),0xFF.toByte())
                else->byteArrayOf(0xEF.toByte(),0xBB.toByte(),0xBF.toByte())
            }
            val bytes=bom+example.toByteArray(charset)
            val decoded=boundedLocalText(bytes.inputStream())
            val imported=ClashYamlAdapter.convert(decoded)
            assertNotNull("Couldn't import $charset",imported)
            assertEquals(1,JSONArray(imported).length())
        }
        val withoutBom=boundedLocalText(example.toByteArray(Charsets.UTF_16LE).inputStream())
        assertNotNull(ClashYamlAdapter.convert(withoutBom))
    }

}
