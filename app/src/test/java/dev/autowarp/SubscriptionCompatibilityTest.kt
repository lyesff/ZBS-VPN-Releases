package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class SubscriptionCompatibilityTest {
    @Test fun detectsProviderPlaceholderWithoutTreatingTelegramAsDecoy(){
        val profiles=JSONArray()
            .put(JSONObject().put("name","✅ Доступ в Telegram"))
            .put(JSONObject().put("name","❌ Приложение не поддерживается"))
            .put(JSONObject().put("name","Germany #54"))
        assertEquals(1,providerPlaceholders(profiles))
        assertFalse(placeholderName("Germany #54"))
    }
    @Test fun experimentalClientUsesOnlyPublicRequestMetadata(){
        val request=subscriptionRequest("https://example.org/sub/test",subscriptionClients[1])
        assertEquals("Happ/3.13.0",request.header("User-Agent"))
        assertEquals("Android",request.header("X-Device-Os"))
        assertNull(request.header("X-Hwid"))
        assertNull(request.header("Authorization"))
    }
    @Test fun defaultClientDoesNotImpersonateOtherApp(){
        val request=subscriptionRequest("https://example.org/sub/test",subscriptionClients[0])
        assertEquals("AutoWARP/0.1.6",request.header("User-Agent"))
        assertNull(request.header("X-Device-Os"))
    }

    @Test fun subscriptionMetadataDetectsMixedLinksWithoutSavingResponse(){
        val raw="vless://opaque@host:443\ntrojan://opaque@host:443\nhysteria2://opaque@host:443"
        val d=subscriptionShape(raw)
        assertEquals("uri_list",d.getString("shape"))
        assertEquals(1,d.getInt("vless"))
        assertEquals(1,d.getInt("trojan"))
        assertEquals(1,d.getInt("hy2"))
        assertFalse(d.toString().contains("opaque"))
    }
    @Test fun subscriptionMetadataDetectsClashYaml(){
        val d=subscriptionShape("proxies:\n  - name: Example\n    type: trojan")
        assertEquals("clash_yaml",d.getString("shape"))
    }

    @Test fun jsonDiagnosticCountsOutboundsWithoutCredentials(){
        val body=JSONObject().put("outbounds",JSONArray()
            .put(JSONObject().put("type","vless").put("uuid","secret-uuid"))
            .put(JSONObject().put("type","trojan").put("password","hidden"))
            .put(JSONObject().put("type","direct")))
        val d=subscriptionShape(body.toString())
        assertEquals("singbox",d.getString("jsonKind"))
        assertEquals(3,d.getInt("jsonEntries"))
        assertEquals(1,d.getInt("jsonVless"))
        assertEquals(1,d.getInt("jsonTrojan"))
        assertFalse(d.toString().contains("secret-uuid"))
        assertFalse(d.toString().contains("hidden"))
    }
    @Test fun jsonDiagnosticRecognizesProviderMessage(){
        val d=subscriptionShape(JSONObject().put("message","Unsupported application").toString())
        assertEquals("provider_message",d.getString("jsonKind"))
        assertEquals(0,d.getInt("jsonEntries"))
        assertFalse(d.toString().contains("Unsupported application"))
    }
    @Test fun jsonSchemaHintsNeverExposeCredentialValues(){
        val body=JSONArray().put(JSONObject().put("protocol","vless")
            .put("streamSettings",JSONObject().put("network","tcp"))
            .put("settings",JSONObject().put("id","private-secret"))
            .put("unexpected-secret-key","private-secret"))
        val d=subscriptionShape(body.toString())
        assertEquals("xray_like",d.getString("entryFormat"))
        assertTrue(d.getJSONArray("knownFields").toString().contains("streamSettings"))
        assertFalse(d.toString().contains("private-secret"))
        assertFalse(d.toString().contains("unexpected-secret-key"))
    }

    @Test fun nestedOutboundsDiagnosticIsShapeOnly(){
        val payload=JSONArray()
            .put(JSONObject().put("remarks","first").put("outbounds",
                JSONArray().put(JSONObject().put("type","vless").put("server","private.example").put("uuid","private-uuid"))))
            .put(JSONObject().put("remarks","second").put("outbounds","super-private-token"))
            .put(JSONObject().put("remarks","third").put("outbounds",
                JSONObject().put("protocol","trojan").put("password","private-password")))
        val d=subscriptionShape(payload.toString())
        val shape=d.getJSONObject("outboundsTypes")
        assertEquals(1,shape.getInt("array"))
        assertEquals(1,shape.getInt("object"))
        assertEquals(1,shape.getInt("string"))
        val fields=d.getJSONArray("nestedOutboundFields").toString()
        assertTrue(fields.contains("type"))
        assertTrue(fields.contains("protocol"))
        assertFalse(d.toString().contains("private.example"))
        assertFalse(d.toString().contains("private-uuid"))
        assertFalse(d.toString().contains("private-password"))
        assertFalse(d.toString().contains("super-private-token"))
    }

    @Test fun nestedOutboundsCountsProtocolsWithoutReturningSecrets() {
        val raw=JSONArray().put(JSONObject().put("remarks","example")
            .put("outbounds",JSONArray()
                .put(JSONObject().put("type","vless").put("uuid","sensitive-uuid"))
                .put(JSONObject().put("type","trojan").put("password","sensitive-password"))))
        val d=subscriptionShape(raw.toString())
        assertEquals(1,d.getInt("nestedVless"))
        assertEquals(1,d.getInt("nestedTrojan"))
        assertEquals(0,d.getInt("nestedOther"))
        assertFalse(d.toString().contains("sensitive-uuid"))
        assertFalse(d.toString().contains("sensitive-password"))
    }

    @Test fun xrayOutboundProtocolsAreCountedWithoutSecrets(){
        val root=JSONArray().put(JSONObject().put("remarks","group")
            .put("outbounds",JSONArray()
                .put(JSONObject().put("protocol","vless").put("settings",JSONObject().put("token","sensitive")))
                .put(JSONObject().put("protocol","trojan").put("settings",JSONObject().put("password","secret")))
                .put(JSONObject().put("protocol","freedom"))))
        val metadata=subscriptionShape(root.toString())
        assertEquals(1,metadata.getInt("nestedVless"))
        assertEquals(1,metadata.getInt("nestedTrojan"))
        assertEquals(1,metadata.getInt("nestedOther"))
        assertFalse(metadata.toString().contains("sensitive"))
        assertFalse(metadata.toString().contains("secret"))
    }

}
