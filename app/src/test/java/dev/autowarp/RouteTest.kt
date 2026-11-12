package dev.autowarp

import org.junit.Test
import org.junit.Assert.*
import java.net.InetAddress
import java.util.Base64
import java.io.File

class RouteTest {
    @Test fun allowedTargets(){
        for(ip in listOf("127.0.0.1","169.254.169.254","100.64.4.2","192.168.0.1","::1","fe80::2","2002:7f00::1"))assertFalse(publicIP(InetAddress.getByName(ip)))
        assertTrue(publicIP(InetAddress.getByName("1.1.1.1")))
    }
    @Test fun protectedChains(){
        val key=Base64.getEncoder().encodeToString(ByteArray(32){(it+1).toByte()})
        val peer=obj("address" to "162.159.193.1","port" to 2408,"public_key" to key,"allowed_ips" to arr("0.0.0.0/0","::/0"))
        val wg=obj("type" to "wireguard","address" to arr("10.77.0.2/32"),"private_key" to key,"peers" to arr(peer))
        val v=obj("type" to "vless","server" to "198.41.192.1","server_port" to 443,"uuid" to "42e17584-457e-49ec-a916-c5a426b2bbac","tls" to obj("enabled" to true,"server_name" to "example.com"))
        val s=obj("warp" to "w","wg" to obj("w" to obj("config" to wg,"id" to "w","name" to "WARP")),"sources" to obj("one" to obj("items" to arr(obj("name" to "one","config" to v,"id" to "v")))))
        for((i,mode) in modes.withIndex()){
            val p=plan(s.put("mode",mode)){arrayOf(InetAddress.getByName(it))}
            val j=org.json.JSONObject(p.json)
            assertEquals("vpn",j.getJSONObject("route").getString("final"))
            assertFalse(p.json.contains("\"direct\""))
            assertTrue(p.routes.isNotEmpty())
            if(i==3)assertTrue(j.getJSONArray("outbounds").getJSONObject(1).has("detour"))
            if(i==4)assertTrue(j.getJSONArray("endpoints").getJSONObject(0).has("detour"))
            System.getProperty("autowarp.fixtures")?.let { File(it,"mode-$i.json").writeText(p.json) }
        }
    }
}
