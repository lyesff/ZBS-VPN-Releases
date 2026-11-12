package dev.autowarp

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory

class AwgDohClientTest {
    private val query=byteArrayOf(0x41,0x57,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1)
    private val reply=query.copyOf().also{it[2]=0x81.toByte();it[3]=0x80.toByte()}
    private fun withClient(block:(MockWebServer,AwgDohClient,CountingFactory)->Unit){
        val cert=HeldCertificate.Builder().addSubjectAlternativeName("doh.invalid").build()
        val serverTLS=HandshakeCertificates.Builder().heldCertificate(cert).build()
        val trust=HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        MockWebServer().use {server->
            server.useHttps(serverTLS.sslSocketFactory(),false);server.start()
            val url=server.url("/dns-query").newBuilder().host("doh.invalid").build()
            val factory=CountingFactory()
            AwgDohClient(url,listOf(InetAddress.getByName("127.0.0.1")),factory,
                OkHttpClient.Builder().sslSocketFactory(trust.sslSocketFactory(),trust.trustManager)).use{client->
                block(server,client,factory)
            }
        }
    }
    @Test fun usesInjectedVPNFactoryBootstrapAndWirePOST(){withClient{server,client,factory->
        server.enqueue(MockResponse().setHeader("Content-Type","application/dns-message").setBody(Buffer().write(reply)))
        assertArrayEquals(reply,client.exchange(query))
        val request=server.takeRequest()
        assertEquals("POST",request.method)
        assertEquals("/dns-query",request.path)
        assertEquals("application/dns-message",request.getHeader("Content-Type"))
        assertArrayEquals(query,request.body.readByteArray())
        assertTrue(factory.calls>0)
    }}
    @Test fun refusesRedirectsMalformedAndOversizedResponsesWithoutFallback(){withClient{server,client,_->
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location","https://other.invalid/dns-query"))
        assertEquals(0,client.exchange(query).size)
        server.enqueue(MockResponse().setHeader("Content-Type","text/html").setBody("not DNS"))
        assertEquals(0,client.exchange(query).size)
        server.enqueue(MockResponse().setHeader("Content-Type","application/dns-message").setBody(Buffer().write(reply.copyOf().also{it[0]=0})))
        assertEquals(0,client.exchange(query).size)
        server.enqueue(MockResponse().setHeader("Content-Type","application/dns-message").setBody(Buffer().write(ByteArray(65536))))
        assertEquals(0,client.exchange(query).size)
        assertEquals(4,server.requestCount)
        client.close()
        assertEquals(0,client.exchange(query).size)
        assertEquals(4,server.requestCount)
    }}
    private class CountingFactory:SocketFactory(){
        var calls=0
        private val delegate=SocketFactory.getDefault()
        override fun createSocket():Socket{calls++;return delegate.createSocket()}
        override fun createSocket(host:String,port:Int):Socket=delegate.createSocket(host,port)
        override fun createSocket(host:String,port:Int,local:InetAddress,localPort:Int):Socket=delegate.createSocket(host,port,local,localPort)
        override fun createSocket(host:InetAddress,port:Int):Socket=delegate.createSocket(host,port)
        override fun createSocket(host:InetAddress,port:Int,local:InetAddress,localPort:Int):Socket=delegate.createSocket(host,port,local,localPort)
    }
}
