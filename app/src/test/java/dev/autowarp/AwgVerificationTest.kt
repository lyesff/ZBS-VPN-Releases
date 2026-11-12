package dev.autowarp

import okhttp3.Dns
import okhttp3.Request
import okhttp3.Response
import okhttp3.Protocol
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import javax.net.SocketFactory
import javax.net.ssl.SSLHandshakeException

class AwgVerificationTest {
    @Test fun laterTcpTimeoutCannotHideEarlierTlsFailure(){
        val tls=AwgVerifyFailure("awg_vpn_tls_timeout",AwgVerifyStage.TLS)
        val tcp=AwgVerifyFailure("awg_vpn_tcp_timeout",AwgVerifyStage.TCP)
        assertSame(tls,awgDeeperFailure(tls,tcp))
        val http=AwgVerifyFailure("awg_vpn_http_failed",AwgVerifyStage.HTTP)
        assertSame(http,awgDeeperFailure(tls,http))
    }
    @Test fun stageAndCertificateErrorsAreClassifiedWithoutExceptionText(){
        assertEquals("awg_vpn_tls_timeout",awgVerifyFailure(AwgVerifyStage.TLS,SocketTimeoutException()).code)
        assertEquals("awg_vpn_http_timeout",awgVerifyFailure(AwgVerifyStage.HTTP,SocketTimeoutException()).code)
        val error=SSLHandshakeException("sensitive details").apply{initCause(CertificateException("private"))}
        assertEquals("awg_vpn_tls_certificate",awgVerifyFailure(AwgVerifyStage.TLS,error).code)
    }
    @Test fun tlsSniChunkedKeepAliveAndSocketRegistration(){
        val certificate=HeldCertificate.Builder().addSubjectAlternativeName("one.one.one.one").build()
        val serverTLS=HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val clientTLS=HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        val server=MockWebServer()
        server.useHttps(serverTLS.sslSocketFactory(),false)
        // Chunked body must be decoded; the client need not wait for connection EOF.
        server.enqueue(MockResponse().setChunkedBody("ip=203.0.113.10\nwarp=on\n",3))
        server.start()
        val stages=mutableListOf<AwgVerifyStage>()
        var registeredPort=0
        val factory=AwgDiagnosticSocketFactory(SocketFactory.getDefault()){registeredPort=it}
        val client=awgVerificationClient(factory){stages.add(it)}.newBuilder()
            .sslSocketFactory(clientTLS.sslSocketFactory(),clientTLS.trustManager)
            .dns(object:Dns {
                override fun lookup(hostname:String)=listOf(InetAddress.getLoopbackAddress())
            }).build()
        try {
            val url=server.url("/cdn-cgi/trace").newBuilder().host("one.one.one.one").build()
            client.newCall(Request.Builder().url(url).build()).execute().use {
                assertEquals("203.0.113.10",awgVerifiedTraceIP(it))
                assertEquals("one.one.one.one",it.handshake!!.peerCertificates.let {certs ->
                    (certs.first() as java.security.cert.X509Certificate).subjectAlternativeNames.first().last()
                })
            }
            assertTrue(registeredPort>0)
            assertEquals(listOf(AwgVerifyStage.TLS,AwgVerifyStage.HTTP),stages)
            val request=server.takeRequest()
            assertEquals("/cdn-cgi/trace",request.path)
        }finally{
            client.connectionPool.evictAll();client.dispatcher.executorService.shutdown();server.shutdown()
        }
    }
    @Test fun hostnameVerificationIsRequired(){
        val cert=HeldCertificate.Builder().addSubjectAlternativeName("different.example").build()
        val serverTLS=HandshakeCertificates.Builder().heldCertificate(cert).build()
        val trusted=HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        val server=MockWebServer();server.useHttps(serverTLS.sslSocketFactory(),false);server.start()
        var stage=AwgVerifyStage.TCP
        val client=awgVerificationClient(SocketFactory.getDefault()){stage=it}.newBuilder()
            .sslSocketFactory(trusted.sslSocketFactory(),trusted.trustManager)
            .dns(object:Dns {
                override fun lookup(hostname:String)=listOf(InetAddress.getLoopbackAddress())
            }).build()
        try {
            val url=server.url("/").newBuilder().host("one.one.one.one").build()
            val error=runCatching{client.newCall(Request.Builder().url(url).build()).execute().close()}.exceptionOrNull()
            assertNotNull(error)
            assertEquals("awg_vpn_tls_certificate",awgVerifyFailure(stage,error as Exception).code)
        }finally{client.connectionPool.evictAll();client.dispatcher.executorService.shutdown();server.shutdown()}
    }
    @Test fun traceRequiresWarpAndNumericIpAndRejectsOversizedBody(){
        fun check(body:String):String {
            val response=Response.Builder().request(Request.Builder().url("https://one.one.one.one/").build())
                .protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(okhttp3.ResponseBody.create(null as okhttp3.MediaType?,body)).build()
            return response.use {awgVerifiedTraceIP(it)}
        }
        assertEquals("203.0.113.10",check("ip=203.0.113.10\nwarp=plus\n"))
        for(body in listOf("ip=hostname.example\nwarp=on\n","ip=203.0.113.10\nwarp=off\n","x".repeat(16385)))
            assertTrue(runCatching{check(body)}.exceptionOrNull() is AwgVerifyFailure)
    }
}
