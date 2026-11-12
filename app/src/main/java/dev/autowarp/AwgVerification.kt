package dev.autowarp

import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

internal enum class AwgVerifyStage(val wire:String) { TCP("tcp"), TLS("tls"), HTTP("http"), TRACE("http") }
internal class AwgVerifyFailure(val code:String,val stage:AwgVerifyStage):Exception(code)

/** The most advanced failed stage is more informative than a later TCP retry. */
internal fun awgDeeperFailure(old:AwgVerifyFailure?,next:AwgVerifyFailure):AwgVerifyFailure =
    if(old==null || next.stage.ordinal>=old.stage.ordinal)next else old

internal fun awgVerifyFailure(stage:AwgVerifyStage,error:Exception):AwgVerifyFailure {
    val certificate=generateSequence<Throwable>(error){it.cause}.take(16)
        .any { it is CertificateException || it is SSLPeerUnverifiedException }
    val code=when {
        certificate -> "awg_vpn_tls_certificate"
        error is SocketTimeoutException -> "awg_vpn_${stage.wire}_timeout"
        error is SSLException -> "awg_vpn_tls_failed"
        else -> "awg_vpn_${stage.wire}_failed"
    }
    return AwgVerifyFailure(code,if(certificate || error is SSLException)AwgVerifyStage.TLS else stage)
}

/** Only OkHttp's TLS/HTTP implementation changes; endpoint and deadlines stay fixed. */
internal fun awgVerificationClient(factory:SocketFactory,onStage:(AwgVerifyStage)->Unit):OkHttpClient =
    OkHttpClient.Builder()
        .socketFactory(factory)
        .dns(object:Dns {
            override fun lookup(hostname:String):List<InetAddress> {
                if(hostname!="one.one.one.one")throw java.net.UnknownHostException()
                return listOf(InetAddress.getByAddress(byteArrayOf(1,1,1,1)))
            }
        })
        .proxy(Proxy.NO_PROXY)
        .protocols(listOf(Protocol.HTTP_1_1))
        .connectTimeout(6500,TimeUnit.MILLISECONDS)
        .readTimeout(6500,TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(false)
        .followRedirects(false).followSslRedirects(false)
        .connectionPool(ConnectionPool(0,1,TimeUnit.SECONDS))
        .eventListener(object:EventListener(){
            override fun secureConnectStart(call:Call){onStage(AwgVerifyStage.TLS)}
            override fun secureConnectEnd(call:Call,handshake:Handshake?){onStage(AwgVerifyStage.HTTP)}
        })
        .build()

/** Reserve/register the actual socket port before OkHttp calls connect(). */
internal class AwgDiagnosticSocketFactory(
    private val delegate:SocketFactory,
    private val register:(Int)->Unit
):SocketFactory(){
    private fun reserve(local:InetAddress?=null,port:Int=0):Socket {
        val socket=delegate.createSocket()
        try {
            socket.bind(InetSocketAddress(local ?: InetAddress.getByAddress(byteArrayOf(0,0,0,0)),port))
            register(socket.localPort)
            return socket
        }catch(e:Exception){runCatching{socket.close()};throw e}
    }
    override fun createSocket():Socket=reserve()
    private fun connected(host:InetAddress,port:Int,local:InetAddress?=null,localPort:Int=0):Socket {
        val socket=reserve(local,localPort)
        try{socket.connect(InetSocketAddress(host,port),6500);return socket}
        catch(e:Exception){runCatching{socket.close()};throw e}
    }
    override fun createSocket(host:String,port:Int):Socket=connected(InetAddress.getByName(host),port)
    override fun createSocket(host:InetAddress,port:Int):Socket=connected(host,port)
    override fun createSocket(host:String,port:Int,local:InetAddress,localPort:Int):Socket=
        connected(InetAddress.getByName(host),port,local,localPort)
    override fun createSocket(host:InetAddress,port:Int,local:InetAddress,localPort:Int):Socket=
        connected(host,port,local,localPort)
}

/** OkHttp decodes Content-Length/chunked framing; this only validates the bounded trace body. */
internal fun awgVerifiedTraceIP(response:Response):String=awgVerifiedTrace(response).ip

internal fun awgVerifiedTrace(response:Response):AwgVerifiedTrace {
    if(response.code!=200)throw AwgVerifyFailure("awg_vpn_http_failed",AwgVerifyStage.HTTP)
    val body=response.body ?: throw AwgVerifyFailure("awg_vpn_http_failed",AwgVerifyStage.HTTP)
    val out=ByteArrayOutputStream()
    body.byteStream().use { input ->
        val buffer=ByteArray(2048)
        while(true){
            val n=input.read(buffer,0,minOf(buffer.size,16385-out.size()))
            if(n<0)break
            out.write(buffer,0,n)
            if(out.size()>16384)throw AwgVerifyFailure("awg_vpn_http_failed",AwgVerifyStage.HTTP)
        }
    }
    val entries=out.toString("UTF-8").lineSequence().mapNotNull { line ->
        if('=' !in line)null else line.substringBefore('=') to line.substringAfter('=').trim()
    }.toList()
    val fields=entries.toMap()
    val ip=fields["ip"].orEmpty()
    // Only numeric input reaches InetAddress; no additional DNS lookup.
    val v4=ip.split('.').let { parts -> parts.size==4 && parts.all {
        it.isNotEmpty() && it.all { c->c in '0'..'9' } && (it.toIntOrNull() ?: -1) in 0..255
    } }
    val v6=':' in ip && ip.all { it in "0123456789abcdefABCDEF:." } &&
        runCatching{InetAddress.getByName(ip) is java.net.Inet6Address}.getOrDefault(false)
    if(!v4 && !v6)throw AwgVerifyFailure("awg_vpn_http_failed",AwgVerifyStage.TRACE)
    if(fields["warp"] !in listOf("on","plus"))
        throw AwgVerifyFailure("awg_vpn_warp_missing",AwgVerifyStage.TRACE)
    val locations=entries.filter {it.first=="loc"}
    val country=if(locations.size==1)AwgRegionPolicy.country(locations.single().second) else ""
    val nodes=entries.filter {it.first=="colo"}
    val colo=if(nodes.size==1)AwgNodePolicy.code(nodes.single().second) else ""
    return AwgVerifiedTrace(ip,country,colo)
}
