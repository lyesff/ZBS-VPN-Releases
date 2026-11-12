package dev.autowarp

import io.nekohasekai.awglab.DNSExchanger
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.Closeable
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.Proxy
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory

/** DNS messages travel over HTTPS sockets bound to the VPN, never protected
 * physical sockets. Only the upstream hostname is bootstrapped before TUN. */
internal class AwgDohClient(
    private val url:HttpUrl,
    bootstrap:List<InetAddress>,
    socketFactory:SocketFactory,
    builder:OkHttpClient.Builder=OkHttpClient.Builder(),
    private val failed:()->Unit={}
):DNSExchanger,Closeable {
    private val closed=AtomicBoolean(false)
    private val addresses=bootstrap.toList().also {require(it.isNotEmpty())}
    private val client=builder
        .proxy(Proxy.NO_PROXY).socketFactory(socketFactory)
        .dns(object:Dns {
            override fun lookup(hostname:String):List<InetAddress> {
                if(!hostname.equals(url.host,true))throw UnknownHostException("doh_host")
                return addresses
            }
        })
        .followRedirects(false).followSslRedirects(false)
        .connectTimeout(5,TimeUnit.SECONDS).readTimeout(6,TimeUnit.SECONDS)
        .callTimeout(8,TimeUnit.SECONDS).build()

    override fun exchange(query:ByteArray):ByteArray {
        if(closed.get() || query.size !in 12..4096)return byteArrayOf()
        return try {
            val request=Request.Builder().url(url)
                .header("Accept","application/dns-message")
                .header("Cache-Control","no-store")
                .post(query.toRequestBody("application/dns-message".toMediaType())).build()
            client.newCall(request).execute().use {response->
                check(response.isSuccessful)
                val body=checkNotNull(response.body)
                check(body.contentType()?.let{it.type=="application" && it.subtype=="dns-message"}==true)
                check(body.contentLength()<=65535)
                val answer=body.byteStream().use{input->
                    val output=ByteArrayOutputStream()
                    val buffer=ByteArray(4096)
                    while(output.size()<=65535){
                        val count=input.read(buffer,0,minOf(buffer.size,65536-output.size()))
                        if(count<0)break
                        output.write(buffer,0,count)
                    }
                    output.toByteArray()
                }
                check(answer.size in 12..65535)
                check(answer[0]==query[0] && answer[1]==query[1] && (answer[2].toInt() and 0x80)!=0)
                answer
            }
        }catch(_:Exception){
            if(!closed.get())failed()
            byteArrayOf()
        }
    }
    override fun close(){
        if(!closed.compareAndSet(false,true))return
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
    }
}
