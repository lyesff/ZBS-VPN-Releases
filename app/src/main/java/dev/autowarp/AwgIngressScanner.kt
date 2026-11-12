package dev.autowarp

import android.net.Network
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetAddress
import java.net.Proxy
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/** Physical HTTPS ranking is only a hint; real AWG + Android verification follows. */
internal object AwgIngressScanner {
    fun rank(network:Network,stopped:()->Boolean):List<String> {
        val pool=Executors.newFixedThreadPool(8)
        val base=OkHttpClient.Builder().socketFactory(network.socketFactory)
            .proxy(Proxy.NO_PROXY).followRedirects(false).followSslRedirects(false)
            .retryOnConnectionFailure(false).connectTimeout(2,TimeUnit.SECONDS)
            .readTimeout(2,TimeUnit.SECONDS).callTimeout(2500,TimeUnit.MILLISECONDS).build()
        // Four samples in every range used by the router's picker, rather than
        // spending full AWG handshakes on eight unranked IPs from a narrow pool.
        val addresses=AwgEndpointPicker.ranges.flatMap {prefix->
            (0 until 4).map {"$prefix.${Random.nextInt(1,255)}"}
        }.distinct().shuffled()
        try{
            val jobs=addresses.map {ip->Callable {
                if(stopped() || Thread.currentThread().isInterrupted)return@Callable null
                val client=base.newBuilder().dns(object:Dns {
                    override fun lookup(hostname:String):List<InetAddress> {
                        require(hostname=="trace.cloudflare.com")
                        return listOf(InetAddress.getByName(ip)) // generated numeric IP only
                    }
                }).build()
                val started=System.nanoTime()
                try{
                    val req=Request.Builder().url("https://trace.cloudflare.com/cdn-cgi/trace")
                        .header("Connection","close").build()
                    client.newCall(req).execute().use {response->
                        if(response.code!=200)return@use null
                        val text=response.peekBody(8193).string()
                        if(text.length>8192)return@use null
                        val nodes=text.lineSequence().filter {it.startsWith("colo=")}.toList()
                        if(nodes.size!=1 || !AwgNodePolicy.accepted(nodes.single().substringAfter('=')))
                            return@use null
                        (System.nanoTime()-started) to "$ip:4500"
                    }
                }catch(_:Exception){null}
            }}
            return pool.invokeAll(jobs,25,TimeUnit.SECONDS).mapNotNull {future->
                runCatching{if(future.isCancelled)null else future.get()}.getOrNull()
            }.sortedBy {it.first}.map {it.second}.take(AwgEndpointPicker.LIMIT)
        }finally{
            pool.shutdownNow()
            base.dispatcher.cancelAll()
            base.connectionPool.evictAll()
            base.dispatcher.executorService.shutdown()
        }
    }
}
