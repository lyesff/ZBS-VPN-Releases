package dev.autowarp

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import androidx.work.*
import io.nekohasekai.libbox.Libbox
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.net.Proxy
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

fun obj(vararg pairs:Pair<String,Any>)=JSONObject().apply { pairs.forEach { put(it.first,it.second) } }
fun arr(vararg v:Any)=JSONArray(v.toList())
fun JSONObject.map(k:String)=optJSONObject(k) ?: JSONObject()
fun JSONObject.entries()=keys().asSequence().map { it to getJSONObject(it) }.toList()
fun digest(s:String)=MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).take(12).joinToString(""){"%02x".format(it)}
fun bounded(input:InputStream,limit:Int=1048576):String{
    val out=java.io.ByteArrayOutputStream();val buf=ByteArray(8192)
    while(true){val n=input.read(buf);if(n<0)break;require(out.size()+n<=limit);out.write(buf,0,n)}
    return out.toString("UTF-8")
}
/** Local text files from Windows may be UTF-8, UTF-8 BOM or UTF-16.
 * Detect explicit BOMs and UTF-16 NUL patterns; never log input text.
 * Network responses still use the existing UTF-8 bounded() reader.
 */
internal fun boundedLocalText(input:InputStream,limit:Int=1048576):String {
    val bytes=java.io.ByteArrayOutputStream()
    val buf=ByteArray(8192)
    while(true){
        val n=input.read(buf)
        if(n<0)break
        require(bytes.size()+n<=limit)
        bytes.write(buf,0,n)
    }
    val data=bytes.toByteArray()
    fun b(i:Int)=data[i].toInt() and 255
    if(data.size>=3 && b(0)==0xEF && b(1)==0xBB && b(2)==0xBF)
        return String(data,3,data.size-3,Charsets.UTF_8)
    if(data.size>=2 && b(0)==0xFF && b(1)==0xFE)
        return String(data,2,data.size-2,Charsets.UTF_16LE)
    if(data.size>=2 && b(0)==0xFE && b(1)==0xFF)
        return String(data,2,data.size-2,Charsets.UTF_16BE)
    // Also handle Windows UTF-16 files without a BOM.
    if(data.size>=8){
        val count=minOf(data.size,256)
        val odd=(1 until count step 2).count{data[it]==0.toByte()}
        val even=(0 until count step 2).count{data[it]==0.toByte()}
        if(odd>count/3 && even<count/16)return String(data,Charsets.UTF_16LE)
        if(even>count/3 && odd<count/16)return String(data,Charsets.UTF_16BE)
    }
    return String(data,Charsets.UTF_8)
}
fun publicIP(ip:InetAddress):Boolean{
    if(ip.isAnyLocalAddress||ip.isLoopbackAddress||ip.isLinkLocalAddress||ip.isSiteLocalAddress||ip.isMulticastAddress)return false
    val b=ip.address.map { it.toInt() and 255 }
    if(b.size==16)return b[0] in 32..63 && !(b[0]==32 && (b[1]==2 || b[1]==1 && (b[2]<2 || b[2]==13 && b[3]==184)))
    return b[0] in 1..223 && !(b[0]==100 && b[1] in 64..127 || b[0]==192 && (b[1]==0 || b[1]==88 && b[2]==99) || b[0]==198 && (b[1] in 18..19 || b[1]==51 && b[2]==100) || b[0]==203 && b[1]==0 && b[2]==113)
}
private val client=OkHttpClient.Builder().proxy(Proxy.NO_PROXY).followRedirects(false).followSslRedirects(false)
    .retryOnConnectionFailure(false).callTimeout(15,TimeUnit.SECONDS)
    .dns(object:Dns{override fun lookup(hostname:String)=Dns.SYSTEM.lookup(hostname).also { require(it.isNotEmpty() && it.all(::publicIP)) }}).build()

/** Stable, non-sensitive import diagnostics; never expose subscription URL or response body. */
fun subscriptionFailure(e:Throwable):String = when(e){
    is java.net.SocketTimeoutException -> "Таймаут загрузки подписки"
    is java.net.UnknownHostException -> "DNS: не удалось найти сервер подписки"
    is javax.net.ssl.SSLException -> "Ошибка TLS при загрузке подписки"
    is java.net.ConnectException -> "Нет соединения с сервером подписки"
    is SubscriptionProblem -> when(e.code){
        "http" -> "HTTP ошибка подписки: ${e.status}"
        "redirect" -> "Сервер подписки перенаправляет на другой адрес"
        "size" -> "Подписка превышает лимит 1 МиБ"
        "format" -> "Формат подписки не поддерживается или нет совместимых серверов"
        "provider" -> "Провайдер вернул заглушку «Приложение не поддерживается» вместо серверов"
        else -> "Некорректный адрес подписки"
    }
    else -> "Не удалось импортировать подписку (формат или доступ)"
}
class SubscriptionProblem(val code:String,val status:Int=0):Exception(code)

class Store private constructor(c:Context){
    private val file=AtomicFile(File(c.noBackupFilesDir,"autowarp.aes"))
    val revision=MutableStateFlow(0L)
    private val key:SecretKey by lazy{
        val ks=KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.getKey("aw-v1",null) as? SecretKey ?: KeyGenerator.getInstance("AES","AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder("aw-v1",KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).setBlockModes("GCM").setEncryptionPaddings("NoPadding").build());generateKey()
        }
    }
    private val lockFile=File(c.noBackupFilesDir,"autowarp.lock")
    @Synchronized private fun <T> locked(block:()->T):T =
        java.io.RandomAccessFile(lockFile,"rw").use { f->f.channel.lock().use { block() } }
    fun read()=locked { readLocked() }
    private fun readLocked():JSONObject{
        val bytes=try{file.openRead().use { it.readBytes() }}catch(e:java.io.FileNotFoundException){return JSONObject()}
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,bytes.copyOfRange(0,12)))
        return JSONObject(String(cipher.doFinal(bytes,12,bytes.size-12),Charsets.UTF_8)).also{AwgSettingsMigration.apply(it)}
    }
    fun edit(block:(JSONObject)->Unit)=locked {
        val s=readLocked();block(s)
        val c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,key)
        val bytes=c.iv+c.doFinal(s.toString().toByteArray());val f=file.startWrite()
        try { f.write(bytes);file.finishWrite(f) }catch(e:Exception){file.failWrite(f);throw e};revision.value++;Unit
    }
    /**
     * Bounded, private event journal. Only fixed codes and numeric probe indices
     * are accepted, never endpoint hosts, profile names or exception strings.
     */
    fun recordEvent(code:String,kind:String="",index:Int=0,total:Int=0,latency:Long=-1L,error:String=""){
        if(!VpnJournalPolicy.accepts(code,kind))return
        val safeError=VpnJournalPolicy.safeError(error)
        edit { s->
            val list=s.optJSONArray("eventLog") ?: JSONArray()
            while(list.length()>=VpnJournalPolicy.LIMIT)list.remove(0)
            list.put(JSONObject().put("at",System.currentTimeMillis())
                .put("elapsed_ms",android.os.SystemClock.elapsedRealtime()).put("code",code).put("kind",kind)
                .put("index",index.coerceIn(0,32))
                .put("total",total.coerceIn(0,32))
                .put("ms",latency.coerceIn(-1L,60000L)).put("error",safeError))
            s.put("eventLog",list)
        }
    }
    fun clearEvents()=edit { it.put("eventLog",JSONArray()) }
    // Stored only in the existing Android Keystore-protected encrypted state.
    // This config contains private keys; never include it in diagnostics.
    fun saveAWG(text:String,imported:Boolean=false){
        require(text.isNotBlank() && text.length<=65536)
        edit {
            it.put("awgQuick",text).put("awgImported",imported).remove("awgProbeStatus")
            // A previous profile's working mask must not override a new import.
            it.remove("awgLastMaskWifi");it.remove("awgLastMaskCellular");it.remove("awgLastMaskOther")
        }
    }
    fun removeAWG()=edit { s->s.remove("awgQuick");s.remove("awgImported");s.remove("awgProbeStatus") }
    fun nestedProbeResult(code:String,outerCountry:String,innerCountry:String,ip:String,
        outerMetaCountry:String="",innerMetaCountry:String="",innerMetaColo:String="")=edit { state->
        val safeIP=AwgNestedResult.numericIP(ip)
        state.put("nestedProbeResult",obj("code" to AwgNestedResult.safe(code),
            "outerCountry" to AwgRegionPolicy.country(outerCountry),
            "innerCountry" to AwgRegionPolicy.country(innerCountry),"ip" to safeIP,
            "outerMetaCountry" to AwgRegionPolicy.country(outerMetaCountry),
            "innerMetaCountry" to AwgRegionPolicy.country(innerMetaCountry),
            "innerMetaColo" to AwgNodePolicy.code(innerMetaColo)))
    }
    fun awgProbeStatus(status:String){
        val safe=status.takeIf { it.matches(Regex("awg_(?:invalid_file|invalid_config|tun_create_failed|ipc_config_failed|endpoint_dns_failed|device_start_failed|no_handshake|https_timeout|tcp_timeout|tls_timeout|http_timeout|tunnel_failed|not_confirmed|https_failed|verified:[0-9]{1,5})")) }
            ?: "awg_https_failed"
        edit { it.put("awgProbeStatus",safe) }
    }
    fun warp(text:String){
        val p=JSONObject(Libbox.importWarp(text));val id=p.getString("id")
        edit { s->val all=s.map("wg");require(all.has(id)||all.length()<16)
            all.put(id,p.put("ini",text));s.put("wg",all).put("warp",id).remove("endpoint") }
    }
    fun source(name:String,url:String,body:String,expected:Long?=null){
        val converted=ClashYamlAdapter.convert(body)
        if(url.isBlank()){
            val info=ClashYamlAdapter.diagnose(body)
                .put("convertedToSingBox",converted!=null).put("stage","conversion")
            edit { s->s.put("lastFileImportDiagnostic",info) }
        }
        val normalized=converted ?: body
        val ps=try{JSONArray(Libbox.importSubscription(normalized))}
            catch(e:Exception){
                if(url.isBlank())edit{s->s.optJSONObject("lastFileImportDiagnostic")?.put("stage","core_rejected")}
                throw e
            }
        if(url.isBlank())edit{s->s.optJSONObject("lastFileImportDiagnostic")?.apply { put("stage","parsed"); put("imported",ps.length()) }}
        val tag=digest(url.ifBlank { name })
        val placeholders=providerPlaceholders(ps)
        if(placeholders==ps.length())throw SubscriptionProblem("provider")
        val accepted=JSONArray()
        for(i in 0 until ps.length())if(!placeholderName(ps.getJSONObject(i).optString("name")))accepted.put(ps.getJSONObject(i))
        edit { s->val all=s.map("sources")
            if(expected!=null && all.optJSONObject(tag)?.optLong("time")!=expected)return@edit
            require(all.has(tag)||all.length()<16);all.put(tag,obj("name" to name,"url" to url,"time" to System.currentTimeMillis(),"items" to accepted,"skipped" to placeholders));s.put("sources",all) }
    }
    fun refresh(url:String,expected:Long?=null){
        val u=runCatching { url.toHttpUrl() }.getOrElse { throw SubscriptionProblem("url") }
        if(!u.isHttps || u.port!=443 || u.username.isNotEmpty() || u.password.isNotEmpty() || u.fragment!=null)throw SubscriptionProblem("url")
        if(':' in u.host || u.host.all { it.isDigit()||it=='.' })require(publicIP(InetAddress.getByName(u.host)))
        val profile=read().optString("subscriptionClient",subscriptionClients[0])
        client.newCall(subscriptionRequest(u.toString(),profile)).execute().use { r->
            if(r.code in 300..399)throw SubscriptionProblem("redirect")
            if(!r.isSuccessful)throw SubscriptionProblem("http",r.code)
            val b=r.body ?: throw SubscriptionProblem("format")
            if(b.contentLength()>1048576)throw SubscriptionProblem("size")
            val body=try{b.byteStream().use{bounded(it)}}catch(_:IllegalArgumentException){throw SubscriptionProblem("size")}
            // Persist metadata only, even when import fails. The encrypted store
            // never receives a raw provider response or subscription credential.
            val shape=subscriptionShape(body)
            shape.put("http",r.code).put("at",System.currentTimeMillis())
            edit { s->s.put("lastSubscriptionDiagnostic",shape) }
            try{source(u.host,url,body,expected)}catch(e:Exception){
                if(e is SubscriptionProblem)throw e
                if(e.message?.contains("unsupported or invalid profile")==true)throw SubscriptionProblem("format")
                throw e
            }
        }
    }
    companion object{
        @Volatile private var instance:Store?=null
        fun get(c:Context)=instance ?: synchronized(this){instance ?: Store(c.applicationContext).also { instance=it }}
    }
}
object Warp{
    /** A separate device for the experimental inner hop; never replaces awgQuick or wg. */
    @Synchronized fun prepareNested(s:Store){
        val state=s.read()
        if(state.optString("nestedWarpQuick").isNotBlank())return
        val now=System.currentTimeMillis()
        check(now>=state.optLong("nestedRetry")){"Пауза регистрации"}
        val pair=state.optJSONObject("nestedKeys") ?: JSONObject(Libbox.newWarpKeys()).also {keys->
            s.edit {it.put("nestedKeys",keys)}
        }
        s.edit {it.put("nestedRetry",now+60000)}
        val url="https://api.devices.cloudflare.com/v0a4005/reg"
        fun request(uri:String,method:String,data:JSONObject,token:String=""):JSONObject{
            val b=Request.Builder().url(uri).method(method,data.toString().toRequestBody("application/json".toMediaType()))
            if(token.isNotBlank())b.header("Authorization","Bearer $token")
            client.newCall(b.build()).execute().use {r->
                if(r.code==429){
                    val seconds=r.header("Retry-After")?.toLongOrNull()?.coerceIn(60,86400) ?: 300L
                    s.edit {it.put("nestedRetry",System.currentTimeMillis()+seconds*1000)}
                }
                check(r.isSuccessful){"Cloudflare HTTP ${r.code}"}
                val result=JSONObject(r.body!!.byteStream().use{bounded(it,65536)}.ifBlank{"{}"})
                return result.optJSONObject("result") ?: result
            }
        }
        val reg=state.optJSONObject("nestedRegistration") ?: run {
            s.recordEvent("awg_nested_reg_post","WARP")
            request(url,"POST",obj("key" to pair.getString("public"))).also {r->
                require(r.getString("id").matches(Regex("[A-Za-z0-9-]{1,80}")) && r.getString("token").isNotBlank())
                s.edit {it.put("nestedRegistration",r)}
            }
        }
        s.recordEvent("awg_nested_reg_activate","WARP")
        val active=request(url+"/"+reg.getString("id"),"PATCH",obj("warp_enabled" to true),reg.getString("token"))
        val cfg=active.optJSONObject("config") ?: reg.getJSONObject("config")
        val peer=cfg.getJSONArray("peers").getJSONObject(0)
        val address=cfg.getJSONObject("interface").getJSONObject("addresses").getString("v4").substringBefore('/')
        require(runCatching{InetAddress.getByName(address) is java.net.Inet4Address}.getOrDefault(false))
        val endpoint=peer.optJSONObject("endpoint")?.optString("host").orEmpty()
            .ifBlank{"engage.cloudflareclient.com:2408"}.let {if(':' in it)it else "$it:2408"}
        // Plain WG inside AWG: no extra masking packet or junk on the inner hop.
        val quick="[Interface]\nPrivateKey = "+pair.getString("private")+"\nAddress = $address/32\nMTU = 1220\n\n"+
            "[Peer]\nPublicKey = "+peer.getString("public_key")+"\nEndpoint = $endpoint\n"+
            "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
        require(io.nekohasekai.awglab.Awglab.validateQuickFile(quick))
        s.edit {it.put("nestedWarpQuick",quick)}
    }
    fun keys(s:Store)=s.edit { if(!it.has("keys"))it.put("keys",JSONObject(Libbox.newWarpKeys())) }
    @Synchronized fun activate(s:Store){
        keys(s);val state=s.read()
        state.optString("registeredConf").takeIf(String::isNotBlank)?.let { s.warp(it);return }
        val now=System.currentTimeMillis();check(now>=state.optLong("retry")){"Пауза регистрации"}
        s.edit { it.put("retry",now+86400000) }
        val pair=state.getJSONObject("keys");val url="https://api.devices.cloudflare.com/v0a4005/reg"
        fun request(uri:String,method:String,data:JSONObject,token:String=""):JSONObject{
            val b=Request.Builder().url(uri).method(method,data.toString().toRequestBody("application/json".toMediaType()))
            if(token.isNotBlank())b.header("Authorization","Bearer $token")
            client.newCall(b.build()).execute().use { r->
                if(r.code==429){val retry=r.header("Retry-After").orEmpty();val until=retry.toLongOrNull()?.coerceIn(0L,315360000L)?.let { now+it*1000 } ?: runCatching { java.time.ZonedDateTime.parse(retry,java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli() }.getOrNull()
                    if(until!=null)s.edit { it.put("retry",maxOf(it.optLong("retry"),until)) }}
                check(r.isSuccessful){"Cloudflare HTTP ${r.code}"}
                val o=JSONObject(r.body!!.byteStream().use { bounded(it,65536) }.ifBlank { "{}" });return o.optJSONObject("result") ?: o
            }
        }
        val reg=state.optJSONObject("reg") ?: request(url,"POST",obj("key" to pair.getString("public"))).also { r->
            require(r.getString("id").matches(Regex("[A-Za-z0-9-]{1,80}")) && r.getString("token").isNotBlank());s.edit { it.put("reg",r) } }
        val active=request(url+"/"+reg.getString("id"),"PATCH",obj("warp_enabled" to true),reg.getString("token"))
        val cfg=active.optJSONObject("config") ?: reg.getJSONObject("config");val peer=cfg.getJSONArray("peers").getJSONObject(0)
        val ip=cfg.getJSONObject("interface").getJSONObject("addresses")
        val addrs=listOf("v4" to "/32","v6" to "/128").mapNotNull { (k,m)->ip.optString(k).takeIf(String::isNotBlank)?.substringBefore('/')?.plus(m) }
        val ep=peer.optJSONObject("endpoint")?.optString("host").orEmpty().ifBlank { "engage.cloudflareclient.com:2408" }
        val reserved=cfg.optString("client_id").takeIf(String::isNotEmpty)?.let { Base64.getDecoder().decode(it) }?.takeIf { it.size==3 }
        val text="[Interface]\nPrivateKey = "+pair.getString("private")+"\nAddress = "+addrs.joinToString(", ")+"\nMTU = 1280\n\n[Peer]\nPublicKey = "+peer.getString("public_key")+"\nEndpoint = "+(if(':' in ep)ep else "$ep:2408")+"\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"+reserved?.joinToString(", ",prefix="Reserved = "){(it.toInt() and 255).toString()}.orEmpty()
        s.warp(text);s.edit { it.put("registeredConf",text) }
    }
}
class RefreshWorker(c:Context,p:WorkerParameters):CoroutineWorker(c,p){
    override suspend fun doWork():Result=withContext(Dispatchers.IO){
        val store=Store.get(applicationContext);var failed=false;var updated=false
        for((_,src) in store.read().map("sources").entries()){val url=src.optString("url")
            if(url.isNotBlank())runCatching { store.refresh(url,src.getLong("time"));updated=true }.onFailure { failed=true }}
        if(updated)runCatching { Tunnel.cmd(applicationContext,"RELOAD") }
        if(failed && runAttemptCount<2)Result.retry() else Result.success()
    }
}


