package dev.autowarp

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.work.*
import io.nekohasekai.awglab.Awglab
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

class Model(app:Application):AndroidViewModel(app){
    val store=Store.get(app);val data=MutableStateFlow<JSONObject?>(null)
    private val fileObserver=object:android.os.FileObserver(app.noBackupFilesDir,CLOSE_WRITE or MOVED_TO){
        override fun onEvent(event:Int,path:String?){if(path=="autowarp.aes")store.revision.update { it+1 }}
    }
    override fun onCleared(){fileObserver.stopWatching();super.onCleared()}
    val busy=MutableStateFlow(false);val message=MutableStateFlow("")
    init {
        fileObserver.startWatching()
        viewModelScope.launch {store.revision.collect { runCatching {withContext(Dispatchers.IO){store.read()}}.onSuccess {data.value=it}.onFailure {message.value="Не удалось расшифровать хранилище"} }}
        val task=PeriodicWorkRequestBuilder<RefreshWorker>(12,TimeUnit.HOURS).setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()).build()
        WorkManager.getInstance(app).enqueueUniquePeriodicWork("subscriptions",ExistingPeriodicWorkPolicy.KEEP,task)
    }
    fun action(done:String,reload:Boolean=false,block:()->Unit){
        if(busy.value)return;busy.value=true
        viewModelScope.launch {try{withContext(Dispatchers.IO){block()};message.value=done;if(reload)Tunnel.cmd(getApplication(),"RELOAD")}
            catch(e:Exception){val m=e.message.orEmpty();message.value=if(e is SubscriptionProblem || e is java.net.SocketTimeoutException || e is java.net.UnknownHostException || e is javax.net.ssl.SSLException || e is java.net.ConnectException)subscriptionFailure(e) else if(m.matches(Regex("Cloudflare HTTP [0-9]{3}"))||m=="Пауза регистрации")"$m. Доступен импорт профиля." else "Операция не удалась. Проверьте формат и доступность источника."}
            finally{busy.value=false}}
    }
    fun withProfile(ready:()->Unit){
        if(busy.value)return
        busy.value=true
        viewModelScope.launch {
            try{
                val ok=withContext(Dispatchers.IO){hasProfile(store.read())}
                if(ok)ready() else message.value=Reason.NO_PROFILE.text
            }catch(_:Exception){message.value=Reason.DENIED.text}
            finally{busy.value=false}
        }
    }
    fun setting(k:String,v:Any)=action("Сохранено",true){
        store.edit { s->
            s.put(k,v)
            if(k in setOf("mode","server","endpoint"))require(hasProfile(s))
            if(k=="endpoint" && v!=""){
                val w=s.map("wg").getJSONObject(s.getString("warp"))
                require(endpoints(w).any { (h,p)->"$h/$p"==v })
            }
            if(k=="server" && v!="")require(nodes(s).any { it.getString("id")==v })
        }
    }
    fun dnsPolicy(id:String,custom:String)=action("DNS сохранён. Применится при подключении"){
        check(!Tunnel.live.value.running)
        require(id in listOf("off","custom") || AwgDnsPolicy.providers.any{it.id==id})
        if(id=="custom")require(AwgDnsPolicy.customUrl(custom)!=null)
        store.edit{it.put("awgDohProvider",id).put("awgDohCustom",custom)}
    }
    fun load(uri:Uri,wg:Boolean)=action("Импорт завершён",true){
        val value=getApplication<Application>().contentResolver.openInputStream(uri)!!.use {boundedLocalText(it)}
        if(wg)store.warp(value) else store.source("Файл "+digest(value).take(6),"",value)
    }
    fun importAWG(uri:Uri)=action("AWG-конфигурация сохранена"){
        val text=getApplication<Application>().contentResolver.openInputStream(uri)!!.use { boundedLocalText(it,65536) }
        require(Awglab.validateQuickFile(text))
        store.saveAWG(text,imported=true)
    }
    fun generateAWG()=action("Профиль готов. Можно подключаться."){
        val conf=AmneziaWarpGenerator.generate(store.read())
        require(Awglab.validateQuickFile(conf)) { "invalid_awg_preset" }
        store.saveAWG(conf)
    }
    fun registerAndGenerateAWG()=action("Профиль готов. Можно подключаться.",true){
        Warp.activate(store)
        val conf=AmneziaWarpGenerator.generate(store.read())
        require(Awglab.validateQuickFile(conf)) { "invalid_awg_preset" }
        store.saveAWG(conf)
    }
    fun testAWG()=action("Проверка завершена — результат в подробностях профиля"){
        val cm=getApplication<Application>().getSystemService(ConnectivityManager::class.java)
        val network=requireNotNull(cm.activeNetwork)
        val caps=requireNotNull(cm.getNetworkCapabilities(network))
        // A userspace AWG probe needs the real physical network and must never
        // route its UDP sockets through an existing VPN, including another app.
        require(!Tunnel.live.value.running)
        require(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
        require(!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        require(cm.allNetworks.none { n->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
        })
        val quick=store.read().optString("awgQuick")
        require(Awglab.validateQuickFile(quick))
        store.recordEvent("awg_probe_start","WARP")
        val result=runCatching {Awglab.probeWarp(quick)}.getOrElse { "awg_https_failed" }
        store.awgProbeStatus(result)
        store.recordEvent(if(result.startsWith("awg_verified:"))"awg_probe_ok" else "awg_probe_fail","WARP",error=result)
    }
    fun export(uri:Uri,wg:Boolean)=action("Экспорт завершён"){
        val s=store.read();val text=if(wg)s.map("wg").getJSONObject(s.getString("warp")).getString("ini")
        else diagnosticReport(s,Tunnel.live.value.state).toString(2)
        getApplication<Application>().contentResolver.openOutputStream(uri,"wt")!!.use {it.write(text.toByteArray())}
    }
    fun checkTun()=action("HTTPS и DNS через Android VPN работают"){
        val cm=getApplication<Application>().getSystemService(ConnectivityManager::class.java);val n=requireNotNull(cm.activeNetwork)
        require(cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true && Tunnel.live.value.running)
        val conn=n.openConnection(java.net.URL("https://www.cloudflare.com/cdn-cgi/trace"),java.net.Proxy.NO_PROXY) as HttpsURLConnection
        try{conn.connectTimeout=8000;conn.readTimeout=8000;conn.instanceFollowRedirects=false;require(conn.responseCode==200)
            val fields=conn.inputStream.use {bounded(it,8192)}.lineSequence().associate {it.substringBefore('=') to it.substringAfter('=')}
            require(android.util.Patterns.IP_ADDRESS.matcher(fields["ip"].orEmpty()).matches());if(Tunnel.live.value.kind in listOf("WARP","WARP через VLESS"))require(fields["warp"] in listOf("on","plus"))
        }finally{conn.disconnect()}
    }
}
class MainActivity:ComponentActivity(){
    private val observer by lazy { VpnObserver(this){Tunnel.live.value=it} }
    internal val statusReady get()=observer.synced
    override fun onStart(){super.onStart();observer.start()}
    override fun onStop(){observer.stop();super.onStop()}
    override fun onCreate(savedInstanceState:Bundle?){super.onCreate(savedInstanceState);setContent {
        MaterialTheme(colorScheme=darkColorScheme(primary=Color(0xff8ce9c1),secondary=Color(0xffbfd2ff),background=Color(0xff0e1519),surface=Color(0xff172025))){Screen(this)}
    }}
}
@Composable private fun Action(text:String,enabled:Boolean=true,click:()->Unit){OutlinedButton(onClick=click,enabled=enabled,modifier=Modifier.fillMaxWidth()){Text(text)}}
@Composable private fun Toggle(text:String,value:Boolean,change:(Boolean)->Unit){Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){Text(text,Modifier.weight(1f));Switch(value,change)}}
@Composable private fun Choice(label:String,value:String,items:List<String>,change:(String)->Unit){
    var open by remember {mutableStateOf(false)}
    Box{Action("$label · $value"){open=true};DropdownMenu(open,{open=false}){items.forEach {v->DropdownMenuItem(text={Text(v)},onClick={open=false;change(v)})}}}
}
@Composable private fun Screen(activity:MainActivity,vm:Model=viewModel()){
    val state by vm.data.collectAsState();val live by Tunnel.live.collectAsState();val busy by vm.busy.collectAsState();val msg by vm.message.collectAsState()
    val s=state ?: run {Surface(Modifier.fillMaxSize()){Text(msg.ifBlank {"Загрузка…"})};return}
    var tab by rememberSaveable {mutableIntStateOf(0)};var input by remember {mutableStateOf("")};var confirm by rememberSaveable {mutableStateOf("")}
    val ready by activity.statusReady.collectAsState()
    val legacyAvailable=remember(s){hasProfile(s)}
    val awgAvailable=remember(s){s.optString("awgQuick").isNotBlank()}
    var showDiagnostics by rememberSaveable {mutableStateOf(false)}
    var showProfileDetails by rememberSaveable {mutableStateOf(false)}
    var showLegacySettings by rememberSaveable {mutableStateOf(false)}
    var showDns by rememberSaveable {mutableStateOf(false)}
    BackHandler(enabled=tab!=0){tab=if(tab==2)3 else 0}
    val awgActive=live.route=="AmneziaWG · Android"
    val awgEndpoint=remember(s){awgConfiguredEndpoint(s.optString("awgQuick"))}
    val awgCheckEvent=remember(s){
        val events=s.optJSONArray("eventLog")
        events?.let {log->
            (log.length()-1 downTo 0).firstNotNullOfOrNull {i->
                log.optJSONObject(i)?.takeIf {
                    it.optString("code") in setOf("awg_vpn_start","awg_vpn_check_start","awg_vpn_check_ok","awg_vpn_check_failed")
                }
            }?.takeUnless {it.optString("code")=="awg_vpn_start"}
        }
    }
    val awgChecking=awgActive && live.phase==Phase.CONNECTED &&
        awgCheckEvent?.optString("code")=="awg_vpn_check_start"
    fun checkConnection(){
        vm.message.value=if(awgActive)"Проверяем текущее подключение через HTTPS…" else "Проверка маршрутов запрошена; результат в журнале."
        Tunnel.cmd(activity,"CHECK")
    }
    val consent=rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()){r->
        if(r.resultCode==Activity.RESULT_OK)vm.withProfile { Tunnel.cmd(activity,"START") } else vm.message.value="Разрешение VPN отклонено"
    }
    fun connectLegacy()=vm.withProfile {
        val intent=VpnService.prepare(activity)
        if(intent==null)Tunnel.cmd(activity,"START") else consent.launch(intent)
    }
    var diagnosticRouterI1 by rememberSaveable {mutableStateOf(true)}
    var pendingAwgRouterI1 by rememberSaveable {mutableStateOf(true)}
    var pendingAwgAppOnly by rememberSaveable {mutableStateOf(false)}
    val awgConsent=rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()){r->
        if(r.resultCode==Activity.RESULT_OK)AwgTunnel.start(activity,pendingAwgAppOnly,pendingAwgRouterI1)
        else vm.message.value="Разрешение VPN отклонено"
    }
    fun connectAWG(appOnly:Boolean=false,routerI1:Boolean=!s.optBoolean("awgImported",false)){
        if(!awgAvailable || vm.busy.value || Tunnel.live.value.running || !ready)return
        val intent=VpnService.prepare(activity)
        pendingAwgAppOnly=appOnly
        pendingAwgRouterI1=routerI1
        if(intent==null)AwgTunnel.start(activity,appOnly,routerI1) else awgConsent.launch(intent)
    }
    var attempted by rememberSaveable {mutableStateOf(false)}
    LaunchedEffect(ready){if(ready && !attempted){
        attempted=true
        if(awgAvailable && s.optBoolean("auto") && live.phase==Phase.DISCONNECTED)connectAWG()
    }}
    val wgFile=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){it?.let {uri->vm.load(uri,true)}}
    val awgFile=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){it?.let {uri->vm.importAWG(uri)}}
    val subFile=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){it?.let {uri->vm.load(uri,false)}}
    val saveWG=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")){it?.let {uri->vm.export(uri,true)}}
    val saveDiag=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")){it?.let {uri->vm.export(uri,false)}}
    val wg=s.map("wg");val w=wg.optJSONObject(s.optString("warp"));val health=s.map("health")
    val nodes=remember(s){nodes(s)};val tabs=listOf("VPN","Профиль","VLESS","Настройки")
    var now by remember {mutableLongStateOf(SystemClock.elapsedRealtime())}
    LaunchedEffect(live.running){while(live.running){now=SystemClock.elapsedRealtime();delay(1000)}}
    val snack=remember {SnackbarHostState()};LaunchedEffect(msg){if(msg.isNotBlank()){snack.showSnackbar(msg);vm.message.value=""}}
    if(showDns)AwgDnsDialog(s,busy,live.running,onDismiss={showDns=false},onSave={id,url->
        vm.dnsPolicy(id,url);showDns=false
    })
    if(confirm.isNotBlank()){val registration=confirm=="reg" || confirm=="awgReg"
        val confirmWasAwg=confirm=="awgReg"
        AlertDialog(onDismissRequest={confirm=""},title={Text(if(registration)"Регистрация WARP" else "Экспорт ключа")},text={Text(if(registration)"ZBS VPN зарегистрирует устройство в Cloudflare WARP и создаст профиль. Продолжайте, если принимаете условия Cloudflare. Также доступен импорт готового профиля." else "Выбранный файл будет содержать приватный ключ WireGuard.")},
            confirmButton={TextButton(onClick={confirm="";if(confirmWasAwg)vm.registerAndGenerateAWG() else if(registration)vm.action("Профиль сохранён",true){Warp.activate(vm.store)} else saveWG.launch("ZBS VPN.conf")}){Text("Продолжить")}},
            dismissButton={TextButton(onClick={confirm=""}){Text("Отмена")}})
    }
    Scaffold(snackbarHost={SnackbarHost(snack)},bottomBar={
        NavigationBar(containerColor=Color(0xff101D22)){
            listOf(0,1,3).forEach { i ->
                val selected=i==tab || (i==3 && tab==2)
                NavigationBarItem(
                    selected=selected,
                    onClick={tab=i},
                    icon={Text(listOf("◉","◇","⇄","⚙")[i],fontSize=23.sp,
                        color=if(selected)Color(0xff74F0D2) else Color(0xff67AFAE))},
                    label={Text(tabs[i])},
                    colors=NavigationBarItemDefaults.colors(
                        selectedIconColor=Color(0xff74F0D2),
                        selectedTextColor=Color(0xffA1F5D9),
                        unselectedIconColor=Color(0xff67AFAE),
                        unselectedTextColor=Color(0xff86ADA9),
                        indicatorColor=Color(0xff203B3C)))
            }
        }
    }){pad->
        key(tab){LazyColumn(Modifier.fillMaxSize().padding(pad),contentPadding=PaddingValues(20.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
            item{
                if(tab==0)Column(verticalArrangement=Arrangement.spacedBy(2.dp)){
                    Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(9.dp)){
                        Text("ZBS",style=MaterialTheme.typography.headlineLarge,
                            color=Color(0xff80F2D0))
                        Text("VPN",style=MaterialTheme.typography.headlineLarge,
                            color=Color(0xff54C4D8))
                    }
                    Text("ZERO BARRIERS SYSTEM",
                        style=MaterialTheme.typography.labelSmall.copy(letterSpacing=1.5.sp),
                        color=MaterialTheme.colorScheme.primary)
                } else Text(tabs[tab],style=MaterialTheme.typography.headlineLarge)
            }
            if(tab==2)item{Action("← Вернуться в настройки"){tab=3}}
            if(busy)item{LinearProgressIndicator(Modifier.fillMaxWidth())}
            when(tab){
                0->{
                    item{
                        val events=s.optJSONArray("eventLog")
                        val eventCode=events?.optJSONObject(events.length()-1)?.optString("code").orEmpty()
                        ConnectionOverview(live,ready,awgAvailable,now,eventCode)
                    }
                    item{
                        val button=if(!ready)"Проверка…" else when(live.phase){
                            Phase.CONNECTED->"Отключить"
                            Phase.CONNECTING->"Отменить подключение"
                            Phase.DISCONNECTING->"Отключение…"
                            Phase.ERROR->if(awgAvailable)"Повторить подключение" else "Настроить VPN"
                            Phase.DISCONNECTED->if(awgAvailable)"Подключить с маскировкой" else "Настроить VPN"
                        }
                        Button(onClick={
                            if(live.running)Tunnel.cmd(activity,"STOP")
                            else if(awgAvailable)connectAWG() else tab=1
                        },enabled=ready && live.phase!=Phase.DISCONNECTING && (live.running || !busy),
                            modifier=Modifier.fillMaxWidth().height(64.dp)){Text(button)}
                    }
                    if(ready && live.phase==Phase.CONNECTED && awgActive){
                        item{
                            Action(if(awgChecking)"Проверяем подключение…" else "Проверить подключение",!awgChecking){checkConnection()}
                            if(awgCheckEvent!=null)Text(eventText(awgCheckEvent),style=MaterialTheme.typography.bodySmall)
                        }
                    }
                    if(awgAvailable)item{
                        Action("Обход геоблокировок · "+AwgDnsPolicy.label(s)){showDns=true}
                        Text("Помогает открыть отдельные сервисы через выбранного DNS-провайдера.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if(awgAvailable && !live.running)item{Text(if(s.optBoolean("awgImported",false))"Маскировка · из импортированного файла" else "Маскировка · встроенная I1",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    if(!live.running || awgActive)item{Text("Подключение с маскировкой использует IPv4. IPv6 блокируется.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    if(live.phase==Phase.ERROR)item{Action("Посмотреть причину"){
                        showDiagnostics=true;tab=3
                    }}
                }
                1->{
                    item{Card(Modifier.fillMaxWidth()){Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){
                        Text(if(awgAvailable)"Профиль готов" else "Профиль WARP",style=MaterialTheme.typography.titleLarge)
                        Text(if(awgAvailable)"Профиль сохранён на этом устройстве и готов к подключению."
                            else "ZBS VPN подготовит профиль автоматически. Также можно импортировать готовый файл.",style=MaterialTheme.typography.bodyMedium)
                        if(awgAvailable){
                            Button(onClick={tab=0},modifier=Modifier.fillMaxWidth()){Text("Перейти к подключению")}
                        }else{
                            Button(onClick={if(w!=null)vm.generateAWG() else confirm="awgReg"},
                                enabled=!busy && !live.running,modifier=Modifier.fillMaxWidth()){
                                Text(if(busy)"Подготавливаем…" else "Создать профиль автоматически")
                            }
                        }
                        Action(if(awgAvailable)"Импортировать другой профиль" else "Импортировать профиль",!busy && !live.running){
                            awgFile.launch(arrayOf("*/*"))
                        }
                        Text("Для импорта подходит профиль AmneziaWG в формате .conf.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                    }}}
                    item{Action(if(showProfileDetails)"Скрыть подробности профиля" else "Подробности и управление профилем"){
                        showProfileDetails=!showProfileDetails
                    }}
                    if(showProfileDetails){

                    item{Text(when{ s.has("registeredConf")->"Регистрация сохранена";s.has("reg")->"Требуется активация регистрации";s.has("keys")->"Локальная пара ключей готова";else->"Регистрации WARP нет"})}
                    item{Action("Создать локальные ключи",!busy&&!s.has("keys")){vm.action("Ключи X25519 созданы"){Warp.keys(vm.store)}}}
                    if(s.has("keys"))item{Text("Ключи уже сохранены. Повторная генерация без сохранения профиля запрещена.",style=MaterialTheme.typography.bodySmall)}
                    if(w!=null){item{
                        val peer=w.optJSONObject("config")?.optJSONArray("peers")?.optJSONObject(0)
                        val reserve=peer?.optJSONArray("reserved")
                        Text("Диагностика профиля: Reserved — "+when {
                            reserve==null -> "отсутствует"
                            reserve.length()==3 -> "3 байта (формат корректен)"
                            else -> "неверная длина"
                        },style=MaterialTheme.typography.bodyMedium)
                    }}
                    item{Action(if(s.has("registeredConf"))"Восстановить сохранённый профиль" else "Зарегистрировать устройство",!busy){confirm="reg"}}
                    item{TextButton(onClick={activity.startActivity(Intent(Intent.ACTION_VIEW,Uri.parse("https://www.cloudflare.com/application/terms/")))}){Text("Условия Cloudflare")}}
                    item{Action("Импорт WireGuard"){wgFile.launch(arrayOf("*/*"))}}
                    item{Action("Экспорт WireGuard",w!=null){confirm="export"}}
                    item{Text("AmneziaWG v3 · экспериментальная проверка",style=MaterialTheme.typography.titleMedium)}
                    item{Text("Импортируйте AWG.conf со своего устройства. Файл содержит приватный ключ — не отправляйте его посторонним. Проба запускается только при отключённом VPN, не меняет системные маршруты и не включает общий VPN.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    item{Action(if(w!=null)"Создать AmneziaWARP из WARP-профиля" else "Создать AmneziaWARP (регистрация WARP)",!busy){
                        if(w!=null)vm.generateAWG() else confirm="awgReg"
                    }}
                    item{Text("Создаётся локально из зарегистрированного WARP. Параметры AWG — экспериментальный базовый шаблон; это не гарантия обхода блокировки и не копия маскировки с роутера.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    item{Action("Импорт AmneziaWG (AWG.conf)",!busy){awgFile.launch(arrayOf("*/*"))}}
                    if(s.has("awgQuick")){
                        item{Text("Точка входа сохранённого AWG: "+(awgEndpoint ?: "не указана"),style=MaterialTheme.typography.bodyMedium)}
                        item{Text("AWG использует Endpoint из сохранённого конфига. Список ниже не меняет уже созданный AWG-конфиг. При генерации AmneziaWARP в него копируется выбранная точка входа или адрес исходного WARP-профиля.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                        item{Action("Проверить AWG-конфиг отдельно",!busy && !live.running){vm.testAWG()}}
                        item{Text("Отдельная проверка использует сохранённый конфиг без Android VPN. Маскировка основной кнопки дополнительно не добавляется.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                        item{
                            val result=s.optString("awgProbeStatus")
                            if(result.isNotBlank()){
                                val label=when{
                                    result.startsWith("awg_verified:")->"HTTPS через AWG подтверждён · ${result.substringAfter(":")} мс"
                                    result=="awg_tun_create_failed"->"Не создан временный сетевой интерфейс"
                                    result=="awg_ipc_config_failed"->"AWG отклонил параметры конфигурации"
                                    result=="awg_endpoint_dns_failed"->"Не удалось разрешить endpoint WARP в публичный IPv4"
                                    result=="awg_device_start_failed"->"AWG не смог запустить устройство"
                                    result=="awg_no_handshake"->"Нет подтверждённого handshake AWG"
                                    result=="awg_https_timeout"->"Handshake был, но HTTPS завершился таймаутом"
                                    result=="awg_tcp_timeout"->"AWG: handshake есть, TCP не подключился"
                                    result=="awg_tls_timeout"->"AWG: TCP подключён, TLS не завершился"
                                    result=="awg_http_timeout"->"AWG: TLS прошёл, HTTP не ответил"
                                    result=="awg_tunnel_failed"->"AWG не смог поднять туннель"
                                    result=="awg_invalid_file" || result=="awg_invalid_config"->"Некорректный AWG-конфиг"
                                    result=="awg_not_confirmed"->"HTTPS работает, но WARP не подтверждён"
                                    else->"HTTPS через AWG не прошёл"
                                }
                                Text("Последняя проверка: $label",style=MaterialTheme.typography.bodySmall)
                            }
                        }
                        item{Action("Удалить сохранённый AWG-конфиг",!busy){
                            vm.action("AWG-конфигурация удалена"){vm.store.removeAWG()}
                        }}
                    }

                    items(wg.entries()){(id,p)->Action((if(s.optString("warp")==id)"✓ " else "")+p.getString("name")+" · "+id.take(6)){vm.action("Профиль выбран",true){vm.store.edit {require(it.map("wg").has(id));it.put("warp",id).remove("endpoint")}}}}
                    if(w!=null){item{Text("Точки входа прежнего режима",style=MaterialTheme.typography.titleMedium)};items(endpoints(w)){(h,p)->val k="$h/$p";val tag="w-"+w.getString("id")+"-"+digest(k)
                        Action((if(s.optString("endpoint")==k)"✓ " else "")+"$h · $p · "+status(health.optJSONObject(tag))){vm.setting("endpoint",k)}}
                        item{Text("Варианты берутся из WARP-профиля; для известных адресов Cloudflare приложение добавляет порты 2408, 500 и 4500. Это список кандидатов, а не подтверждённых рабочих серверов.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                        item{Action("Автовыбор точки входа (прежний режим)"){vm.setting("endpoint","")}}}
                    item{
                        Action(if(awgChecking)"Проверяем подключение…" else if(awgActive)"Проверить текущее подключение" else "Проверить маршруты прежнего режима",
                            live.phase==Phase.CONNECTED && !awgChecking){checkConnection()}
                        if(awgCheckEvent!=null)
                            Text(eventText(awgCheckEvent),style=MaterialTheme.typography.bodySmall)
                    }
                    }
                }
                2->{
                    item{OutlinedTextField(input,{input=it},singleLine=true,label={Text("HTTPS-подписка или ссылка сервера")},modifier=Modifier.fillMaxWidth())}
                    item{Action("Добавить",!busy&&input.isNotBlank()){val v=input.trim();input="";vm.action("Источник сохранён",true){if(listOf("vless://","trojan://","vmess://","hy2://","hysteria2://").any(v::startsWith))vm.store.source("Ручной "+digest(v).take(6),"",v) else vm.store.refresh(v)}}}
                    item{Action("Импорт файла"){subFile.launch(arrayOf("*/*"))}}
                    item{Text("Поддерживаются VLESS, Trojan, VMess (alterId=0), Hysteria 2 в форматах URI и VLESS из Clash/Mihomo YAML (TCP+TLS, uTLS, XUDP, SMUX). Неподдерживаемые транспорты пропускаются.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    item{
                        val file=s.optJSONObject("lastFileImportDiagnostic")
                        if(file!=null){
                            val summary=when(file.optString("format")){
                                "clash_yaml"->"Clash/Mihomo YAML"
                                "providers_only"->"файл proxy-providers, без готового списка proxies"
                                "no_proxies"->"YAML без секции proxies"
                                "json"->"JSON, не YAML"
                                "too_large"->"слишком большой файл"
                                "yaml_parse_error"->"ошибка синтаксиса YAML"
                                "yaml_not_mapping"->"YAML без корневого объекта"
                                "base64_or_encoded"->"похоже на закодированный текст"
                                "uri_list"->"список ссылок URI"
                                "html"->"HTML вместо конфигурации"
                                "empty"->"пустой файл"
                                else->"неизвестный формат файла"
                            }
                            Text("Последний файл: $summary",style=MaterialTheme.typography.bodySmall)
                            Text("Прокси: ${file.optInt("proxies")}; VLESS: ${file.optInt("vless")}; совместимых: ${file.optInt("converted")}",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                            val stage=when(file.optString("stage")){
                                "core_rejected"->"проверка Go-ядра отклонила файл"
                                "parsed"->"профили распознаны Go-ядром"
                                else->"конвертация не завершена"
                            }
                            Text("Этап: $stage",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    item{
                        val d=s.optJSONObject("lastSubscriptionDiagnostic")
                        if(d!=null){
                            val format=when(d.optString("shape")){
                                "html"->"HTML (возможно, страница ошибки)"
                                "json"->"JSON"
                                "clash_yaml"->"Clash/Mihomo YAML (поддерживается VLESS TCP+TLS)"
                                "uri_list"->"Текстовые ссылки"
                                "base64_uri_list"->"Base64-ссылки"
                                "plain_text"->"Текст без распознанных ссылок"
                                else->"Неизвестный"
                            }
                            Text("Последний ответ подписки: HTTP ${d.optInt("http")} · $format",style=MaterialTheme.typography.bodySmall)
                            Text("Обнаружено URI: VLESS ${d.optInt("vless")}, Trojan ${d.optInt("trojan")}, VMess ${d.optInt("vmess")}, Hysteria 2 ${d.optInt("hy2")}",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                            if(d.optString("shape")=="json"){
                                val kind=when(d.optString("jsonKind")){
                                    "singbox"->"sing-box outbounds"
                                    "servers"->"список servers"
                                    "clash_json"->"Clash JSON proxies"
                                    "nodes"->"список nodes"
                                    "array"->"JSON-массив"
                                    "provider_message"->"сообщение провайдера"
                                    "other_object"->"неизвестный JSON-объект"
                                    else->"нераспознанный JSON"
                                }
                                Text("Структура JSON: $kind · элементов ${d.optInt("jsonEntries")}",style=MaterialTheme.typography.bodySmall)
                                Text("В JSON-объектах: VLESS ${d.optInt("jsonVless")}, Trojan ${d.optInt("jsonTrojan")}, VMess ${d.optInt("jsonVmess")}, Hysteria 2 ${d.optInt("jsonHy2")}",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                                val fields=d.optJSONArray("knownFields")
                                val safeFields=fields?.let { a->(0 until a.length()).joinToString(", ") { i->a.optString(i) } }.orEmpty()
                                Text("Тип элементов: ${d.optString("entryFormat","unknown_entries")}",style=MaterialTheme.typography.bodySmall)
                                if(safeFields.isNotBlank())Text("Поля конфигурации: $safeFields",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                                val nested=d.optJSONObject("outboundsTypes")
                                if(nested!=null){
                                    Text("outbounds: массивы ${nested.optInt("array")}, объекты ${nested.optInt("object")}, строки ${nested.optInt("string")}, null ${nested.optInt("null")}",style=MaterialTheme.typography.bodySmall)
                                    val names=d.optJSONArray("nestedOutboundFields")
                                    val nestedNames=names?.let { a->(0 until a.length()).joinToString(", ") { i->a.optString(i) } }.orEmpty()
                                    if(nestedNames.isNotBlank())Text("Поля внутри outbounds: $nestedNames",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                                    Text("Внутри outbounds: VLESS ${d.optInt("nestedVless")}, Trojan ${d.optInt("nestedTrojan")}, другие ${d.optInt("nestedOther")}",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    }
                    items(s.map("sources").entries()){(id,p)->Column{
                        if(p.optInt("skipped")>0)Text("Пропущено служебных профилей: ${p.optInt("skipped")}",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(verticalAlignment=Alignment.CenterVertically){Text(p.getString("name"),Modifier.weight(1f));if(p.optString("url").isNotBlank())TextButton(onClick={vm.action("Обновлено",true){vm.store.refresh(p.getString("url"))}}){Text("Обновить")}
                        TextButton(onClick={vm.action("Удалено",true){vm.store.edit {it.map("sources").remove(id);it.remove("server")}}}){Text("Удалить")}}
                    }}
                    item{Action("Автовыбор сервера"){vm.setting("server","")}}
                    item{
                        val scan=s.optJSONObject("scan")
                        val scanning=scan?.optBoolean("running",false)==true
                        val count=nodes.size.coerceAtMost(24)
                        Action(if(scanning)"Остановить проверку" else "Проверить серверы без подключения ($count)", 
                            !busy && (scanning || (nodes.isNotEmpty() && !live.running && ready))){
                            Tunnel.cmd(activity,if(scanning)"STOP" else "SCAN")
                        }
                    }
                    item{
                        val scan=s.optJSONObject("scan")
                        if(scan!=null && nodes.isNotEmpty()){
                            val done=scan.optInt("done",0)
                            val total=scan.optInt("total",0)
                            val status=scan.optString("status")
                            Text("Предварительная проверка: $done / $total" +
                                if(scan.optBoolean("running"))" · выполняется" else if(status=="finished")" · завершена"
                                else if(status=="failed")" · ошибка запуска" else "")
                            if(scan.optBoolean("running")) LinearProgressIndicator(
                                progress={if(total>0)(done.toFloat()/total).coerceIn(0f,1f) else 0f},
                                modifier=Modifier.fillMaxWidth()
                            )
                        }
                    }
                    item{
                        Action(if(awgChecking)"Проверяем подключение…" else if(awgActive)"Проверить текущее подключение" else "Проверить маршруты прежнего режима",
                            live.phase==Phase.CONNECTED && !awgChecking){checkConnection()}
                        if(awgCheckEvent!=null)
                            Text(eventText(awgCheckEvent),style=MaterialTheme.typography.bodySmall)
                    }
                    items(nodes.sortedBy {health.optJSONObject("v-"+it.getString("id"))?.optInt("ms")?.takeIf {n->n>=0} ?: Int.MAX_VALUE}){p->val id=p.getString("id")
                        Action((if(s.optString("server")==id)"✓ " else "")+p.getString("name")+" · "+status(health.optJSONObject("v-$id"))){vm.setting("server",id)}}
                }
                3->{
                    item{Action("Обход геоблокировок · "+AwgDnsPolicy.label(s)){showDns=true}}
                    item{Toggle("Подключать при открытии приложения",s.optBoolean("auto")){vm.setting("auto",it)}}
                    item{Card(Modifier.fillMaxWidth()){Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                        Text("Подключение с маскировкой",style=MaterialTheme.typography.titleMedium)
                        Text("Интернет через WARP. Сейчас поддерживается IPv4, IPv6 блокируется.",style=MaterialTheme.typography.bodySmall)
                    }}}
                    item{Action("Системный Always-on и блокировка"){activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))}}
                    item{Text("Для блокировки трафика при остановке службы включите в Android постоянный VPN и запрет соединений без VPN.")}

                    item{Action(if(showDiagnostics)"Скрыть диагностику" else "Диагностика и журнал"){
                        showDiagnostics=!showDiagnostics
                    }}
                    if(showDiagnostics){

                        item{Text("Диагностика AWG",style=MaterialTheme.typography.titleMedium)}
                        if(awgAvailable){
                            item{
                                Choice("Маскировка для диагностики",if(diagnosticRouterI1)"Встроенная I1" else "Исходная",
                                    listOf("Исходная","Встроенная I1")){diagnosticRouterI1=it=="Встроенная I1"}
                                Text("Выбор применяется только к диагностическим кнопкам ниже. Основная кнопка сохраняет маскировку импортированного файла; для профиля ZBS VPN добавляет встроенную I1. Здесь можно явно выбрать диагностический вариант.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                                Action("AWG: подключить выбранный вариант",ready && !busy && !live.running){
                                    connectAWG(routerI1=diagnosticRouterI1)
                                }
                                Action("AWG: тест только ZBS VPN",ready && !busy && !live.running){
                                    connectAWG(appOnly=true,routerI1=diagnosticRouterI1)
                                }
                                Text("Тест только ZBS VPN не передаёт трафик других приложений и отключается после проверки HTTPS.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    item{Action("Проверить HTTPS и DNS через TUN",live.running&&!busy){vm.checkTun()}}
                    item{Text("Живой журнал подключения",style=MaterialTheme.typography.titleMedium)}
                    item{Text("Что проверяет ZBS VPN прямо сейчас. HTTPS через маршрут — не прямое измерение WireGuard-handshake.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    val events=s.optJSONArray("eventLog")
                    if(events==null || events.length()==0)item{Text("Журнал пока пуст. Запустите подключение WARP.",style=MaterialTheme.typography.bodySmall)}
                    else items((events.length()-1 downTo maxOf(0,events.length()-32)).toList()){ i->
                        val record=events.optJSONObject(i)
                        if(record!=null)Text(eventLine(record),style=MaterialTheme.typography.bodySmall)
                    }
                    item{Action("Очистить журнал",!busy && (events?.length() ?: 0)>0){
                        vm.action("Журнал очищен"){vm.store.clearEvents()}
                    }}
                    item{Text("Последние проверки маршрутов",style=MaterialTheme.typography.titleMedium)}
                    if(health.length()==0)item{Text("Проверки ещё не проводились")}
                    items(health.entries().sortedByDescending { it.second.optLong("at",0) }.take(12)){(tag,result)->
                        Text((if(tag.startsWith("w-"))"WARP" else if(tag.startsWith("v-"))"VLESS" else "Маршрут")+" · "+status(result))
                    }
                    item{Text("Диагностика не содержит ключей, токенов регистрации или UUID. UDP-handshake напрямую пока не измеряется.",style=MaterialTheme.typography.bodySmall)}
                    item{Action("Экспорт диагностики"){saveDiag.launch("ZBS VPN-diagnostics.json")}}
                    }
                    item{Action(if(showLegacySettings)"Скрыть дополнительные режимы" else "Дополнительные режимы и настройки"){
                        showLegacySettings=!showLegacySettings
                    }}
                    if(showLegacySettings){
                        item{Action("Подписки и серверы VLESS / Trojan / VMess"){tab=2}}
                        item{Text("Прежние режимы WARP / VLESS",style=MaterialTheme.typography.titleMedium)}
                        item{Choice("Маршрут прежнего режима",s.optString("mode","Авто"),modes.filter { hasProfile(JSONObject(s.toString()).put("mode",it)) }){vm.setting("mode",it)}}
                        item{Action("Подключить прежний режим",ready && !busy && !live.running && legacyAvailable){
                            connectLegacy()
                        }}
                        if(!legacyAvailable)item{Text("Добавьте профиль в разделе «Профиль» или дополнительных режимах.")}
                    item{Choice("Клиент подписки",s.optString("subscriptionClient",subscriptionClients[0]),subscriptionClients){vm.setting("subscriptionClient",it)}}
                    item{Text("Экспериментальный профиль меняет только заголовки HTTPS-запроса. Он не подменяет HWID и не гарантирует доступ к подпискам, ограниченным провайдером.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    item{Text("Настройки прежнего VPN-режима",style=MaterialTheme.typography.titleMedium)}
                    item{Text("Автопереключение, IPv6, период и выбор DNS ниже относятся к прежнему режиму. Подключение с маскировкой использует IPv4; DNS задаётся в пункте «Обход геоблокировок», IPv6 блокируется.",style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)}
                    item{Toggle("Автопереключение",s.optBoolean("switch",true)){vm.setting("switch",it)}}
                    item{Toggle("Приоритет стабильности",s.optBoolean("stable",true)){vm.setting("stable",it)}}
                    item{Toggle("IPv6 через туннель",s.optBoolean("ipv6",true)){vm.setting("ipv6",it)}}
                    item{Choice("Период, сек",s.optInt("seconds",30).toString(),listOf("15","30","60","120","300")){vm.setting("seconds",it.toInt())}}
                    item{Choice("DNS over TLS",s.optString("dns","1.1.1.1"),listOf("1.1.1.1","9.9.9.9")){vm.setting("dns",it)}}

                    }
                    item{
                        Card(Modifier.fillMaxWidth()){
                            Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
                                Text("О приложении",style=MaterialTheme.typography.titleMedium)
                                Text("ZBS VPN",style=MaterialTheme.typography.titleLarge)
                                Text("ZERO BARRIERS SYSTEM",
                                    style=MaterialTheme.typography.labelSmall.copy(letterSpacing=1.4.sp),
                                    color=MaterialTheme.colorScheme.primary)
                                val appVersion=remember(activity){runCatching {
                                    activity.packageManager.getPackageInfo(activity.packageName,0).versionName
                                }.getOrNull().orEmpty()}
                                if(appVersion.isNotBlank())Text("Версия $appVersion",
                                    style=MaterialTheme.typography.bodySmall,
                                    color=MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        }}
    }
}
private fun status(h:JSONObject?)=when{
    h==null->"нет проверок"
    h.optLong("ms",-1)>=0->"${h.optLong("ms")} мс"
    else->when(h.optString("error")){
        "probe_timeout"->"таймаут HTTPS"
        "probe_cancelled"->"проверка отменена"
        "probe_dns"->"ошибка DNS"
        "probe_tls_certificate"->"ошибка сертификата TLS"
        "probe_transport"->"ошибка транспорта"
        "probe_network_unreachable"->"сеть недоступна"
        "probe_host_unreachable"->"сервер недоступен"
        "probe_connection_refused"->"соединение отклонено"
        "probe_connection_reset"->"соединение сброшено"
        "probe_connection_closed"->"соединение разорвано"
        "probe_tls_handshake"->"ошибка TLS-рукопожатия"
        "probe_trace_body"->"ошибка ответа HTTPS"
        "probe_trace_ip"->"IP не подтверждён"
        "probe_warp_not_confirmed"->"WARP не подтверждён"
        else->if(h.optString("error").matches(Regex("probe_http_[0-9]{3}")))"ошибка HTTP ${h.optString("error").takeLast(3)}" else "нет ответа (причина неизвестна)"
    }
}
