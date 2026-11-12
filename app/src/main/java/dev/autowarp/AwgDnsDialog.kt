package dev.autowarp

import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.json.JSONObject

@Composable
internal fun AwgDnsDialog(state:JSONObject,busy:Boolean,connected:Boolean,onDismiss:()->Unit,onSave:(String,String)->Unit){
    var selected by rememberSaveable{mutableStateOf(state.optString("awgDohProvider","off").ifBlank{"off"})}
    var custom by rememberSaveable{mutableStateOf(state.optString("awgDohCustom"))}
    var help by rememberSaveable{mutableStateOf(false)}
    val list=rememberLazyListState()
    val valid=selected!="custom" || AwgDnsPolicy.customUrl(custom)!=null
    Dialog(onDismissRequest=onDismiss,properties=DialogProperties(usePlatformDefaultWidth=false)){
        Surface(Modifier.widthIn(max=460.dp).fillMaxWidth(0.94f).fillMaxHeight(0.9f),
            shape=MaterialTheme.shapes.extraLarge,tonalElevation=6.dp){
            Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                Text("Обход геоблокировок",style=MaterialTheme.typography.titleLarge)
                Text("Помогает открыть отдельные сервисы через DNS-провайдера. Работает вместе с WARP; доступность зависит от провайдера.",style=MaterialTheme.typography.bodySmall)
                Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){
                    Text("Готовые варианты · ${AwgDnsPolicy.providers.size}",Modifier.weight(1f),style=MaterialTheme.typography.labelLarge)
                    TextButton(onClick={help=true}){Text("О функции")}
                }
                if(list.canScrollBackward)Text("↑ Ещё варианты выше",style=MaterialTheme.typography.labelSmall)
                LazyColumn(Modifier.weight(1f),state=list,verticalArrangement=Arrangement.spacedBy(4.dp)){
                    item{DnsOption("Выключен","Обычный DNS WARP",selected=="off"){selected="off"}}
                    for(p in AwgDnsPolicy.providers)item{
                        DnsOption(p.name,p.url,selected==p.id){selected=p.id}
                    }
                }
                Text(if(list.canScrollForward)"↓ Ещё провайдеры — прокрутите список" else "Все готовые варианты показаны",
                    style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
                HorizontalDivider()
                // Custom entry and action buttons never scroll out of view.
                DnsOption("Свой DoH — ввести адрес","Ручная настройка DNS",selected=="custom"){selected="custom"}
                if(selected=="custom"){
                    OutlinedTextField(value=custom,onValueChange={custom=it.take(2048)},singleLine=true,
                        label={Text("Адрес DoH")},placeholder={Text("https://dns.example/dns-query")},
                        isError=custom.isNotEmpty() && !valid,modifier=Modifier.fillMaxWidth())
                    if(!valid)Text("Нужен HTTPS-адрес без логина, пароля и фрагмента #.",style=MaterialTheme.typography.labelSmall)
                }
                Text(if(connected)"Отключите VPN, чтобы сохранить изменения."
                    else "Применится при подключении. В Chrome выберите DNS системы.",style=MaterialTheme.typography.bodySmall)
                Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.End){
                    TextButton(onClick=onDismiss){Text("Закрыть")}
                    TextButton(enabled=valid && !busy && !connected,onClick={onSave(selected,custom)}){Text("Сохранить")}
                }
            }
        }
    }
    if(help)AlertDialog(onDismissRequest={help=false},title={Text("Как работает обход")},text={
        Text("Провайдер получает DNS-запросы и может передавать трафик поддерживаемых сервисов. Общий IP может остаться российским. Собственный DNS браузера и Android «Частный DNS» могут переопределять выбор приложения. Если провайдер недоступен, обычный DNS автоматически не подставляется.")
    },confirmButton={TextButton(onClick={help=false}){Text("Понятно")}})
}

@Composable
private fun DnsOption(title:String,subtitle:String,selected:Boolean,onClick:()->Unit){
    Row(Modifier.fillMaxWidth().heightIn(min=56.dp).selectable(selected=selected,role=Role.RadioButton,onClick=onClick),
        verticalAlignment=Alignment.CenterVertically){
        RadioButton(selected=selected,onClick=null)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)){
            Text(title,style=MaterialTheme.typography.bodyLarge)
            Text(subtitle,style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
