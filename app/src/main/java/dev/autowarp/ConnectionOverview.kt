package dev.autowarp

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import java.util.Locale

@Composable internal fun ConnectionOverview(
    live:Live,ready:Boolean,hasProfile:Boolean,now:Long,eventCode:String
){
    val connected=ready && live.phase==Phase.CONNECTED
    val title=when{
        !ready->"Проверяем состояние…"
        connected->"Подключено"
        live.phase==Phase.CONNECTING->"Подключаемся…"
        live.phase==Phase.DISCONNECTING->"Отключаемся…"
        live.phase==Phase.ERROR->"Не удалось подключиться"
        !hasProfile->"Начнём с профиля"
        else->"Готово к подключению"
    }
    val detail=when{
        !ready->"Получаем состояние VPN на устройстве."
        connected && live.route=="AmneziaWG · Android"->"WARP · маскировка включена"
        connected->live.kind
        live.phase==Phase.CONNECTING->when(eventCode){
            "awg_vpn_transport_preflight_start","awg_vpn_transport_preflight"->"Проверяем доступность WARP…"
            "awg_vpn_tun","awg_vpn_post_tun_start","awg_vpn_post_tun"->"Настраиваем VPN на устройстве…"
            "awg_vpn_handshake","awg_vpn_go_before","awg_vpn_tcp_connected","awg_vpn_tls_ready"->"Проверяем доступ к интернету…"
            else->"Подготавливаем защищённое подключение…"
        }
        live.phase==Phase.DISCONNECTING->"Завершаем подключение."
        live.phase==Phase.ERROR->when(live.reason){
            Reason.DENIED,Reason.REVOKED->"Для подключения нужно разрешение Android на VPN."
            Reason.REGION_RU->"Cloudflare определил геолокацию IP как РФ. Фильтр страны остановил подключение."
            Reason.REGION_UNKNOWN->"Не удалось определить страну IP. При включённом фильтре такое подключение отклоняется."
            Reason.NO_PROFILE->"Создайте или импортируйте профиль в разделе «Профиль»."
            Reason.NO_EXIT->"Не удалось подтвердить доступ к интернету через WARP. Попробуйте ещё раз."
            else->"Попробуйте подключиться ещё раз. Подробности доступны в диагностике."
        }
        !hasProfile->"Создайте профиль автоматически или импортируйте готовый."
        else->"Ваш профиль сохранён. Можно включать VPN."
    }
    Card(Modifier.fillMaxWidth(),colors=CardDefaults.cardColors(
        containerColor=if(connected)Color(0xff153c34) else MaterialTheme.colorScheme.surfaceVariant
    )){
        Column(Modifier.padding(24.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){
            Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)){
                Surface(Modifier.size(10.dp),shape=CircleShape,color=when{
                    connected->MaterialTheme.colorScheme.primary
                    live.phase==Phase.ERROR->MaterialTheme.colorScheme.error
                    else->MaterialTheme.colorScheme.outline
                }){}
                Text(title,style=MaterialTheme.typography.headlineSmall)
            }
            Text(detail,style=MaterialTheme.typography.bodyMedium)
            if(ready && (live.phase==Phase.CONNECTING || live.phase==Phase.DISCONNECTING))
                LinearProgressIndicator(Modifier.fillMaxWidth())
            if(connected){
                HorizontalDivider(color=MaterialTheme.colorScheme.outlineVariant)
                Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.spacedBy(16.dp)){
                    Column(Modifier.weight(1f)){
                        Text("↓ Загрузка",style=MaterialTheme.typography.labelMedium)
                        Text(formatTransferRate(live.down),style=MaterialTheme.typography.titleMedium)
                    }
                    Column(Modifier.weight(1f)){
                        Text("↑ Отправка",style=MaterialTheme.typography.labelMedium)
                        Text(formatTransferRate(live.up),style=MaterialTheme.typography.titleMedium)
                    }
                }
                val sec=((now-live.start)/1000).coerceAtLeast(0)
                Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween){
                    Text("HTTPS · ${live.ms} мс",style=MaterialTheme.typography.bodySmall)
                    Text("%02d:%02d:%02d".format(sec/3600,sec/60%60,sec%60),style=MaterialTheme.typography.bodySmall)
                }
                Text("Внешний IP · "+live.ip,style=MaterialTheme.typography.bodySmall)
                if(live.route=="AmneziaWG · Android")Text("Страна IP · "+AwgRegionPolicy.label(live.country)+" · Cloudflare",style=MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** Inner-IP bytes/second. Small transfers remain visible instead of rounding to zero KiB. */
internal fun formatTransferRate(bytes:Long):String=when{
    bytes<=0->"0 Б/с"
    bytes<1024->"$bytes Б/с"
    bytes<1024L*1024->String.format(Locale.ROOT,"%.1f КиБ/с",bytes/1024.0)
    bytes<1024L*1024*1024->String.format(Locale.ROOT,"%.1f МиБ/с",bytes/(1024.0*1024))
    else->String.format(Locale.ROOT,"%.1f ГиБ/с",bytes/(1024.0*1024*1024))
}
