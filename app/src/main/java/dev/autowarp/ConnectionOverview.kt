package dev.autowarp

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
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
    val accent=if(ready && live.phase==Phase.ERROR)Neon.Error else if(connected)Neon.Green else Neon.Ice
    val seconds=if(connected)((now-live.start)/1000).coerceAtLeast(0) else 0
    val duration=if(connected)"%02d:%02d:%02d".format(seconds/3600,seconds/60%60,seconds%60) else "—"
    NeonPanel(accent,contentPadding=14.dp,spacing=9.dp){
        Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)){
            NeonSymbol(if(connected)NeonGlyph.CHECK else NeonGlyph.SHIELD,Modifier.size(32.dp),accent)
            Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(3.dp)){
                Text(title,fontSize=20.sp,fontWeight=FontWeight.Bold,color=Color(0xffDFFFEF),lineHeight=24.sp)
                Text(detail,fontSize=12.sp,lineHeight=15.sp,color=Neon.Muted)
            }
        }
        if(ready && (live.phase==Phase.CONNECTING || live.phase==Phase.DISCONNECTING))
            LinearProgressIndicator(Modifier.fillMaxWidth(),color=accent,trackColor=Color(0xff173F40))
        HorizontalDivider(color=Color(0xff29484D))
        Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.spacedBy(16.dp)){
            NeonMetric("Загрузка",if(connected)formatTransferRate(live.down) else "—",NeonGlyph.DOWN,Modifier.weight(1f))
            NeonMetric("Отправка",if(connected)formatTransferRate(live.up) else "—",NeonGlyph.UP,Modifier.weight(1f))
        }
        Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.spacedBy(16.dp)){
            NeonMetric("HTTPS",if(connected)"${live.ms} мс" else "—",NeonGlyph.PULSE,Modifier.weight(1f))
            NeonMetric("Время",duration,NeonGlyph.CLOCK,Modifier.weight(1f))
        }
        HorizontalDivider(color=Color(0xff29484D))
        Column(verticalArrangement=Arrangement.spacedBy(4.dp)){
            Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(7.dp)){
                NeonSymbol(NeonGlyph.GLOBE,Modifier.size(14.dp),Neon.Ice)
                Text("Внешний IP · "+(if(connected)live.ip else "—"),fontSize=12.sp,lineHeight=15.sp,color=Color(0xffC0D3DC))
            }
            if(!connected || live.route=="AmneziaWG · Android")Row(
                verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(7.dp)){
                NeonSymbol(NeonGlyph.SHIELD,Modifier.size(14.dp),Neon.Ice)
                Text(if(connected)"Страна IP · "+AwgRegionPolicy.label(live.country)+" · Cloudflare" else "Страна IP · —",
                    fontSize=12.sp,lineHeight=15.sp,color=Color(0xffC0D3DC))
            }
        }
    }
}

@Composable private fun NeonMetric(label:String,value:String,glyph:NeonGlyph,modifier:Modifier){
    Column(modifier,verticalArrangement=Arrangement.spacedBy(2.dp)){
        Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(5.dp)){
            NeonSymbol(glyph,Modifier.size(14.dp))
            Text(label,fontSize=11.sp,lineHeight=13.sp,color=Neon.Muted)
        }
        Text(value,fontSize=if(glyph==NeonGlyph.CLOCK)16.sp else 17.sp,lineHeight=21.sp,fontWeight=FontWeight.SemiBold,
            fontFamily=FontFamily.Monospace,color=Color(0xffEAF8FA))
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

