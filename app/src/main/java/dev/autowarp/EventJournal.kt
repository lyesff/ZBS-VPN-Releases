package dev.autowarp

import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Human-readable status from fixed, non-sensitive codes only. */
internal fun eventText(event:JSONObject):String {
    val code=event.optString("code")
    val kind=when(event.optString("kind")){"WARP"->"WARP";"VLESS"->"VLESS";else->"Маршрут"}
    val i=event.optInt("index",0)
    val total=event.optInt("total",0)
    val point=if(i>0 && total>0)" $i/$total" else ""
    val ms=event.optLong("ms",-1)
    val reason=when(event.optString("error")){
        "probe_timeout"->"таймаут HTTPS"
        "probe_cancelled"->"отменено"
        "probe_dns"->"ошибка DNS"
        "probe_tls_certificate"->"ошибка сертификата"
        "probe_tls_handshake"->"ошибка TLS"
        "probe_network_unreachable"->"нет сети"
        "probe_host_unreachable"->"адрес недоступен"
        "probe_connection_refused"->"отказ в соединении"
        "probe_connection_reset"->"сброс соединения"
        "probe_connection_closed"->"соединение закрыто"
        "probe_trace_body"->"ответ HTTPS некорректен"
        "probe_trace_ip"->"IP не подтверждён"
        "probe_warp_not_confirmed"->"WARP не подтверждён"
        "probe_transport"->"ошибка транспорта"
        else->"HTTPS-проверка не прошла"
    }
    return when(code){
        "awg_vpn_watchdog_failed"->"Фоновая проверка HTTPS не прошла"+(if(i>0)" · подряд $i" else "")+": "+awgVerifyErrorText(event.optString("error"))
        "awg_vpn_network_wait"->"Физическая сеть недоступна; ожидаем сеть"
        "awg_vpn_network_changed"->"Физическая сеть сменилась; начинаем восстановление VPN"
        "awg_vpn_wifi_preferred"->"Wi-Fi прошёл проверку; переключаем VPN на Wi-Fi"
        "awg_vpn_wifi_probe_failed"->"Проверка возврата на Wi-Fi не прошла"
        "awg_vpn_network_monitor_unavailable"->"Не удалось зарегистрировать наблюдение за сетью"
        "awg_screen_off"->"Экран выключен"
        "awg_screen_on"->"Экран включён"
        "awg_idle_enter"->"Android сообщил о входе в Doze"
        "awg_idle_exit"->"Android сообщил о выходе из Doze"
        "awg_battery_exempt"->"Системное исключение из оптимизации батареи включено"
        "awg_battery_optimized"->"Системное исключение из оптимизации батареи не включено"
        "awg_notifications_enabled"->"Уведомления VPN разрешены"
        "awg_notifications_disabled"->"Уведомления VPN скрыты системной настройкой или разрешением"
        "awg_background_monitor_started"->"Наблюдение за сном и пробуждением включено"
        "awg_background_monitor_unavailable"->"Не удалось зарегистрировать наблюдение за сном"
        "awg_vpn_network_blocked"->"Android сообщил о блокировке физической сети для приложения"
        "awg_vpn_network_unblocked"->"Android сообщил, что физическая сеть не заблокирована"
        "awg_vpn_network_suspended"->"Физическая сеть помечена системой как приостановленная"
        "awg_vpn_network_resumed"->"Физическая сеть помечена системой как активная"
        "awg_vpn_recovery_start"->"Автоматическое восстановление: закрываем прежний туннель"
        "awg_vpn_user_stop"->"Получена пользовательская команда отключения VPN"
        "awg_vpn_permission_revoked"->"Android отозвал разрешение VPN"
        "awg_vpn_service_destroyed"->"VPN-служба завершает работу"
        "awg_doh_start"->"Обход геоблокировок: запускаем DNS over HTTPS через WARP"
        "awg_doh_ready"->"DNS over HTTPS ответил через WARP; доступ к отдельным сервисам зависит от провайдера"
        "awg_doh_failed"->"DNS over HTTPS не ответил корректно. Выберите другого провайдера или выключите обход геоблокировок"
        "start"->"Запуск VPN"
        "network_wifi"->"Исходная сеть: Wi-Fi"
        "network_cellular"->"Исходная сеть: мобильная"
        "network_other"->"Исходная сеть: другая"
        "network_missing"->"Исходная сеть не найдена"
        "core_start"->"Подготовка VPN-ядра"
        "core_ready"->"VPN-ядро и TUN запущены"
        "probe_start"->"$kind$point · проверка HTTPS через маршрут"
        "probe_ok"->"$kind$point · HTTPS подтверждён"+if(ms>=0)" ($ms мс)" else ""
        "probe_fail"->"$kind$point · $reason"
        "route_switch"->"Переключение на маршрут $kind"
        "route_online"->"$kind · маршрут работает"+if(ms>=0)" ($ms мс)" else ""
        "route_failed"->"Не удалось подтвердить ни один проверенный маршрут"
        "recover"->"Повторная проверка и восстановление"
        "stopped"->"VPN-сервис останавливается"
        "core_failed"->"Ошибка запуска VPN-ядра"
        "scan_start"->"Начало проверки серверов"
        "scan_done"->"Проверка серверов завершена"
        "awg_nested_prepared"->"Двойной WARP: второй профиль готов; передаём запуск VPN-службе"
        "awg_nested_prepare_failed"->AwgNestedResult.text(event.optString("error"))
        "awg_nested_reg_post"->"Двойной WARP: запрашиваем регистрацию второго устройства Cloudflare"
        "awg_nested_reg_activate"->"Двойной WARP: активируем второе устройство Cloudflare"
        "awg_nested_prepare"->"Двойной WARP: готовим отдельный второй профиль; основной не меняется"
        "awg_nested_start"->"Двойной WARP: временная HTTPS-проверка; системный VPN не создаётся"
        "awg_nested_outer_country"->"Первый WARP: страна IP — "+AwgRegionPolicy.label(event.optString("error").removePrefix("awg_country_"))
        "awg_nested_inner_country"->"Двойной WARP: страна IP — "+AwgRegionPolicy.label(event.optString("error").removePrefix("awg_country_"))
        "awg_nested_outer_meta"->"Первый WARP · Speedtest: страна IP — "+AwgRegionPolicy.label(event.optString("error").removePrefix("awg_country_"))
        "awg_nested_inner_meta"->"Двойной WARP · Speedtest: страна IP — "+AwgRegionPolicy.label(event.optString("error").removePrefix("awg_country_"))
        "awg_nested_meta_node"->"Двойной WARP · Speedtest: узел — "+event.optString("error").removePrefix("awg_colo_")
        "awg_nested_done"->AwgNestedResult.text(event.optString("error"))
        "awg_vpn_start"->"AWG VPN: запуск системного туннеля"
        "awg_vpn_mask_retry"->"Авто: пробуем следующую маскировку · попытка $i"
        "awg_node_scan_start"->"AWG: предварительный HTTPS-подбор узлов Cloudflare; это ещё не проверка туннеля"
        "awg_node_scan_done"->"AWG: найдено кандидатов европейского узла: $i; дальше проверяем настоящий AWG"
        "awg_vpn_trace_node"->"AWG: узел HTTPS-проверки Cloudflare — "+event.optString("error").removePrefix("awg_colo_").let {if(it=="unknown")"не определён" else it}
        "awg_picker_start"->"AWG: проверяем до 8 точек входа с выбранными фильтрами узла и страны IP"
        "awg_picker_candidate"->"AWG: проверка точки входа #$i через защищённый UDP и HTTPS"
        "awg_picker_exhausted"->"AWG: среди проверенных точек подходящая не найдена; сохранённый профиль не изменён"
        "awg_picker_saved"->"AWG: новая точка сохранена после подтверждения системного HTTPS и WARP"
        "awg_vpn_mask_original"->"AWG: исходная маскировка сохранённого профиля"
        "awg_vpn_mask_quic"->"AWG: QUIC I1, новый пакет этого запуска"
        "awg_vpn_mask_dns"->"AWG: DNS I1, новый пакет этого запуска"
        "awg_vpn_mask_stun"->"AWG: STUN I1, новый пакет этого запуска"
        "awg_vpn_mask_router_i1"->"AWG: встроенная маскировка I1"
        "awg_vpn_scope_app"->"AWG: тест только AutoWARP; трафик других приложений исключён из туннеля"
        "awg_vpn_scope_all"->"AWG: системный VPN для всех приложений"
        "awg_vpn_app_only_verified"->"AWG: HTTPS и WARP для AutoWARP подтверждены; проверочный VPN отключается"
        "awg_vpn_tun"->"AWG VPN: интерфейс Android создан"
        "awg_vpn_handshake"->"AWG VPN: handshake получен, проверяем HTTPS"
        "awg_vpn_check_start"->"AWG: проверяем HTTPS и WARP через текущее подключение"
        "awg_vpn_check_ok"->"AWG: текущее подключение проверено — HTTPS и WARP подтверждены"+if(ms>=0)" ($ms мс)" else ""
        "awg_vpn_check_failed"->"AWG: проверка текущего подключения не прошла — "+awgVerifyErrorText(event.optString("error"))
        "awg_vpn_exit_country"->"AWG: страна IP по Cloudflare — "+AwgRegionPolicy.label(event.optString("error").removePrefix("awg_country_"))
        "awg_vpn_region_rejected"->"AWG: фильтр страны остановил VPN — "+awgVerifyErrorText(event.optString("error"))
        "awg_vpn_verified"->"AWG VPN: HTTPS и WARP подтверждены"
        "awg_vpn_flow"->"AWG: "+when(event.optString("error")){
            "awg_flow_no_tun_in"->"Android не передал IP-пакеты в TUN"
            "awg_flow_no_tun_out"->"пакеты вошли в TUN, но ответов из AWG нет"
            "awg_flow_bidirectional"->"пакеты прошли TUN в обе стороны; проверяем TCP"
            else->"не удалось получить счётчики пакетов"
        }
        "awg_vpn_tcp_trace","awg_vpn_tcp_bound","awg_vpn_tcp_default"->
            (when(code){
                "awg_vpn_tcp_bound"->"AWG TCP (привязка к VPN): "
                "awg_vpn_tcp_default"->"AWG TCP (маршрутизация Android): "
                else->"AWG TCP: "
            })+when(event.optString("error")){
            "awg_tcp_source_mismatch"->"исходный IP SYN не совпал с адресом TUN"
            "awg_tcp_destination_mismatch"->"IP назначения ответа не совпал с адресом TUN"
            "awg_tcp_sequence_mismatch"->"номер ACK ответа не равен SYN+1"
            "awg_tcp_bad_ip_checksum"->"ответ имеет неверную контрольную сумму IPv4"
            "awg_tcp_bad_tcp_checksum"->"ответ имеет неверную контрольную сумму TCP"
            "awg_tcp_bad_format"->"неверная длина IP/TCP или фрагментированный ответ"
            "awg_tcp_tun_write_failed"->"ошибка записи пакета в Android TUN"
            "awg_tcp_synack_not_written"->"корректный SYN-ACK найден, запись в TUN не подтверждена"
            "awg_tcp_matched_no_ack"->"SYN-ACK нашего сокета корректен: IP, порты, ACK и суммы; записан в TUN, ACK Android не наблюдался"
            "awg_tcp_android_ack"->"Android отправил финальный ACK нашего сокета; TCP-обмен подтверждён"
            "awg_tcp_android_rst"->"Android отправил RST нашего сокета"
            "awg_tcp_unrelated_reply"->"ответы относятся к другим сокетам; ответа нашему SYN нет"
            "awg_tcp_no_syn"->"SYN до 1.1.1.1:443 в TUN не наблюдался"
            "awg_tcp_synack"->"ответ SYN-ACK из WARP в TUN поступил"
            "awg_tcp_rst"->"сервер или промежуточный узел вернул TCP RST"
            "awg_tcp_no_reply"->"SYN отправлен, но SYN-ACK/RST из WARP нет"
            else->"не удалось измерить TCP-флаги"
        }
        "awg_vpn_post_tun_start"->"AWG: VPN уже включён; проверяем прежний netstack до переключения на Android TCP"
        "awg_vpn_post_tun"->"AWG после создания TUN (netstack): "+when{
            event.optString("error").startsWith("awg_verified:")->"HTTPS и WARP подтверждены"
            event.optString("error")=="awg_not_confirmed"->"HTTPS получен, WARP не подтверждён"
            event.optString("error")=="awg_no_handshake"->"handshake не подтверждён"
            event.optString("error")=="awg_tcp_timeout"->"TCP не ответил вовремя"
            event.optString("error")=="awg_tls_timeout"->"TCP есть, TLS не ответил вовремя"
            event.optString("error")=="awg_http_timeout"->"TLS есть, HTTP не ответил вовремя"
            else->"HTTPS не подтверждён"
        }
        "awg_vpn_post_tun_udp"->"AWG UDP контроль после создания TUN: "+when(event.optString("error")){
            "awg_post_udp_no_send"->"отправки UDP не наблюдалось"
            "awg_post_udp_no_reply"->"UDP отправлялся, входящих UDP нет"
            "awg_post_udp_send_error"->"ошибка отправки UDP"
            "awg_post_udp_receive_error"->"ошибка чтения UDP"
            "awg_post_udp_bidirectional"->"UDP прошёл в обе стороны; это ещё не подтверждение Android TCP"
            else->"результат недоступен"
        }
        "awg_vpn_transport_state"->"AWG UDP параметры сокета: "+when(event.optString("error")){
            "awg_transport_unchanged"->"сетевая метка и порт сохранены"
            "awg_transport_mark_changed"->"после создания VPN изменилась сетевая метка"
            "awg_transport_port_changed"->"после создания VPN изменился порт"
            else->"проверка недоступна"
        }
        "awg_vpn_session_reused"->"AWG: Android TUN подключён к уже проверенной сессии без перезапуска движка"
        "awg_vpn_udp_reused"->"AWG UDP: системный режим использует тот же защищённый сокет, что и проба до TUN"
        "awg_vpn_udp_bound"->"AWG UDP: Android принял привязку сокета к физической сети и защиту от VPN"
        "awg_vpn_udp_bind_failed"->"AWG UDP: привязка к физической сети или защита сокета не прошла"
        "awg_vpn_udp_flow"->"AWG UDP: "+when(event.optString("error")){
            "awg_udp_loop"->"обнаружен внешний UDP нашего AWG-сокета внутри TUN; петля остановлена"
            "awg_udp_no_send"->"успешных отправок UDP не зарегистрировано"
            "awg_udp_no_reply"->"UDP отправлялся, входящих UDP-пакетов нет"
            "awg_udp_no_plaintext"->"UDP-пакеты получены, расшифрованные IP-пакеты в TUN не поступили"
            "awg_udp_bidirectional"->"UDP-пакеты получены и расшифрованные IP-пакеты переданы в TUN"
            else->"не удалось измерить UDP-обмен"
        }
        "awg_vpn_tcp_data"->"AWG данные: "+when(event.optString("error")){
            "awg_data_bad_out_checksum"->"данные Android имеют неверную контрольную сумму IP/TCP"
            "awg_data_bad_in_checksum"->"ответ имеет неверную контрольную сумму IP/TCP"
            "awg_data_udp_error"->"UDP-транспорт сообщил ошибку отправки или приёма"
            "awg_data_no_tcp"->"TCP-обмен этой попытки не завершён"
            "awg_data_no_client_data"->"TCP есть, но данные TLS от Android в TUN не наблюдались"
            "awg_data_server_data"->"сервер вернул TCP-данные; проверяем TLS"
            "awg_data_server_ack"->"сервер подтвердил приём данных клиента, ответных данных нет"
            "awg_data_no_reply"->"данные клиента вошли в TUN, подтверждения сервера нет"
            else->"не удалось измерить передачу TCP-данных"
        }
        "awg_vpn_transport_preflight_start"->"AWG: проверяем защищённый UDP до создания Android TUN"
        "awg_vpn_transport_preflight"->"AWG до создания TUN: "+when{
            event.optString("error").startsWith("awg_verified:")->"HTTPS и WARP через защищённый UDP подтверждены"
            event.optString("error")=="awg_no_handshake"->"ответ handshake не получен"
            event.optString("error")=="awg_tcp_timeout"->"handshake есть, TCP не ответил"
            event.optString("error")=="awg_tls_timeout"->"TCP есть, TLS не ответил"
            event.optString("error")=="awg_http_timeout"->"TLS есть, HTTP не ответил"
            event.optString("error")=="awg_not_confirmed"->"HTTPS работает, WARP не подтверждён"
            event.optString("error")=="awg_device_start_failed"->"не удалось запустить защищённый UDP"
            event.optString("error")=="awg_preflight_skipped"->"контроль пропущен: уже существует VPN"
            else->"HTTPS не подтверждён"
        }
        "awg_vpn_go_before","awg_vpn_go_after"->"Контроль Go TLS через Android TUN "+
            (if(code=="awg_vpn_go_before")"до проверки: " else "после сбоя: ")+
            when(event.optString("error")){
                "awg_control_verified"->"HTTPS и WARP подтверждены; это контроль, а не статус VPN"
                "awg_control_not_warp"->"HTTPS прошёл через TUN, но WARP не подтверждён"
                "awg_control_bind_failed"->"не удалось привязать TCP-сокет к VPN"
                "awg_control_no_network"->"Android ещё не предоставил VPN-сеть"
                "awg_control_tcp_timeout"->"TCP не ответил вовремя"
                "awg_control_tcp_failed"->"TCP не подключился"
                "awg_control_tls_timeout"->"TCP есть, TLS не ответил вовремя"
                "awg_control_tls_failed"->"ошибка TLS или сертификата"
                "awg_control_http_timeout"->"HTTP не ответил вовремя"
                "awg_control_http_failed"->"HTTP не подтверждён"
                "awg_control_path_no_syn"->"HTTPS получен, но диагностика не отметила SYN нашего сокета"
                "awg_control_path_no_synack"->"HTTPS получен, но диагностика не сопоставила SYN-ACK"
                "awg_control_path_no_write"->"HTTPS получен, но запись SYN-ACK в TUN не отмечена"
                "awg_control_path_no_ack"->"HTTPS получен, но финальный TCP ACK не отмечен"
                "awg_control_wrong_path"->"HTTPS не сопоставлен с TCP этого TUN"
                else->"контроль остановлен"
            }
        "awg_vpn_tcp_connected"->"AWG VPN: TCP подключён; начинаем TLS"
        "awg_vpn_tls_ready"->"AWG VPN: TLS и сертификат проверены; проверяем HTTP"
        "awg_vpn_verify_attempt"->"AWG-проверка"+(if(i>0)" #$i" else "")+": "+awgVerifyErrorText(event.optString("error"))
        "awg_vpn_failed"->"AWG VPN: "+awgVerifyErrorText(event.optString("error"))+"; туннель остановлен"
        "awg_probe_start"->"AWG: поднятие временного туннеля и HTTPS-проверка"
        "awg_probe_ok"->"AWG: HTTPS через WARP подтверждён"
        "awg_probe_fail"->"AWG: "+when(event.optString("error")){
            "awg_invalid_file","awg_invalid_config"->"неправильный формат конфигурации"
            "awg_tun_create_failed"->"не удалось создать временный интерфейс"
            "awg_ipc_config_failed"->"движок отклонил параметры"
            "awg_endpoint_dns_failed"->"не удалось получить публичный IPv4 endpoint"
            "awg_device_start_failed"->"не удалось запустить AWG-устройство"
            "awg_no_handshake"->"подключение не получило handshake"
            "awg_https_timeout"->"handshake получен, но HTTPS не ответил"
            "awg_tcp_timeout"->"handshake есть, TCP-соединение не установлено"
            "awg_tls_timeout"->"TCP подключён, но TLS не завершился"
            "awg_http_timeout"->"TLS прошёл, но HTTP-ответ не пришёл"
            "awg_not_confirmed"->"HTTPS ответил, но WARP не подтверждён"
            "awg_https_failed"->"HTTPS не прошёл"
            else->"туннель не прошёл проверку"
        }
        else->"Событие диагностики"
    }
}
internal fun eventLine(event:JSONObject):String {
    val whenAt=event.optLong("at",0L)
    val stamp=if(whenAt>0)SimpleDateFormat("HH:mm:ss",Locale.ROOT).format(Date(whenAt)) else "--:--:--"
    return "$stamp  ${eventText(event)}"
}


/** Fixed messages shared by individual attempts and the final failure. */
internal fun awgVerifyErrorText(code:String):String=when(code){
    "awg_vpn_node_rejected"->"узел HTTPS-проверки не входит в список европейских или не определён; вариант отклонён"
    "awg_vpn_preflight_failed"->"исходная HTTPS-проверка не прошла до создания TUN; системный тест не запускался"
    "awg_vpn_region_ru"->"проверка Cloudflare определила РФ; подключение отклонено фильтром страны"
    "awg_vpn_region_unknown"->"страна IP не определена; подключение отклонено фильтром страны"
    "awg_vpn_existing_vpn"->"уже включён другой VPN; отключите его перед запуском AWG"
    "awg_vpn_udp_loop"->"внешний UDP AWG попал обратно в VPN; обнаружена маршрутизационная петля"
    "awg_vpn_no_network"->"Android не предоставил VPN-сеть для проверки"
    "awg_vpn_tcp_timeout"->"таймаут подключения TCP до 1.1.1.1 через VPN"
    "awg_vpn_tcp_failed"->"TCP до 1.1.1.1 через VPN не подключился"
    "awg_vpn_tls_timeout"->"TCP подключён, но TLS не ответил вовремя"
    "awg_vpn_tls_certificate"->"TCP подключён, проверка сертификата или имени TLS не прошла"
    "awg_vpn_tls_failed"->"TCP подключён, ошибка согласования TLS"
    "awg_vpn_http_timeout"->"TLS завершён, но HTTP-ответ не получен вовремя"
    "awg_vpn_http_failed"->"TLS завершён, HTTP-ответ некорректен или не получен"
    "awg_vpn_wrong_path"->"HTTPS ответил, но прохождение проверочного сокета через этот TUN не подтверждено"
    "awg_vpn_warp_missing"->"HTTPS ответил, но WARP не подтверждён"
    "awg_vpn_start_failed"->"системный туннель не запустился"
    "awg_vpn_doh_failed"->"выбранный DNS over HTTPS недоступен; выберите другого провайдера или выключите обход геоблокировок"
    else->"проверка не прошла"
}

