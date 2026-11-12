package dev.autowarp

import java.net.InetAddress
import java.net.Inet6Address
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.SocketException
import javax.net.ssl.SSLException

/** Fixed messages only: native errors, configs and registration tokens are never shown. */
internal object AwgNestedResult {
    private val httpCode=Regex("awg_nested_reg_http_[1-5][0-9]{2}")
    private val texts=mapOf(
        "awg_nested_running" to "Проверка двойного WARP выполняется…",
        "awg_nested_prepared" to "Второй профиль готов; ожидается запуск пробы и разрешение Android, если оно потребуется.",
        "awg_nested_prepare_failed" to "Подготовка второго профиля не завершилась. Проба двойного WARP не запускалась.",
        "awg_nested_reg_wait" to "До повторной регистрации действует пауза. Повторите позже; проба ещё не запускалась.",
        "awg_nested_reg_timeout" to "Сервер регистрации второго профиля не ответил вовремя. Проба не запускалась.",
        "awg_nested_reg_dns" to "Не удалось разрешить адрес сервера регистрации. Проба не запускалась.",
        "awg_nested_reg_tls" to "Не удалось установить защищённое соединение с сервером регистрации. Проба не запускалась.",
        "awg_nested_reg_network" to "Соединение с сервером регистрации не удалось. Проба не запускалась.",
        "awg_nested_reg_format" to "Ответ регистрации не удалось преобразовать в корректный второй профиль. Проба не запускалась.",
        "awg_nested_launch_blocked" to "Второй профиль готов, но запуск пробы заблокирован состоянием приложения. Отключите VPN и повторите проверку.",
        "awg_nested_permission_denied" to "Разрешение Android на VPN не получено; проба не запускалась.",
        "awg_nested_verified" to "HTTPS через двойной WARP подтверждён; страна IP вне РФ. Это временная проба, а не системный VPN.",
        "awg_nested_region_ru" to "Двойной WARP передал HTTPS, но страна IP осталась РФ.",
        "awg_nested_geo_disagree" to "Двойной WARP передал HTTPS, но Trace и Speedtest определили разные страны IP. Зарубежный выход для приложений пока не подтверждён.",
        "awg_nested_region_unknown" to "Двойной WARP передал HTTPS, но страна IP не определена.",
        "awg_nested_outer_node" to "Первый WARP работает, но узел не подтверждён как европейский. Сначала подберите европейский узел обычного подключения.",
        "awg_nested_outer_failed" to "Не удалось подтвердить HTTPS через первый WARP.",
        "awg_nested_inner_failed" to "Первый WARP работает; HTTPS через вложенный туннель не подтверждён.",
        "awg_nested_same_key" to "Для двух туннелей нужны разные ключи.",
        "awg_nested_invalid" to "Не удалось подготовить два корректных профиля.",
        "awg_nested_protect_failed" to "Не удалось защитить внешний UDP-сокет от VPN.",
        "awg_nested_stopped" to "Проверка отменена или достигнут общий лимит времени.",
        "awg_nested_failed" to "Эксперимент не завершён. Сохранённый основной профиль не менялся."
    )
    fun safe(code:String)=code.takeIf {it in texts || httpCode.matches(it)} ?: "awg_nested_failed"
    fun text(code:String):String {
        val safe=safe(code)
        return if(httpCode.matches(safe))"Регистрация второго устройства: Cloudflare вернул HTTP ${safe.takeLast(3)}. Проба не запускалась."
            else texts[safe].orEmpty()
    }
    fun preparationFailure(error:Exception):String {
        val message=error.message.orEmpty()
        val http=Regex("Cloudflare HTTP ([1-5][0-9]{2})").matchEntire(message)
        return when{
            http!=null->"awg_nested_reg_http_"+http.groupValues[1]
            message=="Пауза регистрации"->"awg_nested_reg_wait"
            error is SocketTimeoutException->"awg_nested_reg_timeout"
            error is UnknownHostException->"awg_nested_reg_dns"
            error is SSLException->"awg_nested_reg_tls"
            error is SocketException->"awg_nested_reg_network"
            error is org.json.JSONException || error is IllegalArgumentException->"awg_nested_reg_format"
            else->"awg_nested_prepare_failed"
        }
    }
    fun numericIP(raw:String):String {
        if(raw.length !in 1..45 || raw.any {it !in "0123456789abcdefABCDEF:."})return ""
        val ipv4=raw.split('.').let {parts->parts.size==4 && parts.all {part->
            part.isNotEmpty() && part.all {it in '0'..'9'} && (part.toIntOrNull() ?: -1) in 0..255
        }}
        if(ipv4)return raw
        if(':' in raw && runCatching{InetAddress.getByName(raw) is Inet6Address}.getOrDefault(false))return raw
        return ""
    }
}
