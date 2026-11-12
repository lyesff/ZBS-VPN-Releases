package dev.autowarp

import org.json.JSONObject

/** Retired experimental settings must not keep affecting upgraded profiles. */
internal object AwgSettingsMigration {
    fun apply(state:JSONObject){
        state.remove("awgEuropeanNode")
        state.remove("awgExcludeRussia")
        if(state.optString("awgDohProvider")=="zapret")state.put("awgDohProvider","off")
    }
}
