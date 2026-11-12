package dev.autowarp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class DiagnosticsTest {
    @Test fun reportNeverIncludesKeysOrTokens() {
        val secret="SUPER_SECRET_DO_NOT_EXPORT"
        val profile=JSONObject().put("config",JSONObject().put("private_key",secret)
            .put("peers",JSONArray().put(JSONObject().put("reserved",JSONArray().put(1).put(2).put(3)))))
        val state=JSONObject()
            .put("keys",JSONObject().put("private",secret))
            .put("registeredConf",secret)
            .put("reg",JSONObject().put("token",secret))
            .put("warp","test")
            .put("wg",JSONObject().put("test",profile))
            .put("health",JSONObject().put("w-confidential-tag",
                JSONObject().put("ms",-1).put("error","probe_timeout").put("at",1234)))
        val report=diagnosticReport(state,"Ошибка")
        assertFalse(report.toString().contains(secret))
        assertFalse(report.toString().contains("confidential-tag"))
        assertTrue(report.getBoolean("reserved_length_valid"))
        assertEquals("probe_timeout",report.getJSONArray("last_checks").getJSONObject(0).getString("error"))
    }

    @Test fun unknownProbeErrorIsNotExported() {
        val state=JSONObject().put("health",JSONObject().put("w-private",
            JSONObject().put("ms",-1).put("error","secret-host.example/credential")))
        val report=diagnosticReport(state,"Отключено")
        assertEquals("",report.getJSONArray("last_checks").getJSONObject(0).getString("error"))
    }
}
