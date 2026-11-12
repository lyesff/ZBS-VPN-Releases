package dev.autowarp

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class EventJournalTest {
    @Test fun reportsVerifiedAndUnverifiedStatesPrecisely() {
        assertTrue(eventText(JSONObject().put("code","probe_start")
            .put("kind","WARP").put("index",2).put("total",6)).contains("2/6"))
        assertTrue(eventText(JSONObject().put("code","probe_fail")
            .put("kind","WARP").put("index",2).put("total",6)
            .put("error","probe_timeout")).contains("таймаут HTTPS"))
        assertTrue(eventText(JSONObject().put("code","core_ready"))
            .contains("TUN"))
        assertFalse(eventText(JSONObject().put("code","probe_ok").put("kind","WARP").put("ms",225))
            .contains("handshake"))
    }

    @Test fun neverEchoesUntrustedEventValues() {
        val record=JSONObject().put("code","untrusted-private-key")
            .put("kind","secret-url").put("error","secret-error")
            .put("at",1_700_000_000_000L)
        val output=eventLine(record)
        assertFalse(output.contains("untrusted-private-key"))
        assertFalse(output.contains("secret-url"))
        assertFalse(output.contains("secret-error"))
    }
}
