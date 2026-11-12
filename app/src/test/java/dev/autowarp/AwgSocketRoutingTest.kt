package dev.autowarp

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class AwgSocketRoutingTest {
    @Test fun physicalBindingPrecedesProtection(){
        val order=mutableListOf<String>()
        assertTrue(awgBindAndProtect({order.add("bind")},{order.add("protect");true}))
        assertEquals(listOf("bind","protect"),order)
    }
    @Test fun bindingFailureNeverFallsBackToUnboundTraffic(){
        var protected=false
        assertFalse(awgBindAndProtect({throw IOException("private detail")},{protected=true;true}))
        assertFalse(protected)
    }
    @Test fun deniedOrFailedProtectionFailsClosed(){
        assertFalse(awgBindAndProtect({},{false}))
        assertFalse(awgBindAndProtect({},{throw IOException("private detail")}))
    }
}
