package dev.autowarp

import org.junit.Assert.*
import org.junit.Test

class VpnLifecycleTest {
    @Test fun disconnectedUntilConfirmed(){
        val events=mutableListOf<Phase>();val session=VpnSession { events+=it.phase }
        assertFalse(session.update(Live(Phase.CONNECTED,Reason.ONLINE)))
        assertTrue(session.update(Live(Phase.CONNECTING,Reason.START)))
        assertFalse(session.update(Live(Phase.CONNECTED,Reason.ONLINE)))
        assertTrue(session.update(Live(Phase.CONNECTED,Reason.ONLINE,"server","VLESS","1.2.3.4",43,100)))
        assertTrue(session.beginStop(Reason.STOP));assertFalse(session.beginStop(Reason.STOP))
        assertFalse(session.update(Live(Phase.CONNECTED,Reason.ONLINE,"late result","WARP","1.2.3.4",2,1)))
        assertTrue(session.finish(Reason.IDLE));assertEquals(Live(),session.value)
        assertEquals(listOf(Phase.CONNECTING,Phase.CONNECTED,Phase.DISCONNECTING,Phase.DISCONNECTED),events)
    }
    @Test fun startupErrorRevokeAndRetry(){
        val session=VpnSession {}
        for(problem in listOf(Reason.NO_PROFILE,Reason.CORE,Reason.NO_EXIT,Reason.TIMEOUT,Reason.REVOKED)){
            assertTrue(session.update(Live(Phase.CONNECTING,Reason.START)))
            assertTrue(session.beginStop(problem));assertTrue(session.finish(problem))
            assertEquals(if(problem==Reason.REVOKED)Phase.DISCONNECTED else Phase.ERROR,session.value.phase)
            assertFalse(session.value.running);assertEquals("",session.value.ip);assertEquals(0L,session.value.start)
        }
    }
    @Test fun emptyAndDanglingSelections(){
        val s=obj()
        for(mode in modes)assertFalse(hasProfile(s.put("mode",mode)))
        val node=obj("id" to "v","name" to "v","config" to obj("type" to "vless"))
        s.put("sources",obj("source" to obj("items" to arr(node)))).put("mode","VLESS")
        assertTrue(hasProfile(s));s.put("server","deleted");assertFalse(hasProfile(s))
        s.put("server","v");s.put("mode","VLESS через WARP");assertFalse(hasProfile(s))
        s.put("warp","nonexistent");s.put("mode","WARP");assertFalse(hasProfile(s))
    }
}
