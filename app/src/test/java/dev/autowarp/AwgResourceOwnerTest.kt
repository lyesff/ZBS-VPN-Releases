package dev.autowarp

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class AwgResourceOwnerTest {
    @Test fun retryClosesFailedAttemptBeforeInstallingFreshResources(){
        val calls=mutableListOf<String>()
        val owner=AwgResourceOwner<String,String>({calls.add("tun:$it")},{calls.add("engine:$it")})
        owner.installTun("one");owner.installEngine("one")
        owner.releaseAttempt()
        assertNull(owner.engine())
        assertTrue(owner.installTun("two"));assertTrue(owner.installEngine("two"))
        owner.close();owner.releaseAttempt()
        assertFalse(owner.installEngine("late"))
        assertEquals(listOf("engine:one","tun:one","engine:two","tun:two","engine:late"),calls)
    }
    @Test fun stopBetweenAttemptsCannotReopenTheOwner(){
        var closes=0
        val owner=AwgResourceOwner<String,String>({closes++},{closes++})
        owner.installTun("one")
        owner.releaseAttempt();owner.close();owner.releaseAttempt()
        assertFalse(owner.installTun("late"))
        assertFalse(owner.installEngine("late"))
        assertEquals(3,closes)
    }
    @Test fun stopClosesEngineBeforeTunExactlyOnce(){
        val calls=mutableListOf<String>()
        val owner=AwgResourceOwner<String,String>({calls.add("tun:$it")},{calls.add("engine:$it")})
        assertTrue(owner.installTun("a"));assertTrue(owner.installEngine("b"))
        owner.close();owner.close()
        assertEquals(listOf("engine:b","tun:a"),calls)
        assertNull(owner.engine())
    }
    @Test fun engineFinishingAfterStopIsClosed(){
        val engineStarted=CountDownLatch(1)
        val permitReturn=CountDownLatch(1)
        val engineClosed=CountDownLatch(1)
        val owner=AwgResourceOwner<String,String>({}, {engineClosed.countDown()})
        owner.installTun("tun")
        val worker=Thread {
            engineStarted.countDown()
            check(permitReturn.await(2,TimeUnit.SECONDS))
            owner.installEngine("late engine")
        }
        worker.start()
        assertTrue(engineStarted.await(2,TimeUnit.SECONDS))
        owner.close()
        permitReturn.countDown()
        worker.join(2000)
        assertFalse(worker.isAlive)
        assertTrue(engineClosed.await(2,TimeUnit.SECONDS))
        assertNull(owner.engine())
    }
    @Test fun lateTunIsClosedAndTunClosesEvenIfEngineThrows(){
        var closes=0
        val owner=AwgResourceOwner<String,String>({closes++},{throw IllegalStateException()})
        owner.installTun("tun");owner.installEngine("engine")
        runCatching{owner.close()}
        assertEquals(1,closes)
        assertFalse(owner.installTun("late tun"))
        assertEquals(2,closes)
        owner.close()
        assertEquals(2,closes)
    }
}

