package dev.autowarp

import android.content.Intent
import android.os.Looper
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk=[34])
@LooperMode(LooperMode.Mode.PAUSED)
class TunnelServiceTest {
    private fun session(service:Tunnel)=Tunnel::class.java.getDeclaredField("session").apply {isAccessible=true}.get(service) as VpnSession
    private fun waitFor(service:Tunnel,phase:Phase){
        val until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5)
        while(session(service).value.phase!=phase && System.nanoTime()<until){shadowOf(Looper.getMainLooper()).idle();Thread.sleep(5)}
        assertEquals(phase,session(service).value.phase)
    }
    @Test fun reopenReadsServiceAndDetectsProcessLoss(){
        val ctl=Robolectric.buildService(Tunnel::class.java).create()
        val svc=ctl.get()
        val actual=Live(Phase.CONNECTED,Reason.ONLINE,"test","VLESS","192.0.2.1",10,100)
        session(svc).update(Live(Phase.CONNECTING,Reason.START))
        session(svc).update(actual)
        var observed=Live()
        val observer=VpnObserver(svc.applicationContext){observed=it}
        try {
            observer.start()
            shadowOf(Looper.getMainLooper()).idle()
            assertTrue(observer.synced.value)
            assertEquals(actual,observed)
            observer.stop()
            observer.start()
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(actual,observed)
            // Remove the service receiver without publishing a final snapshot,
            // as when Android kills the remote process.
            val receiver=Tunnel::class.java.getDeclaredField("control").apply { isAccessible=true }.get(svc) as android.content.BroadcastReceiver
            svc.unregisterReceiver(receiver)
            Tunnel::class.java.getDeclaredField("registered").apply { isAccessible=true }.setBoolean(svc,false)
            shadowOf(Looper.getMainLooper()).idleFor(3,TimeUnit.SECONDS)
            assertEquals(Phase.ERROR,observed.phase)
            assertEquals(Reason.LOST,observed.reason)
        }finally{observer.stop();ctl.destroy();waitFor(svc,Phase.DISCONNECTED)}
    }
    @Test fun stickyRestartWithNoProfileStopsForegroundAndNeverCreatesTun(){
        val controller=Robolectric.buildService(Tunnel::class.java).create()
        val service=controller.get()
        service.onStartCommand(null,0,1)
        waitFor(service,Phase.ERROR)
        assertEquals(Reason.NO_PROFILE,session(service).value.reason)
        assertTrue(shadowOf(service).isStoppedBySelf)
        assertTrue(shadowOf(service).isForegroundStopped)
        for(name in listOf("core","fd"))assertNull(Tunnel::class.java.getDeclaredField(name).apply {isAccessible=true}.get(service))
        controller.destroy()
    }
    @Test fun revokeAndRepeatedStopReleaseService(){
        val ctl=Robolectric.buildService(Tunnel::class.java).create()
        val svc=ctl.get();svc.onRevoke();svc.onStartCommand(Intent("STOP"),0,2)
        waitFor(svc,Phase.DISCONNECTED)
        assertTrue(shadowOf(svc).isForegroundStopped);assertTrue(shadowOf(svc).isStoppedBySelf)
        assertEquals(Reason.REVOKED,session(svc).value.reason);ctl.destroy()
    }
    @Test fun systemDestroyFinishesCleanupWithoutAnotherStart(){
        val ctl=Robolectric.buildService(Tunnel::class.java).create();val svc=ctl.get()
        ctl.destroy();waitFor(svc,Phase.DISCONNECTED)
        assertTrue(shadowOf(svc).isForegroundStopped)
    }
    @Test fun blockedWorkerCannotHoldForegroundIndefinitely(){
        val ctl=Robolectric.buildService(Tunnel::class.java).create();val svc=ctl.get()
        val queue=Tunnel::class.java.getDeclaredField("worker").apply {isAccessible=true}.get(svc) as ScheduledThreadPoolExecutor
        val entered=CountDownLatch(1);val release=CountDownLatch(1)
        queue.execute { entered.countDown();release.await(15,TimeUnit.SECONDS) }
        try {
            assertTrue(entered.await(3,TimeUnit.SECONDS))
            svc.onStartCommand(Intent("STOP"),0,1)
            assertEquals(Phase.DISCONNECTING,session(svc).value.phase)
            shadowOf(Looper.getMainLooper()).idleFor(8,TimeUnit.SECONDS)
            assertEquals(Reason.TIMEOUT,session(svc).value.reason)
            assertTrue(shadowOf(svc).isForegroundStopped);assertTrue(shadowOf(svc).isStoppedBySelf)
        }finally{release.countDown();ctl.destroy()}
    }
}
