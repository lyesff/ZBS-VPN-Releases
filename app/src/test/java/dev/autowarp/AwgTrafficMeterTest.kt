package dev.autowarp

import org.junit.Assert.*
import org.junit.Test

class AwgTrafficMeterTest {
    @Test fun actualElapsedTimeAndDirections(){
        val meter=AwgTrafficMeter()
        assertEquals(AwgTransferRate(0,0),meter.sample("1000,2000",1000))
        assertEquals(AwgTransferRate(4096,1024),meter.sample("9192,4048",3000))
        assertEquals(AwgTransferRate(0,0),meter.sample("9192,4048",4000))
        assertEquals(AwgTransferRate(4096,2048),meter.sample("10216,4560",4250))
    }
    @Test fun delayedPollUsesWholeInterval(){
        val meter=AwgTrafficMeter()
        meter.sample("0,0",1000)
        assertEquals(AwgTransferRate(1000,2000),meter.sample("5000,10000",6000))
    }
    @Test fun malformedSamplesDoNotLoseBaseline(){
        val meter=AwgTrafficMeter()
        meter.sample("100,200",1000)
        for(raw in listOf("", "1", "1,2,3", "-1,4", "x,2", "999999999999999999999,1"))
            assertNull(meter.sample(raw,1500))
        assertEquals(AwgTransferRate(1000,2000),meter.sample("2100,4200",3000))
    }
    @Test fun counterResetAndNonAdvancingClockNeverSpike(){
        val meter=AwgTrafficMeter()
        meter.sample("10000,20000",1000)
        assertEquals(AwgTransferRate(0,0),meter.sample("1,2",2000))
        assertEquals(AwgTransferRate(0,0),meter.sample("10,20",2000))
        assertEquals(AwgTransferRate(0,0),meter.sample("20,40",1999))
        assertEquals(AwgTransferRate(1000,2000),meter.sample("1020,2040",2999))
    }
}
