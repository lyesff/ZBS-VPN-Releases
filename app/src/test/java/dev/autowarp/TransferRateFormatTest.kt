package dev.autowarp

import org.junit.Assert.assertEquals
import org.junit.Test

class TransferRateFormatTest {
    @Test fun idleAndSmallTrafficStayReadable(){
        assertEquals("0 Б/с",formatTransferRate(0))
        assertEquals("0 Б/с",formatTransferRate(-1))
        assertEquals("512 Б/с",formatTransferRate(512))
    }
    @Test fun unitsFollowByteCountersWithoutConfusingBits(){
        assertEquals("1.0 КиБ/с",formatTransferRate(1024))
        assertEquals("1.5 КиБ/с",formatTransferRate(1536))
        assertEquals("1.0 МиБ/с",formatTransferRate(1024L*1024))
        assertEquals("2.0 ГиБ/с",formatTransferRate(2L*1024*1024*1024))
    }
}
