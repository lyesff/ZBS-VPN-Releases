package dev.autowarp

import org.junit.Assert.assertEquals
import org.junit.Test

class AwgTcpDiagnosticsTest {
    private fun report(vararg entries:Pair<Int,Long>):String = LongArray(14).apply {
        entries.forEach{(i,n)->this[i]=n}
    }.joinToString(",")
    @Test fun malformedCountersAreUnknown(){
        for(raw in listOf("","1,2,3",List(14){"-1"}.joinToString(","),List(14){"secret"}.joinToString(",")))
            assertEquals("awg_tcp_unknown",awgTCPFlowCode(raw))
    }
    @Test fun noFalseSynAckFromOtherSockets(){
        assertEquals("awg_tcp_unrelated_reply",awgTCPFlowCode(report(0 to 1L,12 to 4L)))
        assertEquals("awg_tcp_matched_no_ack",awgTCPFlowCode(report(0 to 1L,1 to 1L,2 to 1L)))
        assertEquals("awg_tcp_android_ack",awgTCPFlowCode(report(0 to 1L,1 to 1L,2 to 1L,3 to 1L)))
    }
    @Test fun corruptionAndWriteFailuresRemainDistinct(){
        for((i,code) in listOf(6 to "destination_mismatch",7 to "sequence_mismatch",8 to "bad_ip_checksum",
            9 to "bad_tcp_checksum",10 to "bad_format",11 to "tun_write_failed",13 to "source_mismatch"))
            assertEquals("awg_tcp_$code",awgTCPFlowCode(report(0 to 1L,i to 1L)))
    }
    @Test fun payloadFailureStagesAreDistinct(){
        val connected=report(0 to 1L,1 to 1L,2 to 1L,3 to 1L)
        fun data(vararg values:Pair<Int,Long>)=LongArray(7).apply{
            values.forEach{(i,n)->this[i]=n}
        }.joinToString(",")
        assertEquals("awg_data_no_client_data",awgTCPDataCode(data(),connected))
        assertEquals("awg_data_no_reply",awgTCPDataCode(data(0 to 1L),connected))
        assertEquals("awg_data_server_ack",awgTCPDataCode(data(0 to 1L,2 to 1L),connected))
        assertEquals("awg_data_server_data",awgTCPDataCode(data(0 to 1L,1 to 1L),connected))
        assertEquals("awg_data_bad_out_checksum",awgTCPDataCode(data(0 to 1L,4 to 1L),connected))
        assertEquals("awg_data_bad_in_checksum",awgTCPDataCode(data(),report(3 to 1L,9 to 1L)))
        assertEquals("awg_data_udp_error",awgTCPDataCode(data(6 to 1L),connected))
        assertEquals("awg_data_unknown",awgTCPDataCode("private payload",connected))
    }
    @Test fun udpCountersSeparateTheRegressionStages(){
        assertEquals("awg_udp_loop",awgUDPFlowCode("3,0,5,0",1L))
        assertEquals("awg_udp_no_send",awgUDPFlowCode("3,0,0,0"))
        assertEquals("awg_udp_no_reply",awgUDPFlowCode("3,0,5,0"))
        assertEquals("awg_udp_no_plaintext",awgUDPFlowCode("3,0,5,2"))
        assertEquals("awg_udp_bidirectional",awgUDPFlowCode("3,1,5,2"))
        assertEquals("awg_udp_unknown",awgUDPFlowCode("private"))
    }
}
