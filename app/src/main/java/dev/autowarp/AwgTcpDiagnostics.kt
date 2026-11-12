package dev.autowarp

/** Fixed diagnostic codes only; no raw packets or socket identifiers in logs. */
internal fun awgTCPFlowCode(raw:String):String {
    val c=raw.split(",").map{it.toLongOrNull() ?: return "awg_tcp_unknown"}
    if(c.size!=14 || c.any{it<0})return "awg_tcp_unknown"
    return "awg_tcp_"+when {
        c[13]>0 -> "source_mismatch"
        c[0]==0L -> "no_syn"
        c[3]>0 -> "android_ack"
        c[5]>0 -> "android_rst"
        c[8]>0 -> "bad_ip_checksum"
        c[9]>0 -> "bad_tcp_checksum"
        c[10]>0 -> "bad_format"
        c[6]>0 -> "destination_mismatch"
        c[7]>0 -> "sequence_mismatch"
        c[11]>0 -> "tun_write_failed"
        c[2]>0 -> "matched_no_ack"
        c[1]>0 -> "synack_not_written"
        c[4]>0 -> "rst"
        c[12]>0 -> "unrelated_reply"
        else -> "no_reply"
    }
}

/** Data-stage evidence for the same selected TCP socket; no TLS bytes leave Go. */
internal fun awgTCPDataCode(raw:String,control:String):String {
    val d=raw.split(",").map{it.toLongOrNull() ?: return "awg_data_unknown"}
    val c=control.split(",").map{it.toLongOrNull() ?: return "awg_data_unknown"}
    if(d.size!=7 || c.size!=14 || d.any{it<0} || c.any{it<0})return "awg_data_unknown"
    return "awg_data_"+when {
        d[3]>0 || d[4]>0 -> "bad_out_checksum"
        c[8]>0 || c[9]>0 -> "bad_in_checksum"
        d[5]>0 || d[6]>0 -> "udp_error"
        c[3]==0L -> "no_tcp"
        d[0]==0L -> "no_client_data"
        d[1]>0 -> "server_data"
        d[2]>0 -> "server_ack"
        else -> "no_reply"
    }
}


/** Existing aggregate counters separate no UDP reply from no decrypted traffic. */
internal fun awgUDPFlowCode(raw:String,loops:Long=0L):String {
    if(loops>0L)return "awg_udp_loop"
    val c=raw.split(",").map{it.toLongOrNull() ?: return "awg_udp_unknown"}
    if(c.size!=4 || c.any{it<0})return "awg_udp_unknown"
    return "awg_udp_"+when {
        c[2]==0L -> "no_send"
        c[3]==0L -> "no_reply"
        c[1]==0L -> "no_plaintext"
        else -> "bidirectional"
    }
}
