//go:build linux

package awglab

import "testing"

func TestPreparationUDPCountersDoNotClaimSystemTraffic(t *testing.T){
    stats:=&vpnPacketStats{}
    stats.suppressUDP.Store(true)
    stats.recordUDP(true,false);stats.recordUDP(false,false)
    stats.recordUDP(true,true);stats.recordUDP(false,true)
    tx,rx,txErr,rxErr:=stats.preparationUDP()
    if tx!=1 || rx!=1 || txErr!=1 || rxErr!=1{
        t.Fatal("preparation UDP window lost traffic/errors")
    }
    if stats.tunIn.Load()!=0 || stats.tunOut.Load()!=0 ||
        stats.udpSent.Load()!=0 || stats.udpRecv.Load()!=0 ||
        stats.udpSendErrors.Load()!=0 || stats.udpRecvErrors.Load()!=0{
        t.Fatal("preparation was reported as system traffic")
    }
    stats.suppressUDP.Store(false)
    stats.recordUDP(true,false);stats.recordUDP(false,false)
    stats.recordUDP(true,true);stats.recordUDP(false,true)
    tx,rx,txErr,rxErr=stats.preparationUDP()
    if tx!=1 || rx!=1 || txErr!=1 || rxErr!=1 ||
        stats.udpSent.Load()!=1 || stats.udpRecv.Load()!=1 ||
        stats.udpSendErrors.Load()!=1 || stats.udpRecvErrors.Load()!=1{
        t.Fatal("handoff mixed preparation and system counter windows")
    }
}
func TestPostTUNUDPOutcomeKeepsErrorsAndMissingRepliesDistinct(t *testing.T){
    cases:=[]struct{tx,rx,txErr,rxErr int64;want string}{
        {0,0,0,0,"awg_post_udp_no_send"},
        {2,0,0,0,"awg_post_udp_no_reply"},
        {2,3,0,0,"awg_post_udp_bidirectional"},
        {2,3,1,0,"awg_post_udp_send_error"},
        {2,3,0,1,"awg_post_udp_receive_error"},
    }
    for _,c:=range cases{
        if postTUNUDPCode(c.tx,c.rx,c.txErr,c.rxErr)!=c.want{
            t.Fatal("UDP outcome hid a missing reply or socket error")
        }
    }
}
func TestTransportStateExportsComparisonOnly(t *testing.T){
    before:=udpSocketState{valid:true,mark:123,port:41820}
    if compareUDPSocketState(before,before)!="awg_transport_unchanged"{
        t.Fatal("unchanged socket marked changed")
    }
    after:=before;after.mark++
    if compareUDPSocketState(before,after)!="awg_transport_mark_changed"{
        t.Fatal("mark change missed")
    }
    after=before;after.port++
    if compareUDPSocketState(before,after)!="awg_transport_port_changed"{
        t.Fatal("port change missed")
    }
    if compareUDPSocketState(before,udpSocketState{})!="awg_transport_unknown" ||
        readUDPSocketState(nil).valid{
        t.Fatal("unavailable metadata claimed unchanged")
    }
}
func TestPostTUNProbeRejectsMissingOrActivePreparation(t *testing.T){
    for _,p:=range []*AndroidVPNPreparation{nil,{}, {probing:true}, {closed:true}}{
        if outcome,err:=p.ProbeWarpAfterTUN();err!=nil || outcome!="awg_device_start_failed"{
            t.Fatal("post-TUN probe ran without an idle prepared stack")
        }
        if p.PostTUNUDPState()!="awg_post_udp_unknown" ||
            p.TransportState()!="awg_transport_unknown"{
            t.Fatal("invalid preparation claimed transport evidence")
        }
    }
}
