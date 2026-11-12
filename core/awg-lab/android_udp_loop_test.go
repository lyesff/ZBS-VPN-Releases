package awglab

import (
    "encoding/binary"
    "errors"
    "net/netip"
    "testing"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)
func ownUDPTestPacket()[]byte{
    p:=make([]byte,28)
    p[0]=0x45;p[9]=17
    binary.BigEndian.PutUint16(p[2:],uint16(len(p)))
    copy(p[12:16],[]byte{172,16,0,2})
    copy(p[16:20],[]byte{162,159,193,1})
    binary.BigEndian.PutUint16(p[20:],53000)
    binary.BigEndian.PutUint16(p[22:],2408)
    binary.BigEndian.PutUint16(p[24:],8)
    return p
}
func TestOwnUDPMatchAndForeignTraffic(t *testing.T){
    peer:=udpPeerMarker(netip.MustParseAddrPort("162.159.193.1:2408"))
    p:=ownUDPTestPacket()
    if !isOwnUDPPacket(p,53000,peer){t.Fatal("outer UDP loop not detected")}
    cases:=[]func([]byte){
        func(p []byte){p[19]=2},
        func(p []byte){binary.BigEndian.PutUint16(p[20:],53001)},
        func(p []byte){binary.BigEndian.PutUint16(p[22:],2409)},
        func(p []byte){p[9]=6},
        func(p []byte){binary.BigEndian.PutUint16(p[6:],1)},
        func(p []byte){binary.BigEndian.PutUint16(p[24:],7)},
        func(p []byte){p[0]=0x4f},
    }
    for _,change:=range cases{
        q:=append([]byte(nil),p...);change(q)
        if isOwnUDPPacket(q,53000,peer){t.Fatal("foreign or malformed packet matched")}
    }
    for n:=0;n<len(p);n++{
        if isOwnUDPPacket(p[:n],53000,peer){t.Fatal("truncated packet matched")}
    }
    if isOwnUDPPacket(p,0,peer) || isOwnUDPPacket(p,53000,0){t.Fatal("unregistered socket matched")}
}
func TestOwnUDPFirstFragmentAndIPv4Options(t *testing.T){
    peer:=udpPeerMarker(netip.MustParseAddrPort("162.159.193.1:2408"))
    p:=ownUDPTestPacket()
    binary.BigEndian.PutUint16(p[6:],0x2000)
    binary.BigEndian.PutUint16(p[24:],1000)
    if !isOwnUDPPacket(p,53000,peer){t.Fatal("first fragment missed")}
    p=ownUDPTestPacket()
    p=append(append(append([]byte{},p[:20]...),1,1,1,1),p[20:]...)
    p[0]=0x46;binary.BigEndian.PutUint16(p[2:],uint16(len(p)))
    if !isOwnUDPPacket(p,53000,peer){t.Fatal("IPv4 option offset mishandled")}
}
type loopReadTun struct{tun.Device; packet []byte}
func(t *loopReadTun)Read(bufs [][]byte,sizes []int,offset int)(int,error){
    sizes[0]=copy(bufs[0][offset:],t.packet);return 1,nil
}
func TestOwnUDPStopsBeforeReencryption(t *testing.T){
    stats:=&vpnPacketStats{}
    stats.udpLocalPort.Store(53000)
    stats.udpPeer.Store(udpPeerMarker(netip.MustParseAddrPort("162.159.193.1:2408")))
    source:=&loopReadTun{packet:ownUDPTestPacket()}
    adapter:=&countingTun{Device:source,stats:stats}
    n,err:=adapter.Read([][]byte{make([]byte,1500)},make([]int,1),16)
    if n!=0 || !errors.Is(err,ErrVPNRoutingLoop) || stats.udpLoop.Load()!=1{
        t.Fatal("outer packet was passed back for AWG encryption")
    }
    source.packet[19]=2
    n,err=adapter.Read([][]byte{make([]byte,1500)},make([]int,1),16)
    if n!=1 || err!=nil{t.Fatal("unrelated UDP was blocked")}
}
