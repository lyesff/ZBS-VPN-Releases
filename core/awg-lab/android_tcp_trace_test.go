package awglab

import (
    "encoding/binary"
    "testing"
)

func testIPv4TCP(src,dst [4]byte,srcPort,dstPort uint16, flags byte) []byte {
    p:=make([]byte,40)
    p[0]=0x45
    p[9]=6
    copy(p[12:16],src[:])
    copy(p[16:20],dst[:])
    binary.BigEndian.PutUint16(p[20:22],srcPort)
    binary.BigEndian.PutUint16(p[22:24],dstPort)
    p[32]=0x50
    p[33]=flags
    return p
}

func TestDiagnosticTCPFlags(t *testing.T){
    s:=&vpnPacketStats{}
    local:=[4]byte{172,16,0,2}
    peer:=[4]byte{1,1,1,1}
    syn:=testIPv4TCP(local,peer,52100,443,0x02)
    inspectDiagnosticTCP(syn,true,s)
    if s.tcpSyn.Load()!=1 {t.Fatal("expected outgoing SYN")}
    synAck:=testIPv4TCP(peer,local,443,52100,0x12)
    inspectDiagnosticTCP(synAck,false,s)
    if s.tcpSynAck.Load()!=1 {t.Fatal("expected incoming SYN ACK")}
    rst:=testIPv4TCP(peer,local,443,52100,0x14)
    inspectDiagnosticTCP(rst,false,s)
    if s.tcpRst.Load()!=1{t.Fatal("expected incoming RST")}
    inspectDiagnosticTCP(syn,false,s)
    inspectDiagnosticTCP(synAck,true,s)
    if s.tcpSyn.Load()!=1 || s.tcpSynAck.Load()!=1 {t.Fatal("direction filter failed")}
    malformed:=[][]byte{nil,{0x45},make([]byte,35),testIPv4TCP(local,[4]byte{8,8,8,8},51000,443,0x02)}
    for _,p:=range malformed{inspectDiagnosticTCP(p,true,s)}
    if s.tcpSyn.Load()!=1{t.Fatal("malformed or foreign packet counted")}
}

func TestDiagnosticFragmentIgnored(t *testing.T){
    s:=&vpnPacketStats{}
    p:=testIPv4TCP([4]byte{172,16,0,2},[4]byte{1,1,1,1},51000,443,0x02)
    binary.BigEndian.PutUint16(p[6:8],0x2000)
    inspectDiagnosticTCP(p,true,s)
    if s.tcpSyn.Load()!=0{t.Fatal("fragmented packet counted")}
}
