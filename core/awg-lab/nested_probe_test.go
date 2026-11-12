package awglab

import (
    "bytes"
    "encoding/base64"
    "errors"
    "net"
    "net/netip"
    "strings"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func TestNestedBindRoundTripUsesOuterStackWithoutHostSocket(t *testing.T){
    local:=netip.MustParseAddr("203.0.113.2")
    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{local},nil,1280)
    if err!=nil{t.Fatal(err)};defer tun.Close()
    peer,err:=stack.ListenUDPAddrPort(netip.AddrPortFrom(local,0))
    if err!=nil{t.Fatal(err)};defer peer.Close()
    b:=&nestedBind{stack:stack,local:local}
    recv,port,err:=b.Open(0)
    if err!=nil{t.Fatal(err)};defer b.Close()
    if len(recv)!=1 || port==0 || b.BatchSize()!=1{t.Fatal("invalid nested binding")}
    if _,_,err=b.Open(0);!errors.Is(err,conn.ErrBindAlreadyOpen){t.Fatal("duplicate bind accepted")}
    ep,err:=b.ParseEndpoint(peer.LocalAddr().String());if err!=nil{t.Fatal(err)}
    if err=b.Send([][]byte{[]byte("inner-encrypted-packet")},ep);err!=nil{t.Fatal(err)}
    peer.SetReadDeadline(time.Now().Add(time.Second))
    buf:=make([]byte,100)
    n,source,err:=peer.ReadFrom(buf)
    if err!=nil || string(buf[:n])!="inner-encrypted-packet"{t.Fatal("inner packet did not traverse private outer stack")}
    if source.(*net.UDPAddr).AddrPort().Addr()!=local{t.Fatal("nested socket did not bind the outer tunnel address")}
    if _,err=peer.WriteTo([]byte("reply"),source);err!=nil{t.Fatal(err)}
    sizes:=make([]int,1);eps:=make([]conn.Endpoint,1)
    done:=make(chan error,1)
    go func(){_,e:=recv[0]([][]byte{buf},sizes,eps);done<-e}()
    select{
    case err=<-done:
        if err!=nil || sizes[0]!=5 || string(buf[:5])!="reply" || eps[0].DstToString()!=peer.LocalAddr().String(){t.Fatal("nested receive framing invalid")}
    case <-time.After(time.Second):t.Fatal("nested receive blocked")
    }
    go func(){_,e:=recv[0]([][]byte{buf},sizes,eps);done<-e}()
    if err=b.Close();err!=nil{t.Fatal(err)}
    select{case err=<-done:if err==nil{t.Fatal("close did not unblock receive")};case <-time.After(time.Second):t.Fatal("receive leaked after close")}
    if err=b.Close();err!=nil{t.Fatal("close must be idempotent")}
    if !errors.Is(b.Send(nil,ep),net.ErrClosed){t.Fatal("send on closed binding accepted")}
}

func TestNestedProbeRejectsReusedIdentityBeforeAnyUDP(t *testing.T){
    key:=base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1},32))
    public:=base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2},32))
    quick:="[Interface]\nPrivateKey = "+key+"\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = "+public+"\nEndpoint = 162.159.192.1:2408\nAllowedIPs = 0.0.0.0/0\n"
    protector:=&testProtector{allowed:true}
    p:=NewNestedProbe();defer p.Close()
    if result:=p.Run(quick,quick,protector);result!="awg_nested_same_key"{t.Fatal("same identity not rejected")}
    if protector.calls!=0{t.Fatal("opened outer UDP before rejecting reused identity")}
    p.Close()
    if p.Run(quick,quick,protector)!="awg_nested_stopped"{t.Fatal("closed experiment restarted")}
}

func TestNestedEndpointOverrideKeepsIdentityAndRejectsUnsafeDestinations(t *testing.T){
    raw:="private_key=synthetic-secret\nendpoint=162.159.192.1:2408\nallowed_ip=0.0.0.0/0\n"
    changed,err:=nestedEndpoint(raw,"188.114.97.1:500")
    if err!=nil || changed!=strings.Replace(raw,"162.159.192.1:2408","188.114.97.1:500",1){t.Fatal("endpoint rewrite changed other fields")}
    for _,ep:=range []string{"127.0.0.1:2408","10.0.0.1:2408","[::1]:2408","host:2408","162.159.192.1:0"}{
        if _,err=nestedEndpoint(raw,ep);err==nil{t.Fatal("unsafe nested destination accepted")}
    }
    if nestedMTU+60!=1280{t.Fatal("inner MTU does not account for outer encapsulation")}
    if !nestedEuropeanColo("FRA") || nestedEuropeanColo("DME") || nestedEuropeanColo("") || nestedEuropeanColo("FA"){t.Fatal("outer node guard invalid")}
}
