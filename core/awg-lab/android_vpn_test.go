package awglab

import (
    "errors"
    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "net"
    "testing"
)

type testProtector struct{allowed bool; calls int}
func (p *testProtector) Protect(_ int)bool{p.calls++;return p.allowed}

func TestProtectedBindFailsClosed(t *testing.T){
    denied:=&testProtector{}
    bind:=newProtectedBind(denied)
    _,_,err:=bind.Open(0)
    if err==nil{t.Fatal("unprotected UDP socket was allowed")}
    if !errors.Is(err,ErrVPNProtect){t.Fatalf("expected protection error, got %T",err)}
    if denied.calls==0{t.Fatal("protector was not called")}
}

func TestProtectedBindOpenAndClose(t *testing.T){
    allowed:=&testProtector{allowed:true}
    bind:=newProtectedBind(allowed)
    receive,port,err:=bind.Open(0)
    if err!=nil{t.Fatal(err)}
    if port==0 || len(receive)!=1 || bind.BatchSize()!=1{t.Fatal("invalid binding")}
    if allowed.calls==0{t.Fatal("socket never protected")}
    if _,_,err=bind.Open(0);!errors.Is(err,conn.ErrBindAlreadyOpen){
        t.Fatalf("expected already-open, got %v",err)
    }
    if err=bind.Close();err!=nil{t.Fatal(err)}
    if err=bind.Close();err!=nil{t.Fatal("close must be idempotent")}
}

func TestProtectedBindRejectsNonPublicAndIPv6Endpoints(t *testing.T){
    bind:=newProtectedBind(&testProtector{allowed:true})
    for _,s:=range []string{"127.0.0.1:2408","10.0.0.1:2408","[::1]:2408","invalid.host:2408"}{
        if _,err:=bind.ParseEndpoint(s);err==nil{t.Fatal("accepted unsafe endpoint")}
    }
    endpoint,err:=bind.ParseEndpoint("162.159.193.1:2408")
    if err!=nil || endpoint.DstToString()!="162.159.193.1:2408"{
        t.Fatal("public WARP endpoint rejected")
    }
    if err:=bind.SetMark(1);err==nil{t.Fatal("unsupported SO_MARK accepted")}
    if err:=bind.Send(nil,endpoint);!errors.Is(err,net.ErrClosed){t.Fatal("expected closed bind")}
}
