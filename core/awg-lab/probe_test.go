package awglab

import (
    "context"
    "errors"
    "net/netip"
    "net"
    "strings"
    "testing"
)

func TestRejectsEmptyCredentials(t *testing.T) {
    _,err:=Probe(context.Background(),Config{LocalIPv4:"172.16.0.2"})
    if !errors.Is(err,ErrInvalidConfig){t.Fatalf("want invalid configuration, got %v",err)}
}

func TestRejectsInvalidInterfaceAddress(t *testing.T){
    _,err:=Probe(context.Background(),Config{
        LocalIPv4:"definitely-not-an-ip",
        IPCSettings:"private_key=fake\\npublic_key=fake\\nendpoint=example.org:443",
    })
    if !errors.Is(err,ErrInvalidConfig){t.Fatalf("want invalid address, got %v",err)}
}

func TestAWGHandshakeSnapshotParsing(t *testing.T) {
    for _,tc:=range []struct{source string; present bool}{
        {"last_handshake_time_sec=0\nrx_bytes=0\n",false},
        {"public_key=something\nlast_handshake_time_sec=1730000000\nrx_bytes=120\n",true},
        {"last_handshake_time_sec=bad\n",false},
        {"last_handshake_time_nsec=12345\n",false},
        {"private_key=TOP_SECRET\n",false},
    }{
        if got:=parseAWGHandshake(tc.source);got!=tc.present {
            t.Fatalf("handshake parsing mismatch: got %v want %v",got,tc.present)
        }
    }
}

func TestNormalizeEndpointResolvesHostnameToPublicIP(t *testing.T){
    secret:="private_key=SENSITIVE_SECRET\npublic_key=other\nendpoint=engage.cloudflareclient.com:2408\n"
    called:=false
    got,err:=normalizeIPCEndpoint(context.Background(),secret,
        func(_ context.Context,host string)(netip.Addr,error){
            if host!="engage.cloudflareclient.com"{t.Fatal("wrong host")}
            called=true
            return netip.MustParseAddr("162.159.193.1"),nil
        })
    if err!=nil{t.Fatal(err)}
    if !called || !strings.Contains(got,"endpoint=162.159.193.1:2408"){
        t.Fatal("hostname was not replaced")
    }
    if !strings.Contains(got,"private_key=SENSITIVE_SECRET"){t.Fatal("lost peer config")}
}

func TestNormalizeEndpointRejectsUnsafeAddress(t *testing.T){
    for _,addr:=range []string{"127.0.0.1","10.0.0.1","192.168.1.2","::1"}{
        _,err:=normalizeIPCEndpoint(context.Background(),"endpoint="+net.JoinHostPort(addr,"2408")+"\n",
            func(context.Context,string)(netip.Addr,error){return netip.Addr{},ErrEndpointDNS})
        if !errors.Is(err,ErrEndpointDNS){t.Fatal("accepted internal endpoint")}
    }
    _,err:=normalizeIPCEndpoint(context.Background(),"endpoint=engage.cloudflareclient.com:2408\n",
        func(context.Context,string)(netip.Addr,error){return netip.MustParseAddr("10.0.0.1"),nil})
    if !errors.Is(err,ErrEndpointDNS){t.Fatal("accepted private resolver result")}
}

func TestAWGTimeoutPhaseClassification(t *testing.T){
    cases:=[]struct{phase int32; want error}{
        {0,ErrTCPTimeout},{1,ErrTCPTimeout},
        {2,ErrTLSTimeout},{3,ErrTLSTimeout},
        {4,ErrHTTPTimeout},{5,ErrHTTPTimeout},
    }
    for _,tc:=range cases{
        if got:=classifyAWGTimeout(tc.phase);!errors.Is(got,tc.want){
            t.Errorf("phase %d: got %v want %v",tc.phase,got,tc.want)
        }
    }
}
