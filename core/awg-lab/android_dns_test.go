//go:build linux

package awglab

import (
    "bytes"
    "context"
    "encoding/binary"
    "io"
    "net/netip"
    "sync/atomic"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    "golang.org/x/net/dns/dnsmessage"
)

type dnsFixtureExchanger struct{bad bool;large bool;calls atomic.Int32}
func (f *dnsFixtureExchanger) Exchange(query []byte)[]byte{
    f.calls.Add(1)
    var q dnsmessage.Message
    _=q.Unpack(query)
    q.Response=true;q.RecursionAvailable=true
    if f.bad{q.ID++}
    count:=1;if f.large{count=60}
    for i:=0;i<count;i++{q.Answers=append(q.Answers,dnsmessage.Resource{
        Header:dnsmessage.ResourceHeader{Name:q.Questions[0].Name,Type:dnsmessage.TypeA,Class:dnsmessage.ClassINET,TTL:30},
        Body:&dnsmessage.AResource{A:[4]byte{203,0,113,9}},
    })}
    b,_:=q.Pack();return b
}
func dnsFixtureQuery()[]byte{
    q:=dnsmessage.Message{Header:dnsmessage.Header{ID:173,RecursionDesired:true},
        Questions:[]dnsmessage.Question{{Name:dnsmessage.MustNewName("example.com."),Type:dnsmessage.TypeA,Class:dnsmessage.ClassINET}}}
    b,_:=q.Pack();return b
}
func TestDNSRejectsMismatchedAnswersAndSupportsTCPRetry(t *testing.T){
    query:=dnsFixtureQuery()
    var answer dnsmessage.Message
    if answer.Unpack(dnsAnswer(query,&dnsFixtureExchanger{bad:true},true))!=nil || answer.RCode!=dnsmessage.RCodeServerFailure{t.Fatal("accepted mismatched response")}
    large:=&dnsFixtureExchanger{large:true}
    if answer.Unpack(dnsAnswer(query,large,true))!=nil || !answer.Truncated || len(answer.Answers)!=0{t.Fatal("large UDP response must request TCP retry")}
    if answer.Unpack(dnsAnswer(query,large,false))!=nil || answer.Truncated || len(answer.Answers)!=60{t.Fatal("TCP response lost answers")}
    if b:=dnsAnswer([]byte{1,2},large,true);b!=nil{t.Fatal("accepted malformed query")}
    if !CheckDNS(&dnsFixtureExchanger{}) || CheckDNS(&dnsFixtureExchanger{bad:true}) || CheckDNS(nil){t.Fatal("DNS health accepted failure or rejected success")}
}

func TestDNSBridgeUDPAndTCPOverSyntheticAddress(t *testing.T){
    native:=newHandoffFixture(true)
    exchange:=&dnsFixtureExchanger{}
    bridge,err:=newDNSTun(native,exchange)
    if err!=nil{t.Fatal(err)}
    defer bridge.Close()
    // Android-side userspace stack speaks real UDP/TCP over fake TUN frames.
    clientTun,client,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("172.16.0.2")},nil,1280)
    if err!=nil{t.Fatal(err)}
    defer clientTun.Close()
    leaked:=make(chan []byte,4)
    go func(){
        buf:=make([]byte,65535);sizes:=make([]int,1)
        for{
            n,e:=clientTun.Read([][]byte{buf},sizes,0)
            if n>0{select{case native.input<-append([]byte(nil),buf[:sizes[0]]...):case <-native.done:}}
            if e!=nil{return}
        }
    }()
    go func(){
        buf:=make([]byte,65535);sizes:=make([]int,1)
        for{n,e:=bridge.Read([][]byte{buf},sizes,0);if n>0{leaked<-append([]byte(nil),buf[:sizes[0]]...)};if e!=nil{return}}
    }()
    // Fixture Write records native replies; deliver them back to Android.
    ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second);defer cancel()
    go func(){
        index:=0
        for{
            native.mu.Lock();packets:=append([][]byte(nil),native.writes[index:]...);index=len(native.writes);native.mu.Unlock()
            for _,p:=range packets{_,_=clientTun.Write([][]byte{p},0)}
            select{case <-ctx.Done():return;case <-time.After(time.Millisecond):}
        }
    }()
    query:=dnsFixtureQuery()
    udp,err:=client.DialContext(ctx,"udp",androidDNSAddress+":53")
    if err!=nil{t.Fatal(err)}
    _=udp.SetDeadline(time.Now().Add(time.Second))
    if _,err=udp.Write(query);err!=nil{t.Fatal(err)}
    answer:=make([]byte,4096)
    n,err:=udp.Read(answer);_=udp.Close()
    if err!=nil || n<12{t.Fatalf("UDP reply: %d %v",n,err)}
    tcp,err:=client.DialContext(ctx,"tcp",androidDNSAddress+":53")
    if err!=nil{t.Fatal(err)}
    _=tcp.SetDeadline(time.Now().Add(time.Second))
    frame:=append([]byte{0,byte(len(query))},query...)
    if _,err=tcp.Write(frame);err!=nil{t.Fatal(err)}
    if _,err=io.ReadFull(tcp,answer[:2]);err!=nil{t.Fatal(err)}
    length:=int(binary.BigEndian.Uint16(answer[:2]))
    if length<12 || length>len(answer){t.Fatal("invalid DNS frame")}
    if _,err=io.ReadFull(tcp,answer[:length]);err!=nil{t.Fatal(err)}
    _=tcp.Close()
    // Ordinary packets must pass through unchanged, DNS must not reach AWG.
    ordinary:=bytes.Repeat([]byte{1},40)
    native.input<-ordinary
    select{case got:=<-leaked:if !bytes.Equal(got,ordinary){t.Fatal("synthetic DNS escaped to AWG")};case <-ctx.Done():t.Fatal("ordinary traffic blocked")}
    if exchange.calls.Load()!=2{t.Fatal("DNS not exchanged")}
    _=bridge.Close();_=bridge.Close()
    if native.closeCalls.Load()!=1{t.Fatal("native TUN not closed once")}
}
