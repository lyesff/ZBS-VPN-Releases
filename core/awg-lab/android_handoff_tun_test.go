//go:build linux

package awglab

import (
    "bytes"
    "errors"
    "io"
    "os"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type handoffFixture struct {
    input chan []byte
    done chan struct{}
    events chan tun.Event
    once sync.Once
    closeCalls atomic.Int32
    mu sync.Mutex
    writes [][]byte
    bytesWritten bool
    writeEntered chan struct{}
    enterOnce sync.Once
}
func newHandoffFixture(bytesWritten bool)*handoffFixture{
    return &handoffFixture{input:make(chan []byte,8),done:make(chan struct{}),
        events:make(chan tun.Event),bytesWritten:bytesWritten}
}
func (f *handoffFixture) File()*os.File{return nil}
func (f *handoffFixture) Name()(string,error){return "fixture",nil}
func (f *handoffFixture) MTU()(int,error){return 1280,nil}
func (f *handoffFixture) BatchSize()int{return 1}
func (f *handoffFixture) Events()<-chan tun.Event{return f.events}
func (f *handoffFixture) Close()error{
    f.closeCalls.Add(1)
    f.once.Do(func(){close(f.done);close(f.events)})
    return nil
}
func (f *handoffFixture) Read(bufs [][]byte,sizes []int,offset int)(int,error){
    select {
    case <-f.done:return 0,os.ErrClosed
    case packet:=<-f.input:
        if len(packet)>len(bufs[0])-offset{return 0,io.ErrShortBuffer}
        sizes[0]=copy(bufs[0][offset:],packet)
        return 1,nil
    }
}
func (f *handoffFixture) Write(bufs [][]byte,offset int)(int,error){
    if f.writeEntered!=nil{
        f.enterOnce.Do(func(){close(f.writeEntered)})
        <-f.done
        return 0,os.ErrClosed
    }
    f.mu.Lock();defer f.mu.Unlock()
    total:=0
    for _,buf:=range bufs{
        p:=append([]byte(nil),buf[offset:]...)
        f.writes=append(f.writes,p)
        total+=len(p)
    }
    if f.bytesWritten{return total,nil}
    return len(bufs),nil
}
func fixtureStats()*vpnPacketStats{
    s:=&vpnPacketStats{trace:newDiagnosticTCPFlow("172.16.0.2")}
    s.suppressUDP.Store(true)
    return s
}
func boundedHandoffRead(t *testing.T,h *handoffTun,capacity,offset int)([]byte,int,error){
    t.Helper()
    type result struct{buf []byte;size int;err error}
    done:=make(chan result,1)
    go func(){
        buf:=bytes.Repeat([]byte{0xa5},capacity)
        sizes:=make([]int,1)
        n,err:=h.Read([][]byte{buf},sizes,offset)
        if err==nil && n!=1{err=ErrVPNInit}
        done<-result{buf:buf,size:sizes[0],err:err}
    }()
    select {
    case r:=<-done:return r.buf,r.size,r.err
    case <-time.After(time.Second):t.Fatal("handoff read blocked");return nil,0,os.ErrDeadlineExceeded
    }
}
func TestHandoffPreservesFramingOffsetsAndNativeWriteCounts(t *testing.T){
    initial,native:=newHandoffFixture(false),newHandoffFixture(true)
    stats:=fixtureStats()
    h:=newHandoffTun(initial,stats)
    defer h.Close()
    before:=[]byte{0x45,1,2,3,4}
    initial.input<-before
    buf,n,err:=boundedHandoffRead(t,h,64,16)
    if err!=nil || n!=len(before) || !bytes.Equal(buf[16:16+n],before) ||
        !bytes.Equal(buf[:16],bytes.Repeat([]byte{0xa5},16)){
        t.Fatal("preflight packet framing/offset changed")
    }
    if _,err=h.Write([][]byte{append(make([]byte,16),before...)},16);err!=nil{
        t.Fatal("preflight sink failed")
    }
    if stats.tunIn.Load()!=0 || stats.tunOut.Load()!=0{t.Fatal("preflight counted as Android traffic")}
    if err=h.attach(native);err!=nil{t.Fatal("native attach failed")}
    after:=[]byte{0x45,9,8,7,6}
    native.input<-after
    buf,n,err=boundedHandoffRead(t,h,64,16)
    if err!=nil || !bytes.Equal(buf[16:16+n],after){t.Fatal("native packet changed")}
    count,err:=h.Write([][]byte{append(make([]byte,16),after...)},16)
    if err!=nil || count!=1 || stats.tunIn.Load()!=1 || stats.tunOut.Load()!=1{
        t.Fatal("native TUN byte result was not normalized to one packet")
    }
    if stats.suppressUDP.Load(){t.Fatal("post-handoff UDP accounting stayed disabled")}
    if len(initial.writes)!=1 || len(native.writes)!=1 ||
        !bytes.Equal(native.writes[0],after){t.Fatal("decrypted packet went to the wrong stack")}
    _=h.Close();_=h.Close()
    if initial.closeCalls.Load()!=1 || native.closeCalls.Load()!=1{t.Fatal("underlying TUN closed more than once")}
}
func TestHandoffDiscardsQueuedPreflightPackets(t *testing.T){
    initial,native:=newHandoffFixture(false),newHandoffFixture(true)
    h:=newHandoffTun(initial,fixtureStats())
    defer h.Close()
    h.packets<-handoffPacket{phase:0,data:[]byte("stale-preflight")}
    h.packets<-handoffPacket{phase:0,err:os.ErrClosed}
    if h.attach(native)!=nil{t.Fatal("attach failed")}
    native.input<-[]byte("android")
    buf,n,err:=boundedHandoffRead(t,h,64,0)
    if err!=nil || string(buf[:n])!="android"{t.Fatal("stale preflight data/error crossed handoff")}
    second:=newHandoffFixture(true)
    if h.attach(second)==nil{t.Fatal("second native attachment accepted")}
    if second.closeCalls.Load()!=0{t.Fatal("failed attach took caller ownership")}
    _=second.Close()
}
func TestHandoffNeverTruncatesAnIPPacket(t *testing.T){
    initial:=newHandoffFixture(false)
    h:=newHandoffTun(initial,fixtureStats())
    defer h.Close()
    initial.input<-bytes.Repeat([]byte{0x45},100)
    buf,_,err:=boundedHandoffRead(t,h,20,16)
    if !errors.Is(err,io.ErrShortBuffer) || !bytes.Equal(buf,bytes.Repeat([]byte{0xa5},20)){
        t.Fatal("short destination silently truncated an IP packet")
    }
}
func TestHandoffCloseInterruptsReadAndBlockedWrite(t *testing.T){
    initial:=newHandoffFixture(false)
    initial.writeEntered=make(chan struct{})
    h:=newHandoffTun(initial,fixtureStats())
    defer h.Close()
    writer:=make(chan struct{})
    go func(){_,_=h.Write([][]byte{[]byte("fixture")},0);close(writer)}()
    select {case <-initial.writeEntered:case <-time.After(time.Second):t.Fatal("write did not enter fixture")}
    native:=newHandoffFixture(true)
    attaching:=make(chan error,1)
    go func(){attaching<-h.attach(native)}()
    _=h.Close()
    select {case <-writer:case <-time.After(time.Second):t.Fatal("close waited on a blocked write")}
    select {
    case err:=<-attaching:
        if err==nil{t.Fatal("attached to closed handoff")}
    case <-time.After(time.Second):t.Fatal("attach did not exit after close")
    }
    _=native.Close()
    if _,_,err:=boundedHandoffRead(t,h,64,0);!errors.Is(err,os.ErrClosed){
        t.Fatal("closed reader did not return closed error")
    }
}
