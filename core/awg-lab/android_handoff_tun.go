// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "io"
    "os"
    "sync"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type handoffPacket struct {
    phase uint8
    data []byte
    err error
}

// One AWG device sees one stable tun.Device. Only its IP source/sink changes:
// a temporary netstack first, then the Android TUN. Crypto/UDP never restart.
type handoffTun struct {
    mu sync.Mutex
    writeMu sync.Mutex
    closeOnce sync.Once
    initial tun.Device
    native tun.Device
    phase uint8
    closed bool
    packets chan handoffPacket
    done chan struct{}
    events chan tun.Event
    preflightDone chan struct{}
    stats *vpnPacketStats
}

func newHandoffTun(initial tun.Device,stats *vpnPacketStats)*handoffTun{
    h:=&handoffTun{initial:initial,packets:make(chan handoffPacket,64),
        done:make(chan struct{}),events:make(chan tun.Event,1),
        preflightDone:make(chan struct{}),stats:stats}
    h.events<-tun.EventUp
    go h.pump(initial,0)
    return h
}
func (h *handoffTun) active(phase uint8)bool{
    h.mu.Lock();defer h.mu.Unlock()
    return !h.closed && h.phase==phase
}
func (h *handoffTun) emit(p handoffPacket){
    if !h.active(p.phase){return}
    var phaseDone <-chan struct{}
    if p.phase==0{phaseDone=h.preflightDone}
    select {
    case <-phaseDone:
    case h.packets<-p:
    case <-h.done:
    }
}
func (h *handoffTun) pump(source tun.Device,phase uint8){
    batch:=source.BatchSize()
    if batch<1{batch=1}
    bufs:=make([][]byte,batch)
    for i:=range bufs{bufs[i]=make([]byte,65535)}
    sizes:=make([]int,batch)
    for {
        n,err:=source.Read(bufs,sizes,0)
        if n<0 || n>len(bufs){
            h.emit(handoffPacket{phase:phase,err:ErrVPNInit})
            return
        }
        for i:=0;i<n;i++{
            if sizes[i]<0 || sizes[i]>len(bufs[i]){
                h.emit(handoffPacket{phase:phase,err:ErrVPNInit})
                return
            }
            if sizes[i]>0 && h.active(phase){
                copyOfPacket:=append([]byte(nil),bufs[i][:sizes[i]]...)
                h.emit(handoffPacket{phase:phase,data:copyOfPacket})
            }
        }
        if err!=nil{
            h.emit(handoffPacket{phase:phase,err:err})
            return
        }
        // Keep draining an inactive source until its Close returns. Netstack's
        // WriteNotify sends on an unbuffered channel while stack.Close runs.
    }
}
func (h *handoffTun) File()*os.File{return nil}
func (h *handoffTun) Name()(string,error){return "autowarp-handoff",nil}
func (h *handoffTun) MTU()(int,error){return 1280,nil}
func (h *handoffTun) BatchSize()int{return 1}
func (h *handoffTun) Events()<-chan tun.Event{return h.events}
func (h *handoffTun) Read(bufs [][]byte,sizes []int,offset int)(int,error){
    if len(bufs)==0 || len(sizes)==0 || offset<0 || offset>len(bufs[0]){
        return 0,ErrVPNInit
    }
    for {
        select {case <-h.done:return 0,os.ErrClosed;default:}
        select {
        case <-h.done:return 0,os.ErrClosed
        case packet:=<-h.packets:
            if !h.active(packet.phase){continue} // discard stale preflight IP
            if packet.err!=nil{return 0,packet.err}
            if len(packet.data)>len(bufs[0])-offset{return 0,io.ErrShortBuffer}
            sizes[0]=copy(bufs[0][offset:],packet.data)
            return 1,nil
        }
    }
}
func (h *handoffTun) Write(bufs [][]byte,offset int)(int,error){
    h.writeMu.Lock();defer h.writeMu.Unlock()
    h.mu.Lock()
    if h.closed{h.mu.Unlock();return 0,os.ErrClosed}
    sink:=h.initial
    if h.phase==1{sink=h.native}
    h.mu.Unlock()
    return sink.Write(bufs,offset)
}

// Takes ownership of native only on success. Close never waits on writeMu,
// so it can interrupt a blocked native write or a handoff waiting for a write.
func (h *handoffTun) attach(native tun.Device)error{
    if native==nil{return ErrVPNInit}
    h.writeMu.Lock();defer h.writeMu.Unlock()
    h.mu.Lock()
    if h.closed || h.phase!=0{
        h.mu.Unlock()
        return ErrVPNInit
    }
    old:=h.initial
    h.initial=nil
    counted:=&countingTun{Device:native,stats:h.stats}
    h.native=counted
    h.phase=1
    close(h.preflightDone)
    // Preflight UDP must never count as traffic after Android TUN creation.
    h.stats.suppressUDP.Store(false)
    h.mu.Unlock()
    _=old.Close()
    go h.pump(counted,1)
    return nil
}
func (h *handoffTun) Close()error{
    h.closeOnce.Do(func(){
        h.mu.Lock()
        h.closed=true
        initial,native:=h.initial,h.native
        h.initial=nil;h.native=nil
        close(h.done)
        close(h.events)
        h.mu.Unlock()
        if initial!=nil{_=initial.Close()}
        if native!=nil{_=native.Close()}
    })
    return nil
}
