// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "context"
    "encoding/binary"
    "errors"
    "net"
    "net/netip"
    "fmt"
    "sync/atomic"
    "golang.org/x/sys/unix"
    "sync"
    "strconv"
    "syscall"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// SocketProtector must forward to Android VpnService.protect(fd).
// The callback is called before the UDP socket is bound or used.
type SocketProtector interface {
    Protect(fd int) bool
}

var ErrVPNInit=errors.New("awg_vpn_init_failed")
var ErrVPNProtect=errors.New("awg_vpn_protect_failed")

// AndroidVPN is a native transport component, not a complete Android VPN.
// Android still owns VpnService lifecycle, routing and HTTPS verification.
type AndroidVPN struct{
    mu sync.Mutex
    dev *device.Device
    stats *vpnPacketStats
    transport *retainedUDP
}
type vpnPacketStats struct{
    suppressUDP atomic.Bool
    preSent atomic.Int64
    preRecv atomic.Int64
    preSendErrors atomic.Int64
    preRecvErrors atomic.Int64
    tunIn atomic.Int64
    tunOut atomic.Int64
    tunReadBytes atomic.Int64
    tunWrittenBytes atomic.Int64
    udpSent atomic.Int64
    udpRecv atomic.Int64
    udpSendErrors atomic.Int64
    udpRecvErrors atomic.Int64
    udpLoop atomic.Int64
    udpLocalPort atomic.Uint32
    udpPeer atomic.Uint64
    tcpSyn atomic.Int64
    tcpSynAck atomic.Int64
    tcpRst atomic.Int64
    trace *diagnosticTCPFlow
}
// PacketCounters returns four non-sensitive packet counts as CSV:
// Android->AWG, AWG->Android, encrypted UDP send, encrypted UDP receive.
// It never exposes packet contents, IPs, keys or endpoints.
func (a *AndroidVPN) PacketCounters() string {
    if a==nil || a.stats==nil {return "0,0,0,0"}
    s:=a.stats
    return fmt.Sprintf("%d,%d,%d,%d",s.tunIn.Load(),s.tunOut.Load(),
        s.udpSent.Load(),s.udpRecv.Load())
}
// TrafficBytes returns cumulative inner-IP bytes as download,upload CSV.
// Read is Android->AWG (upload); accepted Write is AWG->Android (download).
// Outer UDP masking/keepalives and preflight netstack bytes are excluded.
func (a *AndroidVPN) TrafficBytes()string{
    if a==nil || a.stats==nil{return "0,0"}
    return fmt.Sprintf("%d,%d",a.stats.tunWrittenBytes.Load(),a.stats.tunReadBytes.Load())
}
// TCPTraceCounters counts only TCP control flags on the fixed 1.1.1.1:443
// diagnostic flow. No addresses, payloads or per-user traffic is retained.
func (a *AndroidVPN) TCPTraceCounters() string {
    if a==nil || a.stats==nil{return "0,0,0"}
    s:=a.stats
    return fmt.Sprintf("%d,%d,%d",s.tcpSyn.Load(),s.tcpSynAck.Load(),s.tcpRst.Load())
}
// inspectDiagnosticTCP filters IPv4 TCP control packets to the test endpoint.
// Incoming means Android->TUN, outgoing means decrypted WARP->Android.
func inspectDiagnosticTCP(packet []byte, incoming bool, s *vpnPacketStats) {
    if s==nil || len(packet)<40 || packet[0]>>4!=4 {return}
    ihl:=int(packet[0]&15)*4
    if ihl<20 || len(packet)<ihl+20 || packet[9]!=6{return}
    // Ignore fragmented IPv4 packets (including non-first fragments).
    if binary.BigEndian.Uint16(packet[6:8])&0x3fff!=0{return}
    destination:=[]byte{1,1,1,1}
    var port uint16
    if incoming {
        if packet[16]!=destination[0] || packet[17]!=destination[1] ||
           packet[18]!=destination[2] || packet[19]!=destination[3]{return}
        port=binary.BigEndian.Uint16(packet[ihl+2:ihl+4])
    }else{
        if packet[12]!=destination[0] || packet[13]!=destination[1] ||
           packet[14]!=destination[2] || packet[15]!=destination[3]{return}
        port=binary.BigEndian.Uint16(packet[ihl:ihl+2])
    }
    if port!=443{return}
    flags:=packet[ihl+13]
    if incoming && flags&0x12==0x02 {s.tcpSyn.Add(1)}
    if !incoming && flags&0x12==0x12 {s.tcpSynAck.Add(1)}
    if !incoming && flags&0x04!=0 {s.tcpRst.Add(1)}
}
// Counting device is transparent: underlying implementation still owns TUN.
type countingTun struct{
    tun.Device
    stats *vpnPacketStats
}
func (t *countingTun) Read(bufs [][]byte,sizes []int,offset int)(int,error){
    n,err:=t.Device.Read(bufs,sizes,offset)
    if n>0 {
        t.stats.tunIn.Add(int64(n))
        for i:=0;i<n && i<len(bufs) && i<len(sizes);i++{
            start:=offset
            end:=offset+sizes[i]
            if start>=0 && end>=start && end<=len(bufs[i]){
                if isOwnUDPPacket(bufs[i][start:end],t.stats.udpLocalPort.Load(),t.stats.udpPeer.Load()){
                    // Do not encrypt our own outer UDP again. A TUN read error
                    // makes AWG close the device and prevents runaway loops.
                    t.stats.udpLoop.Add(1)
                    return 0,ErrVPNRoutingLoop
                }
                t.stats.tunReadBytes.Add(int64(end-start))
                inspectDiagnosticTCP(bufs[i][start:end],true,t.stats)
                t.stats.trace.observe(bufs[i][start:end],true)
            }
        }
    }
    return n,err
}
func (t *countingTun) Write(bufs [][]byte,offset int)(int,error){
    // NativeTun.Write in the pinned AWG version returns BYTES, although
    // tun.Device's contract says PACKETS. Write individually so acceptance
    // and diagnostics refer to the actual packet, even on a partial batch.
    for i,buf:=range bufs {
        if offset<0 || offset>len(buf) {return i,ErrVPNInit}
        packet:=buf[offset:]
        token:=t.stats.trace.writeToken(packet)
        synAck:=t.stats.trace.observe(packet,false)
        n,err:=t.Device.Write(bufs[i:i+1],offset)
        success:=err==nil && n>0
        t.stats.trace.written(token,synAck,success)
        if !success {
            if err==nil {err=ErrVPNInit}
            return i,err
        }
        t.stats.tunOut.Add(1)
        t.stats.tunWrittenBytes.Add(int64(len(packet)))
        inspectDiagnosticTCP(packet,false,t.stats)
    }
    return len(bufs),nil
}

// Stop is idempotent. It releases the native TUN and protected UDP bind.
func (a *AndroidVPN) Stop(){
    if a==nil{return}
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.dev!=nil{a.dev.Close();a.dev=nil}
    if a.transport!=nil{a.transport.close();a.transport=nil}
}
func (a *AndroidVPN) IsRunning()bool{
    if a==nil{return false}
    a.mu.Lock();defer a.mu.Unlock()
    return a.dev!=nil
}
func (a *AndroidVPN) HasHandshake()bool{
    if a==nil{return false}
    a.mu.Lock();defer a.mu.Unlock()
    return a.dev!=nil && handshakeSeen(a.dev)
}

// StartAndroidVPN consumes a DUPLICATED Android TUN fd, even on failure.
// Android must first establish the TUN with VpnService.Builder, protect all
// UDP sockets, and ensure no second VPN engine is using that same TUN.
func StartAndroidVPN(fd int,quick string,protector SocketProtector)(*AndroidVPN,error){
    if fd<0{return nil,ErrVPNInit}
    // Avoid constructing two os.File objects for one FD: the finalizer
    // of either object could otherwise close a live Android VPN tunnel.
    owned:=true
    defer func(){if owned{_ = unix.Close(fd)}}()
    if protector==nil{return nil,ErrVPNProtect}
    cfg,err:=FromQuickConfig(quick)
    if err!=nil{return nil,ErrInvalidAWGFile}
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    uapi,err:=normalizeIPCEndpoint(ctx,cfg.IPCSettings,resolvePhysicalIP)
    if err!=nil{return nil,ErrEndpointDNS}
    owned=false // transfer descriptor ownership to the configured constructor
    return startAndroidVPNConfigured(fd,cfg,uapi,protector,nil)
}

// Consumes fd on every path. A retained transport was protected before TUN.
func startAndroidVPNConfigured(fd int,cfg Config,uapi string,protector SocketProtector,
    transport *retainedUDP)(*AndroidVPN,error){
    if fd<0{return nil,ErrVPNInit}
    owned:=true
    defer func(){if owned{_=unix.Close(fd)}}()
    if protector==nil && transport==nil{return nil,ErrVPNProtect}
    tunDevice,_,err:=tun.CreateUnmonitoredTUNFromFD(fd)
    if err!=nil{return nil,ErrVPNInit}
    owned=false // tunDevice is the sole os.File owner of this descriptor.
    stats:=&vpnPacketStats{trace:newDiagnosticTCPFlow(cfg.LocalIPv4)}
    bind:=newProtectedBind(protector,stats)
    if transport!=nil{bind=newRetainedBind(transport,stats)}
    dev:=device.NewDevice(&countingTun{Device:tunDevice,stats:stats},
        bind,
        device.NewLogger(device.LogLevelSilent,""))
    if dev.IpcSet(uapi)!=nil{dev.Close();return nil,ErrIPCConfig}
    if dev.Up()!=nil{dev.Close();return nil,ErrDeviceStart}
    return &AndroidVPN{dev:dev,stats:stats,transport:transport},nil
}

// The first Android adapter deliberately supports only IPv4 endpoints.
// IPv6 sockets are not silently opened without protection. BatchSize=1
// favors correctness over performance pending actual Android E2E testing.
type protectedBind struct{
    mu sync.Mutex
    socket *net.UDPConn
    protector SocketProtector
    retained *retainedUDP
    stats *vpnPacketStats
}
func newProtectedBind(p SocketProtector,stats ...*vpnPacketStats)*protectedBind{
    b:=&protectedBind{protector:p}
    if len(stats)>0{b.stats=stats[0]}
    return b
}
// Protect/bind the original kernel socket before any UDP bind or send.
func openProtectedUDP(protector SocketProtector,port uint16)(*net.UDPConn,error){
    lc:=net.ListenConfig{Control:func(_, _ string,raw syscall.RawConn)error{
        if protector==nil{return ErrVPNProtect}
        var protectErr error
        err:=raw.Control(func(fd uintptr){
            if !protector.Protect(int(fd)){protectErr=ErrVPNProtect}
        })
        if err!=nil{return ErrVPNProtect}
        return protectErr
    }}
    packet,err:=lc.ListenPacket(context.Background(),"udp4",
        net.JoinHostPort("0.0.0.0",strconv.Itoa(int(port))))
    if err!=nil{return nil,err}
    udp,ok:=packet.(*net.UDPConn)
    if !ok{_ = packet.Close();return nil,ErrVPNInit}
    return udp,nil
}
func (b *protectedBind) Open(port uint16)([]conn.ReceiveFunc,uint16,error){
    b.mu.Lock();defer b.mu.Unlock()
    if b.socket!=nil{return nil,0,conn.ErrBindAlreadyOpen}
    var udp *net.UDPConn
    var err error
    if b.retained!=nil{
        udp,err=b.retained.lease(port)
    }else{
        udp,err=openProtectedUDP(b.protector,port)
    }
    if err!=nil{return nil,0,err}
    local,ok:=udp.LocalAddr().(*net.UDPAddr)
    if !ok{_ = udp.Close();return nil,0,ErrVPNInit}
    b.socket=udp
    if b.stats!=nil{b.stats.udpLocalPort.Store(uint32(local.Port))}
    recv:=func(bufs [][]byte,sizes []int,eps []conn.Endpoint)(int,error){
        if len(bufs)==0 || len(sizes)==0 || len(eps)==0{return 0,ErrVPNInit}
        n,addr,err:=udp.ReadFromUDPAddrPort(bufs[0])
        if err!=nil{
            if b.stats!=nil && !errors.Is(err,net.ErrClosed){b.stats.recordUDP(false,true)}
            return 0,err
        }
        sizes[0]=n
        if b.stats!=nil{b.stats.recordUDP(false,false)}
        eps[0]=&conn.StdNetEndpoint{AddrPort:addr}
        return 1,nil
    }
    return []conn.ReceiveFunc{recv},uint16(local.Port),nil
}
func (b *protectedBind) Close()error{
    b.mu.Lock();s:=b.socket;b.socket=nil;b.mu.Unlock()
    if s!=nil{return s.Close()}
    return nil
}
func (*protectedBind) SetMark(mark uint32)error{
    if mark!=0{return ErrVPNInit}
    return nil
}
func (b *protectedBind) Send(bufs [][]byte,ep conn.Endpoint)error{
    b.mu.Lock();s:=b.socket;b.mu.Unlock()
    if s==nil{return net.ErrClosed}
    dst,err:=netip.ParseAddrPort(ep.DstToString())
    if err!=nil || !dst.Addr().Is4(){return ErrVPNInit}
    if b.stats!=nil{b.stats.udpPeer.Store(udpPeerMarker(dst))}
    for _,pkt:=range bufs{
        if _,err=s.WriteToUDPAddrPort(pkt,dst);err!=nil{
            if b.stats!=nil{b.stats.recordUDP(true,true)}
            return err
        }
        if b.stats!=nil{b.stats.recordUDP(true,false)}
    }
    return nil
}
func (*protectedBind) ParseEndpoint(s string)(conn.Endpoint,error){
    ip,err:=netip.ParseAddrPort(s)
    if err!=nil{return nil,err}
    if !usablePeerAddress(ip.Addr()){return nil,ErrVPNInit}
    return &conn.StdNetEndpoint{AddrPort:ip},nil
}
func (*protectedBind) BatchSize()int{return 1}


// Separate accounting windows: preparation traffic never becomes Android TUN
// evidence. Atomic counters also include UDP errors without exposing payloads.
func (s *vpnPacketStats) recordUDP(sent,failed bool){
    if s.suppressUDP.Load(){
        switch {
        case sent && failed:s.preSendErrors.Add(1)
        case sent:s.preSent.Add(1)
        case failed:s.preRecvErrors.Add(1)
        default:s.preRecv.Add(1)
        }
        return
    }
    switch {
    case sent && failed:s.udpSendErrors.Add(1)
    case sent:s.udpSent.Add(1)
    case failed:s.udpRecvErrors.Add(1)
    default:s.udpRecv.Add(1)
    }
}
func (s *vpnPacketStats) preparationUDP()(int64,int64,int64,int64){
    return s.preSent.Load(),s.preRecv.Load(),s.preSendErrors.Load(),s.preRecvErrors.Load()
}
