// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "context"
    "net"
    "net/netip"
    "sync"
    "strings"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    "golang.org/x/sys/unix"
)

// retainedUDP owns the original, already protected kernel socket. Each AWG
// device gets a duplicate descriptor. Closing a device unblocks its own read
// without destroying the socket kept for the next sequential device.
type retainedUDP struct {
    mu sync.Mutex
    socket *net.UDPConn
}

func (r *retainedUDP) lease(port uint16)(*net.UDPConn,error){
    if r==nil{return nil,net.ErrClosed}
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.socket==nil{return nil,net.ErrClosed}
    local,ok:=r.socket.LocalAddr().(*net.UDPAddr)
    if !ok || port!=0 && int(port)!=local.Port{return nil,ErrVPNInit}
    file,err:=r.socket.File()
    if err!=nil{return nil,err}
    defer file.Close()
    packet,err:=net.FilePacketConn(file)
    if err!=nil{return nil,err}
    udp,ok:=packet.(*net.UDPConn)
    if !ok{_=packet.Close();return nil,ErrVPNInit}
    return udp,nil
}

func (r *retainedUDP) close(){
    if r==nil{return}
    r.mu.Lock()
    socket:=r.socket
    r.socket=nil
    r.mu.Unlock()
    if socket!=nil{_=socket.Close()}
}

func newRetainedBind(owner *retainedUDP,stats ...*vpnPacketStats)*protectedBind{
    bind:=&protectedBind{retained:owner}
    if len(stats)>0{bind.stats=stats[0]}
    return bind
}

// AndroidVPNPreparation owns one already-running AWG device until Start
// transfers it to AndroidVPN ownership. No second device/handshake is created.
type AndroidVPNPreparation struct {
    mu sync.Mutex
    engine *AndroidVPN
    handoff *handoffTun
    stack *netstack.Net
    probing bool
    probed bool
    preflightHTTPS bool
    country string
    colo string
    postProbed bool
    postUDP string
    markBefore udpSocketState
    closed bool
    cancel context.CancelFunc
}

// PrepareAndroidVPN resolves/protects before Android establishes its VPN.
// One device starts on a private netstack and remains alive through Start.
func PrepareAndroidVPN(quick string,protector SocketProtector)(*AndroidVPNPreparation,error){
    if protector==nil{return nil,ErrVPNProtect}
    cfg,err:=FromQuickConfig(quick)
    if err!=nil{return nil,ErrInvalidAWGFile}
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    uapi,err:=normalizeIPCEndpoint(ctx,cfg.IPCSettings,resolvePhysicalIP)
    if err!=nil{return nil,ErrEndpointDNS}
    socket,err:=openProtectedUDP(protector,0)
    if err!=nil{return nil,err}
    owner:=&retainedUDP{socket:socket}
    local,err:=netip.ParseAddr(cfg.LocalIPv4)
    if err!=nil{owner.close();return nil,ErrVPNInit}
    initial,stack,err:=netstack.CreateNetTUN([]netip.Addr{local},
        []netip.Addr{netip.MustParseAddr("1.1.1.1")},1280)
    if err!=nil{owner.close();return nil,ErrTunCreate}
    stats:=&vpnPacketStats{trace:newDiagnosticTCPFlow(cfg.LocalIPv4)}
    stats.suppressUDP.Store(true)
    handoff:=newHandoffTun(initial,stats)
    dev:=device.NewDevice(handoff,newRetainedBind(owner,stats),
        device.NewLogger(device.LogLevelSilent,""))
    engine:=&AndroidVPN{dev:dev,stats:stats,transport:owner}
    if dev.IpcSet(uapi)!=nil{engine.Stop();return nil,ErrIPCConfig}
    if dev.Up()!=nil{engine.Stop();return nil,ErrDeviceStart}
    return &AndroidVPNPreparation{engine:engine,handoff:handoff,stack:stack},nil
}

// ProbeWarp leaves the existing device/session alive. Only the HTTP client
// closes; Start cannot overlap a live probe. Close cancels and stops the device.
func (p *AndroidVPNPreparation) ProbeWarp()(string,error){
    return p.probeWarpStage(false)
}

// Run only after Builder.establish and before Start. This retains the same
// userspace TCP stack, AWG device and protected socket across route creation.
func (p *AndroidVPNPreparation) ProbeWarpAfterTUN()(string,error){
    return p.probeWarpStage(true)
}

func (p *AndroidVPNPreparation) probeWarpStage(afterTUN bool)(string,error){
    if p==nil{return "awg_device_start_failed",nil}
    p.mu.Lock()
    if p.closed || p.probing || p.engine==nil || p.stack==nil ||
        (!afterTUN && p.probed) || (afterTUN && (!p.preflightHTTPS || p.postProbed)){
        p.mu.Unlock()
        return "awg_device_start_failed",nil
    }
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    p.cancel=cancel
    p.probing=true
    p.country=""
    p.colo=""
    if afterTUN{p.postProbed=true}else{p.probed=true}
    engine,stack:=p.engine,p.stack
    sent,received,sendErrors,recvErrors:=engine.stats.preparationUDP()
    p.mu.Unlock()
    defer func(){
        cancel()
        p.mu.Lock()
        if !afterTUN{p.markBefore=engineUDPSocketState(engine)}
        if afterTUN{
            tx,rx,txErr,rxErr:=engine.stats.preparationUDP()
            p.postUDP=postTUNUDPCode(tx-sent,rx-received,txErr-sendErrors,rxErr-recvErrors)
        }
        p.probing=false;p.cancel=nil
        p.mu.Unlock()
    }()
    engine.mu.Lock()
    dev:=engine.dev
    engine.mu.Unlock()
    if dev==nil{return "awg_device_start_failed",nil}
    result,err:=probeHTTPS(ctx,dev,func(ctx context.Context)(net.Conn,error){
        return stack.DialContext(ctx,"tcp","1.1.1.1:443")
    })
    outcome,outcomeErr:=probeWarpOutcome(result,err)
    p.mu.Lock()
    p.country=traceCountryCode(result.Country)
    p.colo=traceColoCode(result.Colo)
    p.mu.Unlock()
    if !afterTUN{
        p.mu.Lock()
        p.preflightHTTPS=outcomeErr==nil && preparationHTTPSConfirmed(outcome)
        p.mu.Unlock()
    }
    return outcome,outcomeErr
}

// Start consumes fd on EVERY path. It attaches Android's TUN to the existing
// device without IpcSet, Up, socket creation or a fresh cryptographic session.
func (p *AndroidVPNPreparation) Start(fd int)(*AndroidVPN,error){
    return p.start(fd,nil)
}

// StartWithDNS preserves the verified AWG session and installs a local DNS
// frontend. Only HTTPS from the exchanger crosses the existing VPN route.
func (p *AndroidVPNPreparation) StartWithDNS(fd int,exchange DNSExchanger)(*AndroidVPN,error){
    return p.start(fd,exchange)
}

func (p *AndroidVPNPreparation) start(fd int,exchange DNSExchanger)(*AndroidVPN,error){
    if fd<0{return nil,ErrVPNInit}
    owned:=true
    defer func(){if owned{_=unix.Close(fd)}}()
    if p==nil{return nil,ErrVPNInit}
    p.mu.Lock()
    if p.closed || p.probing || !p.preflightHTTPS || p.engine==nil || p.handoff==nil{
        p.mu.Unlock()
        return nil,ErrVPNInit
    }
    engine,handoff:=p.engine,p.handoff
    p.engine=nil;p.handoff=nil;p.stack=nil;p.closed=true
    p.mu.Unlock()
    native,_,err:=tun.CreateUnmonitoredTUNFromFD(fd)
    if err!=nil{engine.Stop();return nil,ErrVPNInit}
    owned=false
    if exchange!=nil{
        wrapped,e:=newDNSTun(native,exchange)
        if e!=nil{_=native.Close();engine.Stop();return nil,ErrVPNInit}
        native=wrapped
    }
    if err=handoff.attach(native);err!=nil{
        _=native.Close()
        engine.Stop()
        return nil,ErrVPNInit
    }
    return engine,nil
}

func (p *AndroidVPNPreparation) Close(){
    if p==nil{return}
    p.mu.Lock()
    engine,cancel:=p.engine,p.cancel
    p.engine=nil;p.handoff=nil;p.stack=nil;p.cancel=nil;p.closed=true
    p.mu.Unlock()
    if cancel!=nil{cancel()}
    if engine!=nil{engine.Stop()}
}

// Only fixed comparison codes leave native code; never export marks/ports.
type udpSocketState struct { mark int; port uint16; valid bool }
func readUDPSocketState(socket *net.UDPConn)udpSocketState{
    if socket==nil{return udpSocketState{}}
    state:=udpSocketState{}
    raw,err:=socket.SyscallConn()
    if err!=nil{return state}
    var socketErr error
    err=raw.Control(func(fd uintptr){
        state.mark,socketErr=unix.GetsockoptInt(int(fd),unix.SOL_SOCKET,unix.SO_MARK)
    })
    local,ok:=socket.LocalAddr().(*net.UDPAddr)
    if err!=nil || socketErr!=nil || !ok{return udpSocketState{}}
    state.port=uint16(local.Port);state.valid=true
    return state
}
func compareUDPSocketState(before,after udpSocketState)string{
    if !before.valid || !after.valid{return "awg_transport_unknown"}
    if before.port!=after.port{return "awg_transport_port_changed"}
    if before.mark!=after.mark{return "awg_transport_mark_changed"}
    return "awg_transport_unchanged"
}
func (p *AndroidVPNPreparation) TransportState()string{
    if p==nil{return "awg_transport_unknown"}
    p.mu.Lock();defer p.mu.Unlock()
    if p.closed || p.engine==nil{return "awg_transport_unknown"}
    return compareUDPSocketState(p.markBefore,engineUDPSocketState(p.engine))
}
func engineUDPSocketState(engine *AndroidVPN)udpSocketState{
    if engine==nil{return udpSocketState{}}
    engine.mu.Lock();defer engine.mu.Unlock()
    owner:=engine.transport
    if owner==nil{return udpSocketState{}}
    owner.mu.Lock();defer owner.mu.Unlock()
    return readUDPSocketState(owner.socket)
}
func (p *AndroidVPNPreparation) PostTUNUDPState()string{
    if p==nil{return "awg_post_udp_unknown"}
    p.mu.Lock();defer p.mu.Unlock()
    if p.postUDP==""{return "awg_post_udp_unknown"}
    return p.postUDP
}
func postTUNUDPCode(sent,received,sendErrors,recvErrors int64)string{
    switch {
    case sendErrors>0:return "awg_post_udp_send_error"
    case recvErrors>0:return "awg_post_udp_receive_error"
    case sent==0:return "awg_post_udp_no_send"
    case received==0:return "awg_post_udp_no_reply"
    default:return "awg_post_udp_bidirectional"
    }
}

// The synthetic CI peer returns a validated HTTPS trace with warp=off. It
// may exercise the adapter, but it can never mark a real WARP VPN connected.
func preparationHTTPSConfirmed(outcome string)bool{
    return strings.HasPrefix(outcome,"awg_verified:") || outcome=="awg_not_confirmed"
}

// CountryCode is the GeoIP classification from the last successful trace.
// Missing/failed probes return unknown; no fallback to a prior result.
func (p *AndroidVPNPreparation) CountryCode()string{
    if p==nil{return ""}
    p.mu.Lock();defer p.mu.Unlock()
    if p.closed{return ""}
    return p.country
}

// ColoCode identifies the node serving the last successful HTTPS trace.
// It is not an assertion about the tunnel's physical ingress or IP GeoIP.
func (p *AndroidVPNPreparation) ColoCode()string{
    if p==nil{return ""}
    p.mu.Lock();defer p.mu.Unlock()
    if p.closed{return ""}
    return p.colo
}
