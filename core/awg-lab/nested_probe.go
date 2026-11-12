// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "context"
    "net"
    "net/netip"
    "strings"
    "sync"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// NestedProbe is an isolated experiment, never an Android system VPN.
// Only the outer device owns a host UDP socket, which must be protected.
// The inner device's UDP socket lives entirely in the outer private stack.
type NestedProbe struct {
    mu sync.Mutex
    cancel context.CancelFunc
    running,closed bool
    outer,inner Result
    outerMeta,innerMeta Result
    ip string
}

func NewNestedProbe()*NestedProbe{return &NestedProbe{}}

func (p *NestedProbe) Close(){
    if p==nil{return}
    p.mu.Lock();p.closed=true;c:=p.cancel;p.mu.Unlock()
    if c!=nil{c()}
}

func (p *NestedProbe) OuterCountry()string{p.mu.Lock();defer p.mu.Unlock();return p.outer.Country}
func (p *NestedProbe) OuterColo()string{p.mu.Lock();defer p.mu.Unlock();return p.outer.Colo}
func (p *NestedProbe) InnerCountry()string{p.mu.Lock();defer p.mu.Unlock();return p.inner.Country}
func (p *NestedProbe) InnerColo()string{p.mu.Lock();defer p.mu.Unlock();return p.inner.Colo}
func (p *NestedProbe) OuterMetaCountry()string{p.mu.Lock();defer p.mu.Unlock();return p.outerMeta.Country}
func (p *NestedProbe) InnerMetaCountry()string{p.mu.Lock();defer p.mu.Unlock();return p.innerMeta.Country}
func (p *NestedProbe) InnerMetaColo()string{p.mu.Lock();defer p.mu.Unlock();return p.innerMeta.Colo}
func (p *NestedProbe) ExitIP()string{p.mu.Lock();defer p.mu.Unlock();return p.ip}
func (p *NestedProbe) LatencyMillis()int64{p.mu.Lock();defer p.mu.Unlock();return p.inner.Latency.Milliseconds()}

func ipcField(raw,key string)string{
    for _,line:=range strings.Split(raw,"\n"){
        k,v,ok:=strings.Cut(line,"=");if ok && k==key{return v}
    }
    return ""
}

func nestedEndpoint(raw,endpoint string)(string,error){
    ep,err:=netip.ParseAddrPort(endpoint)
    if err!=nil || !usablePeerAddress(ep.Addr()) || ep.Port()==0{return "",ErrEndpointDNS}
    rows:=strings.Split(raw,"\n")
    for i,line:=range rows{if strings.HasPrefix(line,"endpoint="){rows[i]="endpoint="+ep.String()}}
    return strings.Join(rows,"\n"),nil
}

const nestedMTU=1280-60 // IPv4 + UDP + WireGuard data header + authentication tag.

// Run performs HTTPS over the outer stack and then through up to four inner
// endpoints. It returns fixed codes only; no exception/config can cross JNI.
func (p *NestedProbe) Run(outerQuick,innerQuick string,protector SocketProtector)string{
    if p==nil{return "awg_nested_stopped"}
    p.mu.Lock()
    if p.running || p.closed{p.mu.Unlock();return "awg_nested_stopped"}
    ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second)
    p.cancel=cancel;p.running=true;p.outer=Result{};p.inner=Result{};p.outerMeta=Result{};p.innerMeta=Result{};p.ip=""
    p.mu.Unlock()
    defer func(){cancel();p.mu.Lock();p.cancel=nil;p.running=false;p.mu.Unlock()}()
    outerCfg,err:=FromQuickConfig(outerQuick);if err!=nil{return "awg_nested_invalid"}
    innerCfg,err:=FromQuickConfig(innerQuick);if err!=nil{return "awg_nested_invalid"}
    if ipcField(outerCfg.IPCSettings,"private_key")==ipcField(innerCfg.IPCSettings,"private_key"){
        return "awg_nested_same_key"
    }
    if protector==nil{return "awg_nested_protect_failed"}
    // Both endpoint hostnames are resolved before either tunnel is started.
    dnsCtx,dnsCancel:=context.WithTimeout(ctx,5*time.Second)
    outerIPC,err:=normalizeIPCEndpoint(dnsCtx,outerCfg.IPCSettings,resolvePhysicalIP)
    if err!=nil{dnsCancel();return "awg_nested_invalid"}
    innerIPC,err:=normalizeIPCEndpoint(dnsCtx,innerCfg.IPCSettings,resolvePhysicalIP)
    dnsCancel();if err!=nil{return "awg_nested_invalid"}
    local,err:=netip.ParseAddr(outerCfg.LocalIPv4);if err!=nil{return "awg_nested_invalid"}
    outerTun,outerStack,err:=netstack.CreateNetTUN([]netip.Addr{local},[]netip.Addr{netip.MustParseAddr("1.1.1.1")},1280)
    if err!=nil{return "awg_nested_outer_failed"}
    outerDev:=device.NewDevice(outerTun,newProtectedBind(protector),device.NewLogger(device.LogLevelSilent,""))
    defer outerDev.Close()
    if outerDev.IpcSet(outerIPC)!=nil || outerDev.Up()!=nil{return "awg_nested_outer_failed"}
    checkCtx,checkCancel:=context.WithTimeout(ctx,10*time.Second)
    baseline,err:=probeHTTPS(checkCtx,outerDev,func(c context.Context)(net.Conn,error){
        return outerStack.DialContext(c,"tcp","1.1.1.1:443")
    })
    checkCancel()
    if ctx.Err()!=nil{return "awg_nested_stopped"}
    if err!=nil || !baseline.Verified{return "awg_nested_outer_failed"}
    p.mu.Lock();p.outer=baseline;p.mu.Unlock()
    // The caller chooses a European node; fail closed rather than testing an
    // arbitrary outer path and implying that it changes the exit country.
    if !nestedEuropeanColo(baseline.Colo){return "awg_nested_outer_node"}
    outerMeta:=nestedMeta(ctx,outerStack)
    p.mu.Lock();p.outerMeta=outerMeta;p.mu.Unlock()
    endpoints:=[]string{ipcField(innerIPC,"endpoint"),"162.159.192.1:2408",
        "162.159.195.1:2408","188.114.97.1:2408"}
    seen:=map[string]bool{}
    verifiedRussia:=false
    verifiedUnknown:=false
    for _,endpoint:=range endpoints{
        if ctx.Err()!=nil{return "awg_nested_stopped"}
        if seen[endpoint]{continue};seen[endpoint]=true
        candidate,err:=nestedEndpoint(innerIPC,endpoint);if err!=nil{continue}
        result,meta,err:=probeNestedInner(ctx,innerCfg,candidate,outerStack,local)
        if ctx.Err()!=nil{return "awg_nested_stopped"}
        if err!=nil || !result.Verified{continue}
        if nestedCountryDisagrees(result,meta){
            p.mu.Lock();p.inner=result;p.innerMeta=meta;p.ip=result.ExitIP;p.mu.Unlock()
            return "awg_nested_geo_disagree"
        }
        if result.Country!="" && result.Country!="RU"{
            p.mu.Lock();p.inner=result;p.innerMeta=meta;p.ip=result.ExitIP;p.mu.Unlock()
            return "awg_nested_verified"
        }
        if result.Country=="RU" || !verifiedRussia{
            p.mu.Lock();p.inner=result;p.innerMeta=meta;p.ip=result.ExitIP;p.mu.Unlock()
        }
        if result.Country=="RU"{verifiedRussia=true}else{verifiedUnknown=true}
    }
    if verifiedRussia{return "awg_nested_region_ru"}
    if verifiedUnknown{return "awg_nested_region_unknown"}
    return "awg_nested_inner_failed"
}

func nestedEuropeanColo(raw string)bool{
    return strings.Contains("|AMS|ARN|ATH|BUD|FRA|HEL|KBP|KIV|PRG|RIX|SOF|TLL|VIE|VNO|WAW|ZRH|CDG|LHR|DUB|CPH|OSL|MAD|BCN|LIS|MXP|FCO|GVA|MRS|MAN|ZAG|BEG|","|"+traceColoCode(raw)+"|") && traceColoCode(raw)!=""
}

func probeNestedInner(parent context.Context,cfg Config,uapi string,outer *netstack.Net,local netip.Addr)(Result,Result,error){
    ctx,cancel:=context.WithTimeout(parent,10*time.Second);defer cancel()
    address,err:=netip.ParseAddr(cfg.LocalIPv4);if err!=nil{return Result{},Result{},ErrInvalidConfig}
    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{address},[]netip.Addr{netip.MustParseAddr("1.1.1.1")},nestedMTU)
    if err!=nil{return Result{},Result{},ErrTunCreate}
    dev:=device.NewDevice(tun,&nestedBind{stack:outer,local:local},device.NewLogger(device.LogLevelSilent,""))
    defer dev.Close() // Inner closes before the outer device; no shared Android TUN.
    if dev.IpcSet(uapi)!=nil{return Result{},Result{},ErrIPCConfig}
    if dev.Up()!=nil{return Result{},Result{},ErrDeviceStart}
    result,err:=probeHTTPS(ctx,dev,func(c context.Context)(net.Conn,error){
        return stack.DialContext(c,"tcp","1.1.1.1:443")
    })
    if err!=nil{return result,Result{},err}
    return result,nestedMeta(ctx,stack),nil
}

// conn.Bind backed only by a UDP socket in the outer tunnel's private stack.
type nestedBind struct {
    mu sync.Mutex
    stack *netstack.Net
    local netip.Addr
    socket net.PacketConn
}

func (b *nestedBind) Open(uint16)([]conn.ReceiveFunc,uint16,error){
    b.mu.Lock();defer b.mu.Unlock()
    if b.socket!=nil{return nil,0,conn.ErrBindAlreadyOpen}
    if b.stack==nil || !b.local.Is4(){return nil,0,ErrVPNInit}
    udp,err:=b.stack.ListenUDPAddrPort(netip.AddrPortFrom(b.local,0))
    if err!=nil{return nil,0,err}
    b.socket=udp
    recv:=func(bufs [][]byte,sizes []int,eps []conn.Endpoint)(int,error){
        if len(bufs)==0 || len(sizes)==0 || len(eps)==0{return 0,ErrVPNInit}
        n,addr,err:=udp.ReadFrom(bufs[0]);if err!=nil{return 0,err}
        source,ok:=addr.(*net.UDPAddr);if !ok{return 0,ErrVPNInit}
        sizes[0]=n;eps[0]=&conn.StdNetEndpoint{AddrPort:source.AddrPort()};return 1,nil
    }
    return []conn.ReceiveFunc{recv},uint16(udp.LocalAddr().(*net.UDPAddr).Port),nil
}
func (b *nestedBind) Close()error{
    b.mu.Lock();s:=b.socket;b.socket=nil;b.mu.Unlock()
    if s!=nil{return s.Close()};return nil
}
func (*nestedBind) BatchSize()int{return 1}
func (*nestedBind) SetMark(mark uint32)error{if mark!=0{return ErrVPNInit};return nil}
func (*nestedBind) ParseEndpoint(raw string)(conn.Endpoint,error){
    addr,err:=netip.ParseAddrPort(raw)
    if err!=nil || !usablePeerAddress(addr.Addr()) || addr.Port()==0{return nil,ErrEndpointDNS}
    return &conn.StdNetEndpoint{AddrPort:addr},nil
}
func (b *nestedBind) Send(bufs [][]byte,ep conn.Endpoint)error{
    b.mu.Lock();s:=b.socket;b.mu.Unlock();if s==nil{return net.ErrClosed}
    addr,err:=netip.ParseAddrPort(ep.DstToString());if err!=nil || !usablePeerAddress(addr.Addr()){return ErrEndpointDNS}
    for _,pkt:=range bufs{if _,err=s.WriteTo(pkt,net.UDPAddrFromAddrPort(addr));err!=nil{return err}}
    return nil
}
