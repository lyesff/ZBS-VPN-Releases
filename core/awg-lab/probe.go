// SPDX-License-Identifier: GPL-3.0-or-later
// Package awglab is an isolated userspace AmneziaWG transport prototype.
// It does not establish Android VpnService or interact with the device's TUN.
package awglab

import (
    "context"
    "crypto/tls"
    "errors"
    "io"
    "net"
    "net/http"
    "net/http/httptrace"
    "sync/atomic"
    "net/netip"
    "strconv"
    "strings"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

var ErrInvalidConfig=errors.New("awg_invalid_config")
var ErrTunCreate=errors.New("awg_tun_create_failed")
var ErrIPCConfig=errors.New("awg_ipc_config_failed")
var ErrEndpointDNS=errors.New("awg_endpoint_dns_failed")
var ErrDeviceStart=errors.New("awg_device_start_failed")
var ErrNoHandshake=errors.New("awg_no_handshake")
var ErrHTTPSDeadline=errors.New("awg_https_timeout")
var ErrTCPTimeout=errors.New("awg_tcp_timeout")
var ErrTLSTimeout=errors.New("awg_tls_timeout")
var ErrHTTPTimeout=errors.New("awg_http_timeout")
var ErrHTTPFailed=errors.New("awg_https_failed")
var ErrNotWarp=errors.New("awg_not_confirmed")

// Config carries only locally trusted, provisioned WARP credentials.
// IPCSettings contains private keys and must never be logged or exported.
type Config struct {
    LocalIPv4 string
    IPCSettings string
    Timeout time.Duration
}

type Result struct {
    Latency time.Duration
    Verified bool
    Country string // HTTPS trace GeoIP only; not a physical egress location
    Colo string // Cloudflare node serving this HTTPS request, distinct from loc
    ExitIP string // Numeric public-facing IP from the verified HTTPS trace
}

// Probe uses an in-memory IP stack and the actual AmneziaWG userspace
// implementation. This is distinct from a TCP/UDP port-open check.
// A standalone probe must be cancelled when the Android VPN is active
// unless all AWG UDP sockets have been protected from VPN routing loops.
func Probe(parent context.Context, cfg Config) (Result,error) {
    return probeWithBind(parent,cfg,conn.NewStdNetBind())
}

// The Android preflight substitutes ONLY the UDP bind; TCP/TLS, MTU,
// endpoint, credentials and verification remain identical to Probe.
func probeWithBind(parent context.Context,cfg Config,bind conn.Bind)(Result,error){
    if len(cfg.IPCSettings)<32 || len(cfg.IPCSettings)>32768 ||
        !strings.Contains(cfg.IPCSettings,"private_key=") ||
        !strings.Contains(cfg.IPCSettings,"public_key=") ||
        !strings.Contains(cfg.IPCSettings,"endpoint=") {
        return Result{},ErrInvalidConfig
    }
    local,err:=netip.ParseAddr(cfg.LocalIPv4)
    if err!=nil || !local.Is4() || local.IsGlobalUnicast()==false {
        return Result{},ErrInvalidConfig
    }
    duration:=cfg.Timeout
    if duration<=0 || duration>15*time.Second {duration=10*time.Second}
    ctx,cancel:=context.WithTimeout(parent,duration)
    defer cancel()

    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{local},
        []netip.Addr{netip.MustParseAddr("1.1.1.1")},1280)
    if err!=nil{return Result{},ErrTunCreate}
    // NewDevice owns the TUN; closing the device closes the IP stack.
    dev:=device.NewDevice(tun,bind,
        device.NewLogger(device.LogLevelSilent,""))
    defer dev.Close()
    // StdNetBind.ParseEndpoint requires an IP:port, not a hostname:port.
    // Do the DNS lookup before IpcSet, on the physical network only.
    uapi,err:=normalizeIPCEndpoint(ctx,cfg.IPCSettings,resolvePhysicalIP)
    if err!=nil{return Result{},ErrEndpointDNS}
    if dev.IpcSet(uapi)!=nil{return Result{},ErrIPCConfig}
    if dev.Up()!=nil{return Result{},ErrDeviceStart}

    return probeHTTPS(ctx,dev,func(ctx context.Context)(net.Conn,error){
        return stack.DialContext(ctx,"tcp","1.1.1.1:443")
    })
}

// HTTPS over an existing device/stack; this helper never owns or closes dev.
func probeHTTPS(ctx context.Context,dev *device.Device,
    dial func(context.Context)(net.Conn,error))(Result,error){
    transport:=&http.Transport{
        DisableKeepAlives:true,
        TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
        DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){
            return dial(ctx)
        },
    }
    defer transport.CloseIdleConnections()
    client:=&http.Client{Transport:transport,
        CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
    req,err:=http.NewRequestWithContext(ctx,http.MethodGet,
        "https://one.one.one.one/cdn-cgi/trace",nil)
    if err!=nil{return Result{},ErrHTTPFailed}
    // Track the last completed phase without recording URLs, credentials,
    // peer addresses or handshake material.
    var phase atomic.Int32
    req=req.WithContext(httptrace.WithClientTrace(req.Context(),&httptrace.ClientTrace{
        ConnectStart:func(_, _ string){phase.Store(1)},
        ConnectDone:func(_, _ string,err error){if err==nil{phase.Store(2)}},
        TLSHandshakeStart:func(){phase.Store(3)},
        TLSHandshakeDone:func(_ tls.ConnectionState,err error){if err==nil{phase.Store(4)}},
        GotFirstResponseByte:func(){phase.Store(5)},
    }))
    began:=time.Now()
    response,err:=client.Do(req)
    if err!=nil{
        // IpcGet reports *status* and also includes secrets. Parse only the
        // handshake timestamp in memory and never return/log its full body.
        if !handshakeSeen(dev){return Result{},ErrNoHandshake}
        if errors.Is(err,context.DeadlineExceeded) || ctx.Err()==context.DeadlineExceeded {
            return Result{},classifyAWGTimeout(phase.Load())
        }
        return Result{},ErrHTTPFailed
    }
    defer response.Body.Close()
    if response.StatusCode!=http.StatusOK{return Result{},ErrHTTPFailed}
    b,err:=io.ReadAll(io.LimitReader(response.Body,8193))
    if err!=nil || len(b)>8192{return Result{},ErrHTTPFailed}
    foundIP,foundWARP:=false,false
    exitIP:=""
    country:=""
    countryFields:=0
    colo:=""
    coloFields:=0
    for _,line:=range strings.Split(string(b),"\n"){
        key,value,ok:=strings.Cut(strings.TrimSpace(line),"=")
        if !ok {continue}
        if key=="ip" && net.ParseIP(value)!=nil {foundIP=true;exitIP=net.ParseIP(value).String()}
        if key=="warp" && (value=="on" || value=="plus") {foundWARP=true}
        if key=="loc"{countryFields++;country=traceCountryCode(value)}
        if key=="colo"{coloFields++;colo=traceColoCode(value)}
    }
    if countryFields!=1{country=""}
    if coloFields!=1{colo=""}
    if !foundIP {return Result{},ErrHTTPFailed}
    if !foundWARP{return Result{},ErrNotWarp}
    return Result{Latency:time.Since(began),Verified:true,Country:country,Colo:colo,ExitIP:exitIP},nil
}

    
// handshakeSeen inspects the real AWG device UAPI snapshot. It never logs
// or returns UAPI text, as that can contain private credentials.
func handshakeSeen(dev *device.Device) bool {
    data,err:=dev.IpcGet()
    if err!=nil{return false}
    return parseAWGHandshake(data)
}

func parseAWGHandshake(snapshot string) bool {
    for _,line:=range strings.Split(snapshot,"\n") {
        k,v,ok:=strings.Cut(line,"=")
        if !ok || k!="last_handshake_time_sec" {continue}
        seconds,err:=strconv.ParseInt(strings.TrimSpace(v),10,64)
        if err==nil && seconds>0 {return true}
    }
    return false
}

// resolvePhysicalIP resolves endpoint DNS outside the in-memory netstack.
// The Android caller already prohibits running the probe while any VPN is
// active. Never fall back to a private, local or loopback destination.
func resolvePhysicalIP(ctx context.Context,hostname string)(netip.Addr,error){
    addresses,err:=net.DefaultResolver.LookupNetIP(ctx,"ip4",hostname)
    if err!=nil{return netip.Addr{},ErrEndpointDNS}
    for _,addr:=range addresses {
        if usablePeerAddress(addr){return addr,nil}
    }
    return netip.Addr{},ErrEndpointDNS
}

func usablePeerAddress(addr netip.Addr)bool{
    return addr.IsValid() && addr.Is4() && addr.IsGlobalUnicast() &&
        !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()
}

// normalizeIPCEndpoint modifies only the endpoint UAPI field.
// Never return the original UAPI or the DNS exception; it contains secrets.
// The injected resolver makes this logic deterministic in unit tests.
func normalizeIPCEndpoint(ctx context.Context,raw string,
    lookup func(context.Context,string)(netip.Addr,error))(string,error){
    rows:=strings.Split(raw,"\n")
    found:=false
    for i,line:=range rows{
        if !strings.HasPrefix(line,"endpoint="){continue}
        if found{return "",ErrEndpointDNS}
        found=true
        host,port,err:=net.SplitHostPort(strings.TrimPrefix(line,"endpoint="))
        if err!=nil{return "",ErrEndpointDNS}
        if _,err:=strconv.ParseUint(port,10,16);err!=nil || port=="0"{return "",ErrEndpointDNS}
        addr,err:=netip.ParseAddr(host)
        if err!=nil{
            if len(host)==0 || len(host)>253 || strings.ContainsAny(host," /\\\t\r\n"){
                return "",ErrEndpointDNS
            }
            addr,err=lookup(ctx,host)
            if err!=nil{return "",ErrEndpointDNS}
        }
        if !usablePeerAddress(addr){return "",ErrEndpointDNS}
        rows[i]="endpoint="+net.JoinHostPort(addr.String(),port)
    }
    if !found{return "",ErrEndpointDNS}
    return strings.Join(rows,"\n"),nil
}

    
// HTTP trace phase codes are local implementation details, not network
// telemetry. 1: TCP started, 2: TCP connected, 3: TLS started,
// 4: TLS completed, 5: first HTTP byte received.
func classifyAWGTimeout(phase int32) error {
    switch {
    case phase<2:return ErrTCPTimeout
    case phase<4:return ErrTLSTimeout
    default:return ErrHTTPTimeout
    }
}

// Only a bounded country code crosses the mobile boundary, never trace text.
func traceCountryCode(raw string)string{
    code:=strings.ToUpper(strings.TrimSpace(raw))
    if len(code)!=2 || code[0]<'A' || code[0]>'Z' || code[1]<'A' || code[1]>'Z' || code=="XX" || code=="ZZ"{return ""}
    return code
}

func traceColoCode(raw string)string{
    code:=strings.ToUpper(strings.TrimSpace(raw))
    if len(code)!=3{return ""}
    for _,c:=range code{if c<'A' || c>'Z'{return ""}}
    return code
}
