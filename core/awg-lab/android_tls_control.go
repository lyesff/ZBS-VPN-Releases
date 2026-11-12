// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "context"
    "crypto/tls"
    "io"
    "net"
    "net/http"
    "net/http/httptrace"
    "strings"
    "sync/atomic"
    "os"
    "errors"
    "time"
)

// VPNNetworkDialer creates a connected INNER TCP socket using Android's
// existing VPN socket factory and registers its source port before connect.
// Open transfers ownership of one duplicated fd to Go. Close releases only
// the retained Java Socket; it must be idempotent, including after Open fails.
// Negative results: -1 stopped, -2 bind failed, -3 TCP timeout, -4 TCP failed.
type VPNNetworkDialer interface {
    Open() int
    Close()
}

// ProbeSystemTLS compares Go TLS with Android/OkHttp over the SAME kernel TCP,
// Android TUN and protected AWG session. The Android socket path is identical;
// no new AWG engine, UDP socket or routing table is created.
func (a *AndroidVPN) ProbeSystemTLS(dialer VPNNetworkDialer) string {
    if a==nil || dialer==nil || a.stats==nil || a.stats.trace==nil || !a.IsRunning(){
        return "awg_control_stopped"
    }
    defer dialer.Close()
    a.SetDiagnosticPort(0)
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()
    var openResult atomic.Int32
    var phase atomic.Int32
    transport:=&http.Transport{
        DisableKeepAlives:true,
        TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
        DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){
            if ctx.Err()!=nil{return nil,ctx.Err()}
            fd:=dialer.Open()
            if fd<0{
                openResult.Store(int32(fd))
                return nil,errors.New("awg_control_socket_unavailable")
            }
            // FileConn duplicates the descriptor for its own poller. Close
            // the transferred fd exactly once, even if adoption fails.
            file:=os.NewFile(uintptr(fd),"awg-inner-tcp")
            connection,err:=net.FileConn(file)
            _=file.Close()
            if err!=nil{return nil,err}
            if ctx.Err()!=nil{_=connection.Close();return nil,ctx.Err()}
            phase.Store(1) // Android already completed kernel TCP connect.
            return connection,nil
        },
    }
    defer transport.CloseIdleConnections()
    client:=&http.Client{Transport:transport,
        CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
    req,err:=http.NewRequestWithContext(ctx,http.MethodGet,
        "https://one.one.one.one/cdn-cgi/trace",nil)
    if err!=nil{return "awg_control_http_failed"}
    req=req.WithContext(httptrace.WithClientTrace(req.Context(),&httptrace.ClientTrace{
        ConnectDone:func(_, _ string,err error){if err==nil{phase.Store(1)}},
        TLSHandshakeStart:func(){phase.Store(1)},
        TLSHandshakeDone:func(_ tls.ConnectionState,err error){if err==nil{phase.Store(2)}},
    }))
    response,err:=client.Do(req)
    if err!=nil{
        switch openResult.Load(){
        case -1:return "awg_control_stopped"
        case -2:return "awg_control_bind_failed"
        case -3:return "awg_control_tcp_timeout"
        case -4:return "awg_control_tcp_failed"
        }
        suffix:="failed"
        if ctx.Err()==context.DeadlineExceeded{suffix="timeout"}
        if phase.Load()==0{return "awg_control_tcp_"+suffix}
        if phase.Load()==1{return "awg_control_tls_"+suffix}
        return "awg_control_http_"+suffix
    }
    defer response.Body.Close()
    if response.StatusCode!=http.StatusOK{return "awg_control_http_failed"}
    body,err:=io.ReadAll(io.LimitReader(response.Body,8193))
    if err!=nil {
        if ctx.Err()==context.DeadlineExceeded{return "awg_control_http_timeout"}
        return "awg_control_http_failed"
    }
    if len(body)>8192{return "awg_control_http_failed"}
    // Require the same selected socket's complete TCP exchange through TUN.
    // A physical-network response, even a valid HTTPS trace, must never pass.
    flow:=strings.Split(a.TCPFlowCounters(),",")
    if len(flow)!=14{return "awg_control_wrong_path"}
    missing:=[4]string{"awg_control_path_no_syn","awg_control_path_no_synack",
        "awg_control_path_no_write","awg_control_path_no_ack"}
    for i:=0;i<4;i++{if flow[i]=="0" || flow[i]==""{return missing[i]}}
    foundIP,warp:=false,false
    for _,line:=range strings.Split(string(body),"\n"){
        key,value,ok:=strings.Cut(strings.TrimSpace(line),"=")
        if !ok{continue}
        if key=="ip" && net.ParseIP(value)!=nil{foundIP=true}
        if key=="warp" && (value=="on" || value=="plus"){warp=true}
    }
    if !foundIP{return "awg_control_http_failed"}
    if !warp{return "awg_control_not_warp"}
    return "awg_control_verified"
}
