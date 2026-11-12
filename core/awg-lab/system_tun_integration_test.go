//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/hex"
    "encoding/pem"
    "fmt"
    "io"
    "math/big"
    "net"
    "net/http"
    "net/netip"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/sys/unix"
)

// Run ONLY in a fresh network namespace in CI. The mock peer owns 1.1.1.1
// inside its userspace stack; no packet is sent to real Cloudflare. All keys
// are generated for this test and discarded. A passing test proves the local
// kernel/TUN/adapter path, not Android routing or real WARP interoperability.
func TestSystemTUNIntegration(t *testing.T){
    if os.Getenv("AUTOWARP_SYSTEM_TUN_TEST")!="1" {
        t.Skip("requires an isolated root network namespace; see awg-lab workflow")
    }
    if os.Geteuid()!=0{t.Fatal("system TUN test requires root inside its network namespace")}
    // Prevent accidental modification of a live runner's networking.
    interfaces,err:=net.Interfaces()
    if err!=nil{t.Fatal("cannot inspect isolated network namespace")}
    for _,iface:=range interfaces{
        if iface.Name!="lo"{t.Fatal("refusing to configure a non-isolated network namespace")}
    }
    ipCommand(t,"link","set","lo","up")
    ipCommand(t,"addr","add","203.0.113.1/32","dev","lo")

    serverPrivate,serverPublic:=integrationKeyPair(t)
    clientPrivate,clientPublic:=integrationKeyPair(t)
    certificate,roots,caPEM:=integrationTLSCertificate(t)
    caFile:=filepath.Join(t.TempDir(),"test-ca.pem")
    if os.WriteFile(caFile,caPEM,0600)!=nil{t.Fatal("cannot write mock TLS root")}
    // Probe uses normal certificate verification. This test process has its
    // own root store; production TLS settings are never weakened.
    t.Setenv("SSL_CERT_FILE",caFile)

    serverTun,serverStack,err:=netstack.CreateNetTUN(
        []netip.Addr{netip.MustParseAddr("1.1.1.1")},nil,1280)
    if err!=nil{t.Fatal("cannot create mock peer netstack")}
    peer:=device.NewDevice(serverTun,conn.NewStdNetBind(),device.NewLogger(device.LogLevelSilent,""))
    defer peer.Close()
    serverUAPI:="private_key="+hex.EncodeToString(serverPrivate)+"\n"+
        "listen_port=41820\n"+integrationObfuscation()+
        "replace_peers=true\npublic_key="+hex.EncodeToString(clientPublic)+
        "\nreplace_allowed_ips=true\nallowed_ip=172.16.0.2/32\n"
    if peer.IpcSet(serverUAPI)!=nil || peer.Up()!=nil{t.Fatal("mock AWG peer failed to start")}
    listener,err:=serverStack.ListenTCPAddrPort(netip.MustParseAddrPort("1.1.1.1:443"))
    if err!=nil{t.Fatal("mock peer TCP listener failed")}
    https:=&http.Server{Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        defer r.Body.Close()
        if r.Method==http.MethodGet{
            _,_=io.WriteString(w,"ip=203.0.113.9\nwarp=on\nloc=DE\n")
            return
        }
        data,e:=io.ReadAll(io.LimitReader(r.Body,65537))
        if e!=nil || len(data)>65536{w.WriteHeader(http.StatusBadRequest);return}
        _,_=w.Write(data)
    })}
    tlsListener:=tls.NewListener(listener,&tls.Config{
        Certificates:[]tls.Certificate{certificate},MinVersion:tls.VersionTLS12,
    })
    serving:=make(chan struct{})
    go func(){defer close(serving);_=https.Serve(tlsListener)}()
    defer func(){_=https.Close();<-serving}()

    quick:=fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 172.16.0.2/32\nMTU = 1280\n"+
        "S1 = 0\nS2 = 0\nS3 = 0\nS4 = 0\nJc = 4\nJmin = 40\nJmax = 70\n"+
        "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nRandomTrailers = on\nDisableCookies = on\n"+
        "[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:41820\nPersistentKeepalive = 25\n",
        base64.StdEncoding.EncodeToString(clientPrivate),base64.StdEncoding.EncodeToString(serverPublic))
    cfg,err:=FromQuickConfig(quick)
    if err!=nil{t.Fatal("synthetic client config rejected")}
    cfg.Timeout=8*time.Second
    result,err:=Probe(context.Background(),cfg)
    if err!=nil || !result.Verified{t.Fatalf("mock netstack baseline failed: %v",err)}
    t.Log("mock netstack baseline: HTTPS succeeded (not a real WARP test)")
    protected,err:=ProbeProtectedWarp(quick,&testProtector{allowed:true})
    if err!=nil || !strings.HasPrefix(protected,"awg_verified:"){
        t.Fatalf("protected netstack preflight failed: %s",protected)
    }
    denied,err:=ProbeProtectedWarp(quick,&testProtector{allowed:false})
    if err!=nil || denied!="awg_device_start_failed"{
        t.Fatalf("protected preflight did not fail closed: %s",denied)
    }
    t.Log("protected netstack preflight succeeded; denied protection failed closed")
    // Shared APK asset is public camouflage bytes, never a client credential.
    signature,err:=os.ReadFile("../../app/src/main/assets/warp-router-i1.cps")
    if err!=nil{t.Fatal("cannot read public router I1 fixture")}
    maskedQuick:=strings.Replace(quick,"[Interface]\n","[Interface]\nI1 = "+strings.TrimSpace(string(signature))+"\n",1)
    masked,err:=ProbeProtectedWarp(maskedQuick,&testProtector{allowed:true})
    if err!=nil || !strings.HasPrefix(masked,"awg_verified:"){
        t.Fatalf("router I1 compatibility preflight failed: %s",masked)
    }
    t.Log("pinned AWG userspace accepted router I1 and completed mock HTTPS")



    keeperProtector:=&testProtector{allowed:true}
    prepared,err:=PrepareAndroidVPN(quick,keeperProtector)
    if err!=nil{t.Fatal("cannot prepare persistent protected UDP")}
    defer prepared.Close()
    engineBefore:=prepared.engine
    deviceBefore:=engineBefore.dev
    kept:=engineBefore.transport
    originalInode,originalPort:=udpSocketIdentity(t,kept.socket)
    preflight,err:=prepared.ProbeWarp()
    if err!=nil || !strings.HasPrefix(preflight,"awg_verified:"){
        t.Fatal("retained transport preflight did not complete HTTPS")
    }
    if prepared.CountryCode()!="DE"{t.Fatal("pre-TUN country was not preserved from the validated trace")}
    if engineBefore.PacketCounters()!="0,0,0,0"{
        t.Fatal("preflight packets leaked into system-phase aggregate counters")
    }

    fd:=integrationTUN(t)
    owned:=true
    defer func(){if owned{_=unix.Close(fd)}}()
    ipCommand(t,"addr","add","172.16.0.2/32","dev","awgsys0")
    ipCommand(t,"link","set","awgsys0","mtu","1280","up")
    ipCommand(t,"route","add","1.1.1.1/32","dev","awgsys0","src","172.16.0.2")
    // The namespace route excludes outer UDP from TUN. Android's protect/bind
    // APIs cannot be tested here; the callback is an explicit test double.
    post,err:=prepared.ProbeWarpAfterTUN()
    if err!=nil || !strings.HasPrefix(post,"awg_verified:"){
        t.Fatal("same netstack failed after kernel TUN routes were activated")
    }
    if prepared.CountryCode()!="DE"{t.Fatal("post-TUN country was not preserved from the validated trace")}
    if prepared.PostTUNUDPState()!="awg_post_udp_bidirectional" ||
        prepared.TransportState()!="awg_transport_unchanged"{
        t.Fatal("post-TUN netstack did not retain bidirectional UDP/transport")
    }
    if again,_:=prepared.ProbeWarpAfterTUN();again!="awg_device_start_failed"{
        t.Fatal("post-TUN probe allowed an unbounded repeat")
    }
    if engineBefore.PacketCounters()!="0,0,0,0"{
        t.Fatal("post-TUN netstack was counted as system-TUN evidence")
    }
    engine,err:=prepared.Start(fd)
    owned=false // Prepared Start consumes fd on both success and failure.
    if err!=nil{t.Fatalf("system adapter failed: %v",err)}
    defer engine.Stop()
    prepared.Close() // The SAME engine/session is now owned by Android resources.
    if engine!=engineBefore || engine.dev!=deviceBefore || !engine.HasHandshake(){
        t.Fatal("handoff restarted the AWG device or lost the verified handshake")
    }
    if engine.transport!=kept || kept.socket==nil{
        t.Fatal("preparation did not transfer transport ownership")
    }
    inode,port:=udpSocketIdentity(t,kept.socket)
    if inode!=originalInode || port!=originalPort ||
        engine.stats.udpLocalPort.Load()!=uint32(originalPort) || keeperProtector.calls!=1{
        t.Fatal("handoff recreated/reprotected the original UDP socket")
    }

    // Go TLS uses the kernel's TCP through this exact system TUN/AWG device.
    // Refusing the route callback must never fall back to a direct socket.
    deniedControl:=&integrationVPNDialer{engine:engine,allowed:false}
    if code:=engine.ProbeSystemTLS(deniedControl);code!="awg_control_bind_failed"{
        t.Fatalf("inner TCP did not fail closed on denied VPN binding: %s",code)
    }
    if deniedControl.closeCalls!=1{t.Fatal("denied control did not release its dialer")}
    connectedControl:=&integrationVPNDialer{engine:engine,allowed:true}
    if code:=engine.ProbeSystemTLS(connectedControl);code!="awg_control_verified"{
        t.Fatalf("Go TLS control did not traverse the existing kernel TUN: %s",code)
    }
    if connectedControl.closeCalls!=1 || connectedControl.connection!=nil{
        t.Fatal("Go TLS control retained its original socket after descriptor adoption")
    }
    t.Log("Go TLS control verified through the same system TUN and AWG session")

    for _,version:=range []uint16{tls.VersionTLS12,tls.VersionTLS13}{
        t.Run(tls.VersionName(version),func(t *testing.T){
            dialer:=&net.Dialer{Timeout:6500*time.Millisecond,Control:func(_, _ string,raw syscall.RawConn)error{
                var socketErr error
                err:=raw.Control(func(fd uintptr){
                    socketErr=unix.Bind(int(fd),&unix.SockaddrInet4{Addr:[4]byte{172,16,0,2}})
                    if socketErr!=nil{return}
                    address,e:=unix.Getsockname(int(fd))
                    if e!=nil{socketErr=e;return}
                    local,ok:=address.(*unix.SockaddrInet4)
                    if !ok{socketErr=ErrVPNInit;return}
                    engine.SetDiagnosticPort(local.Port)
                })
                if err!=nil{return err};return socketErr
            }}
            transport:=&http.Transport{
                DisableKeepAlives:true,TLSHandshakeTimeout:6500*time.Millisecond,
                TLSClientConfig:&tls.Config{RootCAs:roots,ServerName:"one.one.one.one",MinVersion:version,MaxVersion:version},
                DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return dialer.DialContext(ctx,"tcp4","1.1.1.1:443")},
            }
            defer transport.CloseIdleConnections()
            client:=&http.Client{Transport:transport,Timeout:12*time.Second}
            payload:=bytes.Repeat([]byte{0x53,0x19,0x7a,0x01},8192)
            response,err:=client.Post("https://one.one.one.one/echo","application/octet-stream",bytes.NewReader(payload))
            if err!=nil{
                t.Logf("aggregate=%s control=%s data=%s loops=%d",engine.PacketCounters(),engine.TCPFlowCounters(),engine.TCPDataCounters(),engine.UDPLoopCount())
                t.Fatalf("kernel TCP/TLS request failed: %v",err)
            }
            defer response.Body.Close()
            echoed,err:=io.ReadAll(io.LimitReader(response.Body,int64(len(payload)+1)))
            if err!=nil || response.StatusCode!=http.StatusOK || !bytes.Equal(payload,echoed){
                t.Fatal("multi-packet TLS payload was truncated or corrupted")
            }
            totals:=strings.Split(engine.TrafficBytes(),",")
            if len(totals)!=2{t.Fatal("missing inner-IP traffic totals")}
            for _,field:=range totals{
                total,e:=strconv.ParseInt(field,10,64)
                if e!=nil || total<int64(len(payload)){
                    t.Fatal("32 KiB transfer was not counted in both traffic directions")
                }
            }
            fields:=strings.Split(engine.TCPFlowCounters(),",")
            if len(fields)!=14{t.Fatal("missing correlated flow diagnostics")}
            for i:=0;i<4;i++{
                n,e:=strconv.ParseUint(fields[i],10,64)
                if e!=nil || n==0{t.Fatalf("missing system TCP handshake stage %d",i)}
            }
            if engine.UDPLoopCount()!=0{t.Fatal("outer UDP unexpectedly entered the system TUN")}
            t.Logf("kernel TCP/TLS payload OK: aggregate=%s control=%s data=%s",engine.PacketCounters(),engine.TCPFlowCounters(),engine.TCPDataCounters())
        })
    }
    engine.Stop()
    if _,err:=kept.lease(0);err==nil{
        t.Fatal("engine stop retained its original UDP socket")
    }
    if keeperProtector.calls!=1{t.Fatal("system traffic opened/reprotected another UDP socket")}
}

func ipCommand(t *testing.T,args ...string){
    t.Helper()
    if output,err:=exec.Command("ip",args...).CombinedOutput();err!=nil{
        t.Fatalf("isolated network setup failed: %s",strings.TrimSpace(string(output)))
    }
}
func integrationTUN(t *testing.T)int{
    t.Helper()
    fd,err:=unix.Open("/dev/net/tun",unix.O_RDWR|unix.O_CLOEXEC,0)
    if err!=nil{t.Fatal("cannot open namespace TUN")}
    ifr,err:=unix.NewIfreq("awgsys0")
    if err==nil{
        // Same raw IPv4 framing as VpnService; deliberately no VNET_HDR/GSO.
        ifr.SetUint16(unix.IFF_TUN|unix.IFF_NO_PI)
        err=unix.IoctlIfreq(fd,unix.TUNSETIFF,ifr)
    }
    if err!=nil{_=unix.Close(fd);t.Fatal("cannot create raw namespace TUN")}
    return fd
}
func integrationKeyPair(t *testing.T)([]byte,[]byte){
    t.Helper()
    private:=make([]byte,32)
    if _,err:=rand.Read(private);err!=nil{t.Fatal("cannot create synthetic AWG key")}
    public,err:=curve25519.X25519(private,curve25519.Basepoint)
    if err!=nil{t.Fatal("cannot derive synthetic AWG public key")}
    return private,public
}
func integrationObfuscation()string{
    return "s1=0\ns2=0\ns3=0\ns4=0\njc=4\njmin=40\njmax=70\nh1=1\nh2=2\nh3=3\nh4=4\nrandom_trailers=true\ndisable_cookies=true\n"
}
func integrationTLSCertificate(t *testing.T)(tls.Certificate,*x509.CertPool,[]byte){
    t.Helper()
    key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
    if err!=nil{t.Fatal("cannot create synthetic TLS key")}
    certificate:=&x509.Certificate{
        SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"AutoWARP isolated CI peer"},
        DNSNames:[]string{"one.one.one.one"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
        IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
        ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    der,err:=x509.CreateCertificate(rand.Reader,certificate,certificate,&key.PublicKey,key)
    if err!=nil{t.Fatal("cannot create synthetic TLS certificate")}
    caPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
    roots:=x509.NewCertPool()
    if !roots.AppendCertsFromPEM(caPEM){t.Fatal("cannot load synthetic TLS root")}
    return tls.Certificate{Certificate:[][]byte{der},PrivateKey:key},roots,caPEM
}

// Namespace routes substitute Android's VPN SocketFactory. Keep one original
// socket alive while the control owns the transferred descriptor copy.
type integrationVPNDialer struct {
    engine *AndroidVPN
    allowed bool
    connection *net.TCPConn
    closeCalls int
}
func (d *integrationVPNDialer) Open()int{
    if !d.allowed{return -2}
    dialer:=&net.Dialer{Timeout:6500*time.Millisecond,Control:func(_, _ string,raw syscall.RawConn)error{
        var socketErr error
        err:=raw.Control(func(fd uintptr){
            socketErr=unix.Bind(int(fd),&unix.SockaddrInet4{Addr:[4]byte{172,16,0,2}})
            if socketErr!=nil{return}
            address,e:=unix.Getsockname(int(fd))
            if e!=nil{socketErr=e;return}
            tcp,ok:=address.(*unix.SockaddrInet4)
            if !ok{socketErr=ErrVPNInit;return}
            d.engine.SetDiagnosticPort(tcp.Port)
        })
        if err!=nil{return err};return socketErr
    }}
    connection,err:=dialer.Dial("tcp4","1.1.1.1:443")
    if err!=nil{return -4}
    d.connection=connection.(*net.TCPConn)
    file,err:=d.connection.File()
    if err!=nil{return -4}
    defer file.Close()
    fd,err:=unix.Dup(int(file.Fd()))
    if err!=nil{return -4}
    return fd
}
func (d *integrationVPNDialer) Close(){
    d.closeCalls++
    if d.connection!=nil{_=d.connection.Close();d.connection=nil}
}
