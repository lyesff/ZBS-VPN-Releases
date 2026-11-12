//go:build linux

package awglab

import (
    "encoding/base64"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "golang.org/x/sys/unix"
)

func udpSocketIdentity(t *testing.T,socket *net.UDPConn)(uint64,uint16){
    t.Helper()
    raw,err:=socket.SyscallConn()
    if err!=nil{t.Fatal("cannot inspect fixture UDP")}
    var stat unix.Stat_t
    var statErr error
    if raw.Control(func(fd uintptr){statErr=unix.Fstat(int(fd),&stat)})!=nil || statErr!=nil{
        t.Fatal("cannot stat fixture UDP")
    }
    return stat.Ino,uint16(socket.LocalAddr().(*net.UDPAddr).Port)
}

func TestRetainedUDPLeasesPreserveSocketAndPort(t *testing.T){
    protector:=&testProtector{allowed:true}
    original,err:=openProtectedUDP(protector,0)
    if err!=nil{t.Fatal("cannot open protected fixture UDP")}
    owner:=&retainedUDP{socket:original}
    defer owner.close()
    inode,port:=udpSocketIdentity(t,original)
    remote,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
    if err!=nil{t.Fatal("cannot open UDP fixture peer")}
    defer remote.Close()
    endpoint:=&conn.StdNetEndpoint{AddrPort:netip.AddrPortFrom(
        netip.MustParseAddr("127.0.0.1"),uint16(remote.LocalAddr().(*net.UDPAddr).Port))}

    for attempt:=0;attempt<2;attempt++{
        bind:=newRetainedBind(owner)
        requested:=uint16(0)
        if attempt>0{requested=port} // also exercise AWG BindUpdate reopen
        receivers,actual,err:=bind.Open(requested)
        if err!=nil{t.Fatal("retained lease did not open")}
        copiedInode,copiedPort:=udpSocketIdentity(t,bind.socket)
        if inode!=copiedInode || port!=copiedPort || actual!=port{
            _=bind.Close()
            t.Fatal("lease changed the kernel socket or UDP port")
        }
        payload:=[]byte(fmt.Sprintf("synthetic-lease-%d",attempt))
        if bind.Send([][]byte{payload},endpoint)!=nil{t.Fatal("fixture UDP send failed")}
        _=remote.SetReadDeadline(time.Now().Add(time.Second))
        buffer:=make([]byte,128)
        n,address,e:=remote.ReadFromUDPAddrPort(buffer)
        if e!=nil || address.Port()!=port || string(buffer[:n])!=string(payload){
            t.Fatal("peer did not receive the retained source port")
        }
        if _,e=remote.WriteToUDPAddrPort(payload,address);e!=nil{t.Fatal("fixture reply failed")}
        _=bind.socket.SetReadDeadline(time.Now().Add(time.Second))
        sizes:=make([]int,1);endpoints:=make([]conn.Endpoint,1)
        n,e=receivers[0]([][]byte{buffer},sizes,endpoints)
        if e!=nil || n!=1 || string(buffer[:sizes[0]])!=string(payload){
            t.Fatal("retained lease did not receive fixture reply")
        }
        if bind.Close()!=nil || bind.Close()!=nil{t.Fatal("lease close is not idempotent")}
    }
    if protector.calls!=1{t.Fatal("duplicate descriptors re-ran protection")}
    owner.close()
    if _,_,err:=newRetainedBind(owner).Open(0);!errors.Is(err,net.ErrClosed){
        t.Fatal("closed owner silently opened a replacement socket")
    }
}

func TestRetainedUDPCloseUnblocksLeaseReaderWithoutLosingOriginal(t *testing.T){
    original,err:=openProtectedUDP(&testProtector{allowed:true},0)
    if err!=nil{t.Fatal("fixture UDP failed")}
    owner:=&retainedUDP{socket:original}
    defer owner.close()
    bind:=newRetainedBind(owner)
    receivers,_,err:=bind.Open(0)
    if err!=nil{t.Fatal("fixture lease failed")}
    done:=make(chan error,1)
    go func(){
        _,err:=receivers[0]([][]byte{make([]byte,128)},make([]int,1),make([]conn.Endpoint,1))
        done<-err
    }()
    _=bind.Close()
    select {
    case err:=<-done:
        if err==nil{t.Fatal("closed lease read unexpectedly succeeded")}
    case <-time.After(time.Second):
        t.Fatal("closing the lease did not unblock its AWG reader")
    }
    lease,err:=owner.lease(0)
    if err!=nil{t.Fatal("closing a device destroyed preparation's UDP socket")}
    _=lease.Close()
}

func preparedFixtureQuick()string{
    key:=base64.StdEncoding.EncodeToString(make([]byte,32))
    return "[Interface]\nPrivateKey = "+key+"\nAddress = 172.16.0.2/32\n"+
        "[Peer]\nPublicKey = "+key+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:41820\n"
}

func TestPreparationFailsClosedAndCancelsOnce(t *testing.T){
    denied:=&testProtector{}
    if p,err:=PrepareAndroidVPN(preparedFixtureQuick(),denied);p!=nil || !errors.Is(err,ErrVPNProtect){
        t.Fatal("preparation accepted denied socket protection")
    }
    socket,err:=openProtectedUDP(&testProtector{allowed:true},0)
    if err!=nil{t.Fatal("fixture socket failed")}
    owner:=&retainedUDP{socket:socket}
    p:=&AndroidVPNPreparation{engine:&AndroidVPN{transport:owner}}
    cancellations:=0
    p.cancel=func(){cancellations++}
    p.Close();p.Close()
    if cancellations!=1 || p.engine!=nil || p.stack!=nil || p.handoff!=nil{
        t.Fatal("preparation cancellation/credential release is not idempotent")
    }
    if _,err:=owner.lease(0);!errors.Is(err,net.ErrClosed){t.Fatal("preparation leaked its original socket")}
}

func TestPreparationRejectsOverlapAndAlwaysConsumesTUNFD(t *testing.T){
    engineBefore:=&AndroidVPN{}
    p:=&AndroidVPNPreparation{engine:engineBefore,handoff:&handoffTun{},probing:true}
    defer p.Close()
    fd,err:=unix.Open("/dev/null",unix.O_RDWR|unix.O_CLOEXEC,0)
    if err!=nil{t.Fatal("cannot open descriptor fixture")}
    if engine,err:=p.Start(fd);engine!=nil || err==nil{
        t.Fatal("system engine started while the preflight was still active")
    }
    if p.closed || p.engine!=engineBefore{t.Fatal("rejected overlap consumed the active engine")}
    if _,err:=unix.FcntlInt(uintptr(fd),unix.F_GETFD,0);!errors.Is(err,unix.EBADF){
        t.Fatal("rejected start did not consume its TUN descriptor")
    }
}

func TestPreparationWithoutHTTPSCannotAttachAndConsumesFD(t *testing.T){
    engine:=&AndroidVPN{}
    p:=&AndroidVPNPreparation{engine:engine,handoff:&handoffTun{},probed:true}
    defer p.Close()
    fd,err:=unix.Open("/dev/null",unix.O_RDWR|unix.O_CLOEXEC,0)
    if err!=nil{t.Fatal("cannot open descriptor fixture")}
    if started,err:=p.Start(fd);started!=nil || err==nil{
        t.Fatal("preparation without a successful HTTPS baseline attached a TUN")
    }
    if p.engine!=engine || p.closed{
        t.Fatal("rejected attachment lost preparation ownership")
    }
    if _,err:=unix.FcntlInt(uintptr(fd),unix.F_GETFD,0);!errors.Is(err,unix.EBADF){
        t.Fatal("rejected baseline did not consume transferred TUN fd")
    }
    if outcome,_:=p.ProbeWarpAfterTUN();outcome!="awg_device_start_failed"{
        t.Fatal("failed baseline allowed a misleading post-TUN comparison")
    }
}
