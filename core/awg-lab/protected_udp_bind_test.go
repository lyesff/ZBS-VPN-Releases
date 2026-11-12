package awglab

import (
    "bytes"
    "net"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "golang.org/x/sys/unix"
)

type preBindProtector struct{called bool; unbound bool}
func (p *preBindProtector) Protect(fd int)bool {
    p.called=true
    address,err:=unix.Getsockname(fd)
    if err!=nil{return false}
    local,ok:=address.(*unix.SockaddrInet4)
    p.unbound=ok && local.Port==0
    return p.unbound
}
func TestUDPProtectionRunsBeforeBind(t *testing.T){
    p:=&preBindProtector{}
    b:=newProtectedBind(p)
    if _,_,err:=b.Open(0);err!=nil{t.Fatal(err)}
    defer b.Close()
    if !p.called || !p.unbound{t.Fatal("socket was bound before protection")}
}
func TestProtectedUDPBidirectionalDatagrams(t *testing.T){
    remote,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
    if err!=nil{t.Fatal(err)}
    defer remote.Close()
    remote.SetReadDeadline(time.Now().Add(3*time.Second))
    b:=newProtectedBind(&testProtector{allowed:true})
    fns,_,err:=b.Open(0)
    if err!=nil{t.Fatal(err)}
    defer b.Close()
    ep:=&conn.StdNetEndpoint{AddrPort:remote.LocalAddr().(*net.UDPAddr).AddrPort()}
    for _,size:=range []int{60,1280,2000}{
        want:=bytes.Repeat([]byte{byte(size%251)},size)
        if err=b.Send([][]byte{want},ep);err!=nil{t.Fatal(err)}
        buf:=make([]byte,3000)
        n,addr,err:=remote.ReadFromUDP(buf)
        if err!=nil || !bytes.Equal(want,buf[:n]){t.Fatal("outgoing datagram changed")}
        if _,err=remote.WriteToUDP(want,addr);err!=nil{t.Fatal(err)}
        // Deadline exists only in this test; production transport is unchanged.
        b.socket.SetReadDeadline(time.Now().Add(3*time.Second))
        sizes:=make([]int,1);eps:=make([]conn.Endpoint,1)
        count,err:=fns[0]([][]byte{buf},sizes,eps)
        if err!=nil || count!=1 || !bytes.Equal(want,buf[:sizes[0]]){
            t.Fatal("incoming datagram changed")
        }
    }
}
