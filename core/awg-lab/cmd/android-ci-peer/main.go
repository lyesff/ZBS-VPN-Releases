// SPDX-License-Identifier: GPL-3.0-or-later
// android-ci-peer is an isolated CI fixture, NOT a WARP server or product mode.
// The workflow maps 1.1.1.2 to its runner's loopback before launching this peer.
// Synthetic AWG terminates locally; encrypted TLS bytes are relayed unchanged
// to real 1.1.1.1:443. No WARP registration or user credentials are involved.
package main

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/netip"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    "golang.org/x/crypto/curve25519"
)

func keyPair()([]byte,[]byte){
    private:=make([]byte,32)
    if _,err:=rand.Read(private);err!=nil{log.Fatal("cannot create synthetic key")}
    public,err:=curve25519.X25519(private,curve25519.Basepoint)
    if err!=nil{log.Fatal("cannot derive synthetic key")}
    return private,public
}
func main(){
    fixture:=flag.String("fixture","","private test-APK asset path")
    flag.Parse()
    if *fixture==""{log.Fatal("fixture path required")}
    ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
    defer cancel()
    serverPrivate,serverPublic:=keyPair()
    clientPrivate,clientPublic:=keyPair()
    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("1.1.1.1")},nil,1280)
    if err!=nil{log.Fatal("mock netstack creation failed")}
    peer:=device.NewDevice(tun,conn.NewStdNetBind(),device.NewLogger(device.LogLevelSilent,""))
    defer peer.Close()
    config:="private_key="+hex.EncodeToString(serverPrivate)+"\nlisten_port=41820\n"+
        "s1=0\ns2=0\ns3=0\ns4=0\njc=4\njmin=40\njmax=70\nh1=1\nh2=2\nh3=3\nh4=4\n"+
        "random_trailers=true\ndisable_cookies=true\nreplace_peers=true\npublic_key="+
        hex.EncodeToString(clientPublic)+"\nreplace_allowed_ips=true\nallowed_ip=172.16.0.2/32\n"
    if peer.IpcSet(config)!=nil || peer.Up()!=nil{log.Fatal("mock AWG peer startup failed")}
    listener,err:=stack.ListenTCPAddrPort(netip.MustParseAddrPort("1.1.1.1:443"))
    if err!=nil{log.Fatal("mock TCP listener startup failed")}
    defer listener.Close()
    quick:=fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 172.16.0.2/32\nMTU = 1280\n"+
        "S1 = 0\nS2 = 0\nS3 = 0\nS4 = 0\nJc = 4\nJmin = 40\nJmax = 70\n"+
        "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nRandomTrailers = on\nDisableCookies = on\n"+
        "[Peer]\nPublicKey = %s\nEndpoint = 1.1.1.2:41820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
        base64.StdEncoding.EncodeToString(clientPrivate),base64.StdEncoding.EncodeToString(serverPublic))
    dir:=filepath.Dir(*fixture)
    if os.MkdirAll(dir,0755)!=nil{log.Fatal("fixture directory unavailable")}
    temporary,err:=os.CreateTemp(dir,".awg-ci-*")
    if err!=nil{log.Fatal("fixture creation failed")}
    tempName:=temporary.Name()
    defer os.Remove(tempName)
    if temporary.Chmod(0600)!=nil{log.Fatal("fixture permissions failed")}
    if _,err=temporary.WriteString(quick);err!=nil{log.Fatal("fixture write failed")}
    if temporary.Close()!=nil || os.Rename(tempName,*fixture)!=nil{log.Fatal("fixture publication failed")}
    log.Print("AWG Android CI peer ready: synthetic keys, transparent TCP relay; not WARP")
    go func(){<-ctx.Done();_=listener.Close();peer.Close()}()
    for {
        incoming,err:=listener.Accept()
        if err!=nil{
            if ctx.Err()!=nil{return}
            log.Fatal("mock TCP accept failed")
        }
        go relay(incoming)
    }
}
func relay(incoming net.Conn){
    defer incoming.Close()
    upstream,err:=net.DialTimeout("tcp4","1.1.1.1:443",8*time.Second)
    if err!=nil{log.Print("public HTTPS upstream unavailable");return}
    defer upstream.Close()
    _=incoming.SetDeadline(time.Now().Add(30*time.Second))
    _=upstream.SetDeadline(time.Now().Add(30*time.Second))
    done:=make(chan struct{},2)
    go func(){_,_=io.Copy(upstream,incoming);done<-struct{}{}}()
    go func(){_,_=io.Copy(incoming,upstream);done<-struct{}{}}()
    <-done
}
