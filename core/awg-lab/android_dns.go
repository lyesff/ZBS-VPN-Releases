// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "encoding/binary"
    "io"
    "net"
    "net/netip"
    "strings"
    "sync"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    "golang.org/x/net/dns/dnsmessage"
)

// DNSExchanger sends an RFC 8484 wire message through Android's VPN Network.
// The implementation must be bounded, cancellable and must not use system DNS
// for its own upstream hostname (which would recurse into this listener).
type DNSExchanger interface { Exchange(query []byte) []byte }

// CheckDNS verifies wire format, matching question and a successful answer.
// It checks DNS health only, never claims a service or GeoIP is unblocked.
func CheckDNS(exchange DNSExchanger)bool{
    if exchange==nil{return false}
    q:=dnsmessage.Message{Header:dnsmessage.Header{ID:0x4157,RecursionDesired:true},
        Questions:[]dnsmessage.Question{{Name:dnsmessage.MustNewName("example.com."),Type:dnsmessage.TypeA,Class:dnsmessage.ClassINET}}}
    query,err:=q.Pack();if err!=nil{return false}
    answer:=dnsAnswer(query,exchange,false)
    var m dnsmessage.Message
    return m.Unpack(answer)==nil && m.RCode==dnsmessage.RCodeSuccess && !m.Truncated && len(m.Answers)>0
}

// Only this synthetic address is consumed locally. No host UDP/TCP DNS socket
// is opened and user questions never go to a physical-network resolver.
const androidDNSAddress="198.18.0.53"

type dnsTun struct {
    tun.Device
    local tun.Device
    udp net.PacketConn
    tcp net.Listener
    exchange DNSExchanger
    writeMu sync.Mutex
    mu sync.Mutex
    closed bool
    conns map[net.Conn]bool
    once sync.Once
    slots chan struct{}
    done chan struct{}
}

func newDNSTun(native tun.Device,exchange DNSExchanger)(*dnsTun,error){
    if native==nil || exchange==nil{return nil,ErrVPNInit}
    local,stack,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(androidDNSAddress)},nil,1280)
    if err!=nil{return nil,err}
    d:=&dnsTun{Device:native,local:local,exchange:exchange,slots:make(chan struct{},16),
        done:make(chan struct{}),conns:make(map[net.Conn]bool)}
    // Drain netstack output even during Close: its channel is unbuffered.
    go d.pumpReplies()
    addr:=netip.MustParseAddrPort(androidDNSAddress+":53")
    d.udp,err=stack.ListenUDPAddrPort(addr)
    if err==nil{d.tcp,err=stack.ListenTCPAddrPort(addr)}
    if err!=nil{
        if d.udp!=nil{_=d.udp.Close()}
        close(d.done);_=local.Close()
        return nil,err // caller still owns native
    }
    go d.serveUDP()
    go d.serveTCP()
    return d,nil
}

func localDNSPacket(packet []byte)bool{
    // Consume ALL IPv4 packets to the synthetic address, including fragments
    // and non-DNS ports. Never leak this address to Cloudflare.
    return len(packet)>=20 && packet[0]>>4==4 &&
        packet[16]==198 && packet[17]==18 && packet[18]==0 && packet[19]==53
}

func (d *dnsTun) Read(bufs [][]byte,sizes []int,offset int)(int,error){
    if len(bufs)==0 || len(sizes)<len(bufs) || offset<0{return 0,ErrVPNInit}
    for {
        n,err:=d.Device.Read(bufs,sizes,offset)
        if n<0 || n>len(bufs){return 0,ErrVPNInit}
        kept:=0
        for i:=0;i<n;i++{
            if offset<0 || sizes[i]<0 || offset+sizes[i]>len(bufs[i]){return 0,ErrVPNInit}
            p:=bufs[i][offset:offset+sizes[i]]
            if localDNSPacket(p){
                if _,e:=d.local.Write([][]byte{p},0);e!=nil{return 0,e}
            }else{
                if kept!=i{copy(bufs[kept][offset:],p)}
                sizes[kept]=sizes[i];kept++
            }
        }
        if kept>0 || err!=nil{return kept,err}
    }
}
func (d *dnsTun) Write(bufs [][]byte,offset int)(int,error){
    d.writeMu.Lock();defer d.writeMu.Unlock()
    return d.Device.Write(bufs,offset)
}
func (d *dnsTun) pumpReplies(){
    buf:=make([]byte,65535);sizes:=make([]int,1)
    for {
        n,err:=d.local.Read([][]byte{buf},sizes,0)
        if n>0{
            select{case <-d.done:default:_,_=d.Write([][]byte{buf[:sizes[0]]},0)}
        }
        if err!=nil{return}
    }
}
func (d *dnsTun) acquire()bool{
    select{case <-d.done:return false;default:}
    select{case d.slots<-struct{}{}:return true;default:return false}
}
func (d *dnsTun) serveUDP(){
    buf:=make([]byte,4097)
    for {
        n,peer,err:=d.udp.ReadFrom(buf)
        if err!=nil{return}
        query:=append([]byte(nil),buf[:n]...)
        if !d.acquire(){continue}
        go func(){
            defer func(){<-d.slots}()
            answer:=dnsAnswer(query,d.exchange,true)
            if len(answer)>0{_,_=d.udp.WriteTo(answer,peer)}
        }()
    }
}
func (d *dnsTun) serveTCP(){
    for {
        c,err:=d.tcp.Accept()
        if err!=nil{return}
        if !d.acquire(){_=c.Close();continue}
        d.mu.Lock()
        if d.closed{d.mu.Unlock();<-d.slots;_=c.Close();return}
        d.conns[c]=true;d.mu.Unlock()
        go func(){
            defer func(){_=c.Close();d.mu.Lock();delete(d.conns,c);d.mu.Unlock();<-d.slots}()
            for i:=0;i<32;i++{
                _=c.SetDeadline(time.Now().Add(12*time.Second))
                var prefix [2]byte
                if _,err:=io.ReadFull(c,prefix[:]);err!=nil{return}
                size:=int(binary.BigEndian.Uint16(prefix[:]))
                if size<12 || size>4096{return}
                query:=make([]byte,size)
                if _,err:=io.ReadFull(c,query);err!=nil{return}
                answer:=dnsAnswer(query,d.exchange,false)
                if len(answer)==0{return}
                frame:=make([]byte,len(answer)+2)
                binary.BigEndian.PutUint16(frame,uint16(len(answer)))
                copy(frame[2:],answer)
                if _,err:=io.Copy(c,strings.NewReader(string(frame)));err!=nil{return}
            }
        }()
    }
}
func (d *dnsTun) Close()error{
    d.once.Do(func(){
        d.mu.Lock();d.closed=true;close(d.done)
        for c:=range d.conns{_=c.Close()}
        d.mu.Unlock()
        _=d.Device.Close() // also interrupts a blocked reply Write
        _=d.udp.Close();_=d.tcp.Close();_=d.local.Close()
    })
    return nil
}

func dnsAnswer(query []byte,exchange DNSExchanger,udp bool)[]byte{
    var q dnsmessage.Message
    if len(query)>4096 || q.Unpack(query)!=nil || q.Response || q.OpCode!=0 || len(q.Questions)!=1{return nil}
    fallback:=func(truncated bool,code dnsmessage.RCode)[]byte{
        m:=dnsmessage.Message{Header:dnsmessage.Header{ID:q.ID,Response:true,
            RecursionDesired:q.RecursionDesired,RecursionAvailable:true,Truncated:truncated,RCode:code},Questions:q.Questions}
        b,_:=m.Pack();return b
    }
    answer:=exchange.Exchange(query)
    var a dnsmessage.Message
    if len(answer)<12 || len(answer)>65535 || a.Unpack(answer)!=nil || !a.Response ||
        a.ID!=q.ID || a.OpCode!=q.OpCode || len(a.Questions)!=1 ||
        !strings.EqualFold(a.Questions[0].Name.String(),q.Questions[0].Name.String()) ||
        a.Questions[0].Type!=q.Questions[0].Type || a.Questions[0].Class!=q.Questions[0].Class{
        return fallback(false,dnsmessage.RCodeServerFailure)
    }
    if udp{
        limit:=512
        for _,r:=range q.Additionals{if r.Header.Type==dnsmessage.TypeOPT{
            limit=int(r.Header.Class);if limit<512{limit=512};if limit>1232{limit=1232}
        }}
        if len(answer)>limit{return fallback(true,dnsmessage.RCodeSuccess)}
    }
    return answer
}
