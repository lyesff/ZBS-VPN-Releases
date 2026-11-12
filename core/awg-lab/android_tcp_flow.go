// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "encoding/binary"
    "fmt"
    "net/netip"
    "sync"
)

// Only the explicitly registered HTTPS socket is traced. Packet contents,
// addresses, ports and sequence numbers stay in memory and are never exported.
// A new registration replaces the previous attempt, including its counters.
type diagnosticTCPFlow struct {
    mu sync.Mutex
    local [4]byte
    port uint16
    generation uint64
    synSeen, peerSeen bool
    clientSeq, serverSeq uint32
    counts [14]uint64
    data [5]uint64
    sentEnd uint32
}

func (f *diagnosticTCPFlow) selectPort(port int) {
    f.mu.Lock()
    defer f.mu.Unlock()
    f.generation++
    f.port=0
    if port>0 && port<=65535 { f.port=uint16(port) }
    f.synSeen=false
    f.peerSeen=false
    f.clientSeq=0
    f.serverSeq=0
    f.counts=[14]uint64{}
    f.data=[5]uint64{}
    f.sentEnd=0
}

// SetDiagnosticPort selects a socket bound by Android BEFORE connect().
// LocalIPv4 is taken from the same validated quick-config as Android's TUN.
func (a *AndroidVPN) SetDiagnosticPort(port int) {
    if a!=nil && a.stats!=nil && a.stats.trace!=nil { a.stats.trace.selectPort(port) }
}

// TCPFlowCounters: SYN, matching valid SYN-ACK, TUN accepted SYN-ACK,
// Android final ACK, peer RST, Android RST, wrong destination IP,
// wrong ACK number, bad IPv4 checksum, bad TCP checksum, bad format,
// TUN write failure, unrelated response, wrong outgoing source IP.
func (a *AndroidVPN) TCPFlowCounters() string {
    if a==nil || a.stats==nil || a.stats.trace==nil { return "" }
    f:=a.stats.trace
    f.mu.Lock()
    defer f.mu.Unlock()
    c:=f.counts
    return fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
        c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7],c[8],c[9],c[10],c[11],c[12],c[13])
}

// TCPDataCounters exposes counts only: client data packets, server data packets,
// ACKs covering client data, outgoing bad IP/TCP checksums, UDP send/receive
// errors. Payloads and TLS contents are never retained or exported.
func (a *AndroidVPN) TCPDataCounters() string {
    if a==nil || a.stats==nil || a.stats.trace==nil{return ""}
    f:=a.stats.trace
    f.mu.Lock()
    d:=f.data
    f.mu.Unlock()
    return fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d",d[0],d[1],d[2],d[3],d[4],
        a.stats.udpSendErrors.Load(),a.stats.udpRecvErrors.Load())
}

func newDiagnosticTCPFlow(local string) *diagnosticTCPFlow {
    f:=&diagnosticTCPFlow{}
    if ip,err:=netip.ParseAddr(local); err==nil && ip.Is4() { f.local=ip.As4() }
    return f
}

// checksumSum folds the Internet checksum, including an odd trailing byte.
func checksumSum(p []byte, sum uint32) uint32 {
    for len(p)>=2 { sum+=uint32(binary.BigEndian.Uint16(p)); p=p[2:] }
    if len(p)>0 { sum+=uint32(p[0])<<8 }
    for sum>>16!=0 { sum=(sum&0xffff)+(sum>>16) }
    return sum
}

// observe runs BEFORE Write: Linux's offload/GRO adapter may mutate buffers.
// Return true only for a valid SYN-ACK belonging to the selected socket.
func (f *diagnosticTCPFlow) observe(p []byte, fromAndroid bool) bool {
    if f==nil { return false }
    f.mu.Lock()
    defer f.mu.Unlock()
    if f.port==0 || len(p)<20 || p[0]>>4!=4 || p[9]!=6 { return false }
    ihl:=int(p[0]&15)*4
    if ihl<20 || len(p)<ihl+20 { return false }
    // Non-first fragments do not contain a TCP header.
    if binary.BigEndian.Uint16(p[6:8])&0x1fff!=0 { return false }
    peer:=[4]byte{1,1,1,1}
    src:=[4]byte(p[12:16]); dst:=[4]byte(p[16:20])
    sp:=binary.BigEndian.Uint16(p[ihl:]); dp:=binary.BigEndian.Uint16(p[ihl+2:])
    if fromAndroid {
        if dst!=peer || dp!=443 || sp!=f.port { return false }
        if src!=f.local { f.counts[13]++; return false }
    } else {
        if src!=peer || sp!=443 { return false }
        if dp!=f.port { f.counts[12]++; return false }
        if dst!=f.local { f.counts[6]++; return false }
    }
    length:=int(binary.BigEndian.Uint16(p[2:4]))
    tcpLen:=int(p[ihl+12]>>4)*4
    if length<ihl+20 || length>len(p) || tcpLen<20 || ihl+tcpLen>length ||
        binary.BigEndian.Uint16(p[6:8])&0x2000!=0 {
        f.counts[10]++; return false
    }
    p=p[:length] // AWG padding is outside IPv4 Total Length.
    // Validate the returned wire packet, never repair an invalid checksum.
    // Outgoing CHECKSUM_PARTIAL may be completed by the native TUN adapter.
    if !fromAndroid {
        if checksumSum(p[:ihl],0)!=0xffff { f.counts[8]++; return false }
        pseudo:=checksumSum(p[12:20],uint32(6+length-ihl))
        if checksumSum(p[ihl:],pseudo)!=0xffff { f.counts[9]++; return false }
    }
    flags:=p[ihl+13]
    seq:=binary.BigEndian.Uint32(p[ihl+4:])
    ack:=binary.BigEndian.Uint32(p[ihl+8:])
    payload:=length-ihl-tcpLen
    if fromAndroid && payload>0 {
        f.data[0]++
        if checksumSum(p[:ihl],0)!=0xffff{f.data[3]++}
        pseudo:=checksumSum(p[12:20],uint32(6+length-ihl))
        if checksumSum(p[ihl:],pseudo)!=0xffff{f.data[4]++}
        end:=seq+uint32(payload)
        if f.data[0]==1 || int32(end-f.sentEnd)>0{f.sentEnd=end}
    }
    if !fromAndroid {
        if payload>0{f.data[1]++}
        if f.synSeen && f.data[0]>0 && flags&0x16==0x10 &&
            int32(ack-(f.clientSeq+1))>0 && int32(f.sentEnd-ack)>=0{f.data[2]++}
    }
    if fromAndroid {
        if flags&0x17==0x02 {
            // Retransmits keep the same ISN. A new socket registration resets it.
            f.clientSeq=seq; f.synSeen=true; f.counts[0]++
        }
        if flags&0x04!=0 { f.counts[5]++ }
        if f.peerSeen && flags&0x17==0x10 && seq==f.clientSeq+1 && ack==f.serverSeq+1 {
            f.counts[3]++
        }
    } else {
        if flags&0x04!=0 { f.counts[4]++ }
        if flags&0x17==0x12 {
            if !f.synSeen { f.counts[12]++; return false }
            if ack!=f.clientSeq+1 { f.counts[7]++; return false }
            f.serverSeq=seq; f.peerSeen=true; f.counts[1]++
            return true
        }
    }
    return false
}

// writeToken prevents completion of a previous socket's delayed write from
// being attributed to a newly registered socket. Unrelated traffic is ignored.
func (f *diagnosticTCPFlow) writeToken(p []byte) uint64 {
    if f==nil {return 0}
    f.mu.Lock()
    defer f.mu.Unlock()
    if f.port==0 || len(p)<20 || p[0]>>4!=4 || p[9]!=6 {return 0}
    ihl:=int(p[0]&15)*4
    if ihl<20 || len(p)<ihl+20 || binary.BigEndian.Uint16(p[6:8])&0x1fff!=0 {return 0}
    if [4]byte(p[12:16])!=[4]byte{1,1,1,1} ||
        binary.BigEndian.Uint16(p[ihl:])!=443 || binary.BigEndian.Uint16(p[ihl+2:])!=f.port {return 0}
    return f.generation
}
func (f *diagnosticTCPFlow) written(token uint64, synAck, success bool) {
    if f==nil || token==0 { return }
    f.mu.Lock()
    defer f.mu.Unlock()
    if token!=f.generation {return}
    if !success { f.counts[11]++ } else if synAck { f.counts[2]++ }
}
