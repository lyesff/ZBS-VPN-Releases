package awglab

import (
    "bytes"
    "encoding/binary"
    "errors"
    "testing"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func flowPacket(inbound bool, flags byte, seq,ack uint32, payload []byte) []byte {
    local:=[4]byte{172,16,0,2}; peer:=[4]byte{1,1,1,1}
    src,dst,sp,dp:=local,peer,uint16(52100),uint16(443)
    if inbound {src,dst,sp,dp=peer,local,dp,sp}
    p:=testIPv4TCP(src,dst,sp,dp,flags)
    p=append(p,payload...)
    binary.BigEndian.PutUint32(p[24:],seq)
    binary.BigEndian.PutUint32(p[28:],ack)
    sealFlowPacket(p)
    return p
}
func sealFlowPacket(p []byte) {
    ihl:=int(p[0]&15)*4
    binary.BigEndian.PutUint16(p[2:],uint16(len(p)))
    p[10],p[11]=0,0
    binary.BigEndian.PutUint16(p[10:],^uint16(checksumSum(p[:ihl],0)))
    p[ihl+16],p[ihl+17]=0,0
    sum:=checksumSum(p[12:20],uint32(6+len(p)-ihl))
    binary.BigEndian.PutUint16(p[ihl+16:],^uint16(checksumSum(p[ihl:],sum)))
}
func startFlow() *diagnosticTCPFlow {
    f:=newDiagnosticTCPFlow("172.16.0.2")
    f.selectPort(52100)
    f.observe(flowPacket(false,0x02,100,0,nil),true)
    return f
}
func TestCorrelatedTCPHandshake(t *testing.T) {
    f:=startFlow()
    p:=flowPacket(true,0x12,900,101,nil)
    if !f.observe(p,false) {t.Fatal("valid reply not matched")}
    f.written(f.writeToken(p),true,true)
    f.observe(flowPacket(false,0x10,101,901,nil),true)
    for i:=0;i<4;i++ {if f.counts[i]!=1 {t.Fatalf("handshake stage %d missing",i)}}
    // Retried registration cannot reuse a preceding socket's SYN/sequence.
    f.selectPort(52101)
    if f.observe(p,false) || f.counts[1]!=0 || f.counts[0]!=0 {t.Fatal("stale socket matched")}
}
func TestCorrelatedTCPRejectsInvalidReplies(t *testing.T) {
    cases:=[]struct{name string; index int; change func([]byte)}{
        {"destination",6,func(p []byte){p[19]=3;sealFlowPacket(p)}},
        {"acknowledgement",7,func(p []byte){binary.BigEndian.PutUint32(p[28:],102);sealFlowPacket(p)}},
        {"ip checksum",8,func(p []byte){p[8]^=1}},
        {"tcp checksum",9,func(p []byte){p[35]^=1}},
        {"total length",10,func(p []byte){binary.BigEndian.PutUint16(p[2:],200)}},
        {"tcp header length",10,func(p []byte){p[32]=0xf0}},
        {"fragment",10,func(p []byte){binary.BigEndian.PutUint16(p[6:],0x2000)}},
        {"other socket",12,func(p []byte){binary.BigEndian.PutUint16(p[22:],52101);sealFlowPacket(p)}},
    }
    for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
        f:=startFlow();p:=flowPacket(true,0x12,900,101,nil);tc.change(p)
        if f.observe(p,false) || f.counts[tc.index]!=1 || f.counts[1]!=0 {t.Fatal("invalid SYN-ACK accepted or misclassified")}
    })}
}
func TestCorrelatedTCPSourceAndReset(t *testing.T) {
    f:=newDiagnosticTCPFlow("172.16.0.2");f.selectPort(52100)
    p:=flowPacket(false,0x02,100,0,nil);p[15]=9;sealFlowPacket(p)
    f.observe(p,true)
    if f.counts[13]!=1 || f.counts[0]!=0 {t.Fatal("wrong Android source accepted")}
    f=startFlow()
    f.observe(flowPacket(true,0x14,0,101,nil),false)
    f.observe(flowPacket(false,0x04,101,0,nil),true)
    if f.counts[4]!=1 || f.counts[5]!=1 {t.Fatal("RST direction lost")}
}
func TestCorrelatedTCPChecksumAndPadding(t *testing.T) {
    // RFC 1071 example, plus an odd-length pseudoheader/segment case.
    if checksumSum([]byte{0,1,0xf2,3,0xf4,0xf5,0xf6,0xf7},0)!=0xddf2 {t.Fatal("checksum reference vector")}
    f:=startFlow();p:=flowPacket(true,0x12,900,101,[]byte{7})
    p=append(p,make([]byte,15)...)
    if !f.observe(p,false) {t.Fatal("odd segment or trailing AWG padding mishandled")}
    // IPv4 options move the TCP header; options participate in IP checksum.
    p=flowPacket(true,0x12,900,101,nil)
    p=append(append(append([]byte{},p[:20]...),1,1,1,1),p[20:]...)
    p[0]=0x46;sealFlowPacket(p)
    if !f.observe(p,false) {t.Fatal("IPv4 options mishandled")}
    for n:=0;n<len(p);n++ { f.observe(p[:n],false) } // no panic on truncated inputs
}
func TestCorrelatedTCPSequenceWrap(t *testing.T) {
    f:=newDiagnosticTCPFlow("172.16.0.2");f.selectPort(52100)
    f.observe(flowPacket(false,0x02,^uint32(0),0,nil),true)
    if !f.observe(flowPacket(true,0x12,^uint32(0),0,nil),false) {t.Fatal("ISN wrap")}
    f.observe(flowPacket(false,0x10,0,0,nil),true)
    if f.counts[3]!=1 {t.Fatal("ACK wrap")}
}

type packetWriteTun struct {
    tun.Device
    packets [][]byte
    failAt int
    mutate bool
}
func (t *packetWriteTun) Write(bufs [][]byte,offset int)(int,error) {
    if len(t.packets)==t.failAt {return 0,errors.New("write failed")}
    p:=bufs[0][offset:]
    t.packets=append(t.packets,append([]byte(nil),p...))
    n:=len(p)
    if t.mutate {clear(p)}
    return n,nil // pinned NativeTun's BYTE count, not packet count
}
func TestCountingTunWriteContractAndCorrelation(t *testing.T) {
    f:=startFlow();stats:=&vpnPacketStats{trace:f}
    target:=&packetWriteTun{failAt:-1}
    adapter:=&countingTun{Device:target,stats:stats}
    packet:=flowPacket(true,0x12,900,101,nil)
    buf:=append(make([]byte,16),packet...)
    n,err:=adapter.Write([][]byte{buf,buf},16)
    if err!=nil || n!=2 || stats.tunOut.Load()!=2 {t.Fatal("byte count leaked into packet contract")}
    if !bytes.Equal(target.packets[0],packet) {t.Fatal("TUN offset changed packet")}
    if f.counts[1]!=2 || f.counts[2]!=2 {t.Fatal("acceptance not associated with actual SYN-ACK")}
    target=&packetWriteTun{failAt:1};adapter.Device=target
    n,err=adapter.Write([][]byte{buf,buf},16)
    if n!=1 || err==nil || f.counts[11]!=1 {t.Fatal("partial batch not reported")}
}
func TestCountingTunObservesBeforeOffloadMutation(t *testing.T) {
    f:=startFlow();stats:=&vpnPacketStats{trace:f}
    adapter:=&countingTun{Device:&packetWriteTun{failAt:-1,mutate:true},stats:stats}
    n,err:=adapter.Write([][]byte{flowPacket(true,0x12,900,101,nil)},0)
    if n!=1 || err!=nil || f.counts[1]!=1 || f.counts[2]!=1 {t.Fatal("diagnosed mutated offload buffer")}
}

func TestDelayedWriteCannotContaminateNewSocket(t *testing.T) {
    f:=startFlow();p:=flowPacket(true,0x12,900,101,nil)
    token:=f.writeToken(p)
    matched:=f.observe(p,false)
    f.selectPort(52101)
    f.written(token,matched,true)
    f.written(token,matched,false)
    if f.counts[2]!=0 || f.counts[11]!=0 {t.Fatal("stale write contaminated new registration")}
}

func TestDiagnosticTCPDataAndAcknowledgement(t *testing.T){
    f:=startFlow()
    if !f.observe(flowPacket(true,0x12,900,101,nil),false){t.Fatal("SYN-ACK")}
    f.observe(flowPacket(false,0x18,101,901,[]byte("synthetic client data")),true)
    f.observe(flowPacket(true,0x10,901,122,nil),false)
    if f.data[0]!=1 || f.data[2]!=1 || f.data[1]!=0{t.Fatal("client data ACK not distinguished")}
    f.observe(flowPacket(true,0x18,901,122,[]byte("server data")),false)
    if f.data[1]!=1{t.Fatal("server payload missing")}
    f.selectPort(52101)
    if f.data!=[5]uint64{} || f.sentEnd!=0{t.Fatal("old data counters retained")}
}
func TestDiagnosticTCPDataChecksums(t *testing.T){
    f:=startFlow()
    p:=flowPacket(false,0x18,101,901,[]byte{1,2,3})
    p[8]^=1
    p[len(p)-1]^=1
    original:=append([]byte(nil),p...)
    f.observe(p,true)
    if f.data[3]!=1 || f.data[4]!=1{t.Fatal("outgoing corrupt checksums missed")}
    if !bytes.Equal(p,original){t.Fatal("diagnostics must not repair or alter packets")}
}
