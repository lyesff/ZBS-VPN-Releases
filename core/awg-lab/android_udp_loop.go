// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "encoding/binary"
    "errors"
    "net/netip"
)

var ErrVPNRoutingLoop=errors.New("awg_vpn_udp_loop")

// Only numeric tuple metadata is retained internally. It is never exported.
func udpPeerMarker(peer netip.AddrPort)uint64{
    if !peer.IsValid() || !peer.Addr().Is4(){return 0}
    ip:=peer.Addr().As4()
    return uint64(binary.BigEndian.Uint32(ip[:]))<<16 | uint64(peer.Port())
}

// Match the current AWG socket's outer UDP tuple entering the Android TUN.
// Other app UDP and non-first IP fragments must never trigger the guard.
func isOwnUDPPacket(packet []byte,localPort uint32,peer uint64)bool{
    if localPort==0 || peer==0 || len(packet)<28 || packet[0]>>4!=4 || packet[9]!=17{return false}
    ihl:=int(packet[0]&15)*4
    length:=int(binary.BigEndian.Uint16(packet[2:4]))
    fragments:=binary.BigEndian.Uint16(packet[6:8])
    if ihl<20 || ihl+8>len(packet) || length<ihl+8 || length>len(packet) || fragments&0x1fff!=0{return false}
    udpLength:=int(binary.BigEndian.Uint16(packet[ihl+4:ihl+6]))
    if udpLength<8 || fragments&0x2000==0 && udpLength>length-ihl{return false}
    destination:=uint64(binary.BigEndian.Uint32(packet[16:20]))<<16 |
        uint64(binary.BigEndian.Uint16(packet[ihl+2:ihl+4]))
    return destination==peer && uint32(binary.BigEndian.Uint16(packet[ihl:ihl+2]))==localPort
}

func (a *AndroidVPN) UDPLoopCount()int64{
    if a==nil || a.stats==nil{return 0}
    return a.stats.udpLoop.Load()
}
