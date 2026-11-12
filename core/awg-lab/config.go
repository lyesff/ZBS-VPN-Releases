// SPDX-License-Identifier: GPL-3.0-or-later
package awglab

import (
    "context"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "strconv"
    "strings"
)

var ErrInvalidAWGFile=errors.New("awg_invalid_file")

// FromQuickConfig accepts a bounded awg-quick file and translates it to
// the real AWG v3 UAPI. This never returns or logs the resulting secret.
func FromQuickConfig(raw string) (Config,error) {
    if len(raw)==0 || len(raw)>65536{return Config{},ErrInvalidAWGFile}
    sections:=map[string]map[string]string{
        "Interface":{}, "Peer":{},
    }
    current:=""
    for _,line:=range strings.Split(strings.ReplaceAll(raw,"\r\n","\n"),"\n"){
        line=strings.TrimSpace(line)
        if line=="" || strings.HasPrefix(line,"#") || strings.HasPrefix(line,";"){continue}
        if strings.HasPrefix(line,"[") {
            switch line {case "[Interface]":current="Interface";case "[Peer]":current="Peer";default:return Config{},ErrInvalidAWGFile}
            continue
        }
        if current=="" {return Config{},ErrInvalidAWGFile}
        key,value,ok:=strings.Cut(line,"=")
        if !ok{return Config{},ErrInvalidAWGFile}
        key,value=strings.TrimSpace(key),strings.TrimSpace(value)
        if key=="" || value=="" || sections[current][key]!="" {return Config{},ErrInvalidAWGFile}
        sections[current][key]=value
    }
    iface,peer:=sections["Interface"],sections["Peer"]
    allowedInterface:=map[string]bool{
        "PrivateKey":true,"Address":true,"DNS":true,"MTU":true,
        "S1":true,"S2":true,"S3":true,"S4":true,
        "Jc":true,"Jmin":true,"Jmax":true,
        "H1":true,"H2":true,"H3":true,"H4":true,
        "I1":true,"I2":true,"I3":true,"I4":true,"I5":true,
        "RandomTrailers":true,"DisableCookies":true,
    }
    allowedPeer:=map[string]bool{"PublicKey":true,"PresharedKey":true,"Endpoint":true,
        "AllowedIPs":true,"PersistentKeepalive":true}
    for k:=range iface{if !allowedInterface[k] {return Config{},ErrInvalidAWGFile}}
    for k:=range peer{if !allowedPeer[k] {return Config{},ErrInvalidAWGFile}}
    b64key:=func(value string)(string,error){
        b,err:=base64.StdEncoding.DecodeString(value)
        if err!=nil || len(b)!=32{return "",ErrInvalidAWGFile}
        return hex.EncodeToString(b),nil
    }
    private,err:=b64key(iface["PrivateKey"]);if err!=nil{return Config{},err}
    public,err:=b64key(peer["PublicKey"]);if err!=nil{return Config{},err}
    address:=""
    for _,entry:=range strings.Split(iface["Address"],","){
        field:=strings.TrimSpace(entry)
        ip,err:=netip.ParseAddr(field)
        if err!=nil {
            prefix,e:=netip.ParsePrefix(field)
            if e!=nil{return Config{},ErrInvalidAWGFile}
            ip=prefix.Addr()
        }
        if ip.Is4() {address=ip.String()}
    }
    if address=="" {return Config{},ErrInvalidAWGFile}
    host,port,err:=net.SplitHostPort(peer["Endpoint"])
    if err!=nil || host=="" {return Config{},ErrInvalidAWGFile}
    n,err:=strconv.Atoi(port)
    if err!=nil || n<1 || n>65535 {return Config{},ErrInvalidAWGFile}
    if ip,err:=netip.ParseAddr(host);err==nil {
        if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {return Config{},ErrInvalidAWGFile}
    } else {
        if len(host)>253 || strings.ContainsAny(host," /@\\\t\n") {return Config{},ErrInvalidAWGFile}
    }
    // UAPI accepts a hostname endpoint; its resolver will use the local
    // Android network. We do not allow user-defined redirects.
    lines:=[]string{"private_key="+private}
    obfNumbers:=map[string]string{
        "S1":"s1","S2":"s2","S3":"s3","S4":"s4",
        "Jc":"jc","Jmin":"jmin","Jmax":"jmax",
        "H1":"h1","H2":"h2","H3":"h3","H4":"h4",
    }
    for _,key:=range []string{"S1","S2","S3","S4","Jc","Jmin","Jmax","H1","H2","H3","H4"} {
        if v:=iface[key];v!="" {
            // Header values may be ranges, e.g. "1-4".
            for _,part:=range strings.Split(v,"-"){
                n,err:=strconv.ParseUint(part,10,32)
                if err!=nil || n>65535 {return Config{},ErrInvalidAWGFile}
            }
            lines=append(lines,obfNumbers[key]+"="+v)
        }
    }
    for _,key:=range []string{"I1","I2","I3","I4","I5"}{
        if v:=iface[key];v!="" {
            if len(v)>16384 || strings.ContainsAny(v,"\n\r") {return Config{},ErrInvalidAWGFile}
            lines=append(lines,strings.ToLower(key)+"="+v)
        }
    }
    for _,key:=range []string{"RandomTrailers","DisableCookies"}{
        if v:=iface[key];v!="" {
            enabled,err:=strconv.ParseBool(v)
            if err!=nil {if strings.EqualFold(v,"on"){enabled=true}else if strings.EqualFold(v,"off"){enabled=false}else{return Config{},ErrInvalidAWGFile}}
            name:="random_trailers";if key=="DisableCookies"{name="disable_cookies"}
            lines=append(lines,fmt.Sprintf("%s=%t",name,enabled))
        }
    }
    lines=append(lines,"replace_peers=true","public_key="+public,
        "replace_allowed_ips=true")
    allow:=peer["AllowedIPs"]
    if allow==""{return Config{},ErrInvalidAWGFile}
    for _,field:=range strings.Split(allow,","){
        p,err:=netip.ParsePrefix(strings.TrimSpace(field))
        if err!=nil{return Config{},ErrInvalidAWGFile}
        lines=append(lines,"allowed_ip="+p.String())
    }
    if v:=peer["PresharedKey"];v!="" {
        key,err:=b64key(v);if err!=nil{return Config{},err}
        lines=append(lines,"preshared_key="+key)
    }
    if v:=peer["PersistentKeepalive"];v!="" {
        n,err:=strconv.ParseUint(v,10,16);if err!=nil{return Config{},ErrInvalidAWGFile}
        lines=append(lines,fmt.Sprintf("persistent_keepalive_interval=%d",n))
    }
    lines=append(lines,"endpoint="+net.JoinHostPort(host,port))
    return Config{LocalIPv4:address,IPCSettings:strings.Join(lines,"\n")+"\n"},nil
}

// ProbeWARP is gomobile-compatible. It returns only non-sensitive outcome
// codes; Android must make sure no VPN is active before invoking it.
func ValidateQuickFile(raw string) bool {
    _,err:=FromQuickConfig(raw)
    return err==nil
}

// ProbeWarp invokes AWG without establishing the Android VPN TUN.
func ProbeWarp(awgQuick string)(string,error){
    cfg,err:=FromQuickConfig(awgQuick)
    if err!=nil {return "awg_invalid_file",nil}
    result,err:=Probe(context.Background(),cfg)
    return probeWarpOutcome(result,err)
}

// ProbeProtectedWarp runs before VpnService establishes its TUN. It uses
// the same protected UDP bind as the system engine. Its device closes before
// returning, so the two engines never overlap.
func ProbeProtectedWarp(quick string,protector SocketProtector)(string,error){
    if protector==nil{return "awg_device_start_failed",nil}
    cfg,err:=FromQuickConfig(quick)
    if err!=nil{return "awg_invalid_file",nil}
    result,err:=probeWithBind(context.Background(),cfg,newProtectedBind(protector))
    return probeWarpOutcome(result,err)
}

func probeWarpOutcome(result Result,err error)(string,error){
    if err!=nil {
        switch {
        case errors.Is(err,ErrInvalidConfig):return "awg_invalid_config",nil
        case errors.Is(err,ErrTunCreate):return "awg_tun_create_failed",nil
        case errors.Is(err,ErrIPCConfig):return "awg_ipc_config_failed",nil
        case errors.Is(err,ErrEndpointDNS):return "awg_endpoint_dns_failed",nil
        case errors.Is(err,ErrDeviceStart):return "awg_device_start_failed",nil
        case errors.Is(err,ErrNoHandshake):return "awg_no_handshake",nil
        case errors.Is(err,ErrHTTPSDeadline):return "awg_https_timeout",nil
        case errors.Is(err,ErrTCPTimeout):return "awg_tcp_timeout",nil
        case errors.Is(err,ErrTLSTimeout):return "awg_tls_timeout",nil
        case errors.Is(err,ErrHTTPTimeout):return "awg_http_timeout",nil
        case errors.Is(err,ErrNotWarp):return "awg_not_confirmed",nil
        default:return "awg_https_failed",nil
        }
    }
    return fmt.Sprintf("awg_verified:%d",result.Latency.Milliseconds()),nil
}
