// SPDX-License-Identifier: GPL-3.0-or-later
package libbox

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type awMap = map[string]any
type awProfile struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Config awMap  `json:"config"`
}

var awInvalid = errors.New("unsupported or invalid profile")

func awJSON(x any) string { b, _ := json.Marshal(x); return string(b) }
func awProfileOf(name string, o awMap) awProfile {
	sum := sha256.Sum256([]byte(awJSON(o)))
	return awProfile{name, hex.EncodeToString(sum[:12]), o}
}
func awKey(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == 32
}
func NewWarpKeys() (string, error) {
	var s [32]byte
	if _, e := rand.Read(s[:]); e != nil {
		return "", e
	}
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	k, e := ecdh.X25519().NewPrivateKey(s[:])
	if e != nil {
		return "", e
	}
	return awJSON(map[string][]byte{"private": s[:], "public": k.PublicKey().Bytes()}), nil
}
func awPrefixes(s string) ([]string, error) {
	var out []string
	for _, v := range strings.Split(s, ",") {
		p, e := netip.ParsePrefix(strings.TrimSpace(v))
		if e != nil {
			return nil, awInvalid
		}
		out = append(out, p.String())
	}
	return out, nil
}
func awHost(s string) bool {
	if _, e := netip.ParseAddr(s); e == nil {
		return !strings.Contains(s, "%")
	}
	return len(s) > 0 && len(s) <= 253 && regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(s)
}
func ImportWarp(text string) (string, error) {
	if len(text) > 65536 {
		return "", awInvalid
	}
	sec := ""
	ss := map[string]map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(strings.SplitN(l, "#", 2)[0])
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") {
			sec = l
			if (sec != "[Interface]" && sec != "[Peer]") || ss[sec] != nil {
				return "", awInvalid
			}
			ss[sec] = map[string]string{}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || ss[sec] == nil || ss[sec][k] != "" || v == "" {
			return "", awInvalid
		}
		allow := " PrivateKey Address DNS MTU "
		if sec == "[Peer]" {
			allow = " PublicKey PresharedKey Endpoint AllowedIPs PersistentKeepalive Reserved "
		}
		if !strings.Contains(allow, " "+k+" ") {
			return "", awInvalid
		}
		ss[sec][k] = v
	}
	a, p := ss["[Interface]"], ss["[Peer]"]
	if !awKey(a["PrivateKey"]) || !awKey(p["PublicKey"]) {
		return "", awInvalid
	}
	addr, e := awPrefixes(a["Address"])
	if e != nil {
		return "", e
	}
	allowed, e := awPrefixes(p["AllowedIPs"])
	if e != nil {
		return "", e
	}
	host, port, e := net.SplitHostPort(p["Endpoint"])
	n, e2 := strconv.Atoi(port)
	if e != nil || !awHost(host) || e2 != nil || n < 1 || n > 65535 {
		return "", awInvalid
	}
	peer := awMap{"address": host, "port": n, "allowed_ips": allowed, "public_key": p["PublicKey"]}
	if s := p["PresharedKey"]; s != "" {
		if !awKey(s) {
			return "", awInvalid
		}
		peer["pre_shared_key"] = s
	}
	if s := p["PersistentKeepalive"]; s != "" {
		v, e := strconv.ParseUint(s, 10, 16)
		if e != nil {
			return "", awInvalid
		}
		peer["persistent_keepalive_interval"] = v
	}
	if s := p["Reserved"]; s != "" {
		vals := []int{}
		for _, q := range strings.Split(s, ",") {
			v, e := strconv.ParseUint(strings.TrimSpace(q), 10, 8)
			if e != nil {
				return "", awInvalid
			}
			vals = append(vals, int(v))
		}
		if len(vals) != 3 {
			return "", awInvalid
		}
		peer["reserved"] = vals
	}
	mtu := 1280
	if s := a["MTU"]; s != "" {
		mtu, e = strconv.Atoi(s)
		if e != nil || mtu < 576 || mtu > 9000 {
			return "", awInvalid
		}
	}
	return awJSON(awProfileOf(p["Endpoint"], awMap{"type": "wireguard", "private_key": a["PrivateKey"], "address": addr, "mtu": mtu, "peers": []awMap{peer}})), nil
}
func awKeys(o awMap, allowed string) bool {
	for k := range o {
		if !strings.Contains(" "+allowed+" ", " "+k+" ") {
			return false
		}
	}
	return true
}
// Some subscription exporters serialize absent optional query parameters as
// literal "null". Treat them as absent, never as TLS names or fingerprints.
func awOptional(v string) string {
    if v == "" || strings.EqualFold(v, "null") || strings.EqualFold(v, "undefined") { return "" }
    return v
}
func awLink(line string) (awProfile, error) {
	u, e := url.Parse(line)
	if e != nil || u.Scheme != "vless" || u.User == nil {
		return awProfile{}, awInvalid
	}
	q := u.Query()
	h := u.Hostname()
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 || !awHost(h) {
		return awProfile{}, awInvalid
	}
	if v := q.Get("encryption"); v != "" && v != "none" {
		return awProfile{}, awInvalid
	}
	if v := awOptional(q.Get("allowInsecure")); v != "" && v != "false" && v != "0" {
		return awProfile{}, awInvalid
	}
	if v := awOptional(q.Get("headerType")); v != "" && v != "none" {
		return awProfile{}, awInvalid
	}
	for k := range q {
		if !strings.Contains(" security type flow fp sni alpn host path serviceName pbk sid spx encryption allowInsecure headerType mode ", " "+k+" ") {
			return awProfile{}, awInvalid
		}
	}
	if v := awOptional(q.Get("mode")); v != "" && v != "gun" {
		return awProfile{}, awInvalid
	}
	o := awMap{"type": "vless", "server": h, "server_port": port, "uuid": u.User.Username()}
	if v := awOptional(q.Get("flow")); v != "" {
		o["flow"] = v
	}
	switch q.Get("security") {
	case "", "none":
	case "tls", "reality":
		name := awOptional(q.Get("sni"))
		if name == "" {
			name = h
		}
		t := awMap{"enabled": true, "server_name": name}
		if v := awOptional(q.Get("alpn")); v != "" {
			t["alpn"] = strings.Split(v, ",")
		}
		fp := awOptional(q.Get("fp"))
		if q.Get("security") == "reality" {
			if fp == "" {
				fp = "chrome"
			}
			t["reality"] = awMap{"enabled": true, "public_key": awOptional(q.Get("pbk")), "short_id": awOptional(q.Get("sid"))}
		}
		if fp != "" {
			t["utls"] = awMap{"enabled": true, "fingerprint": fp}
		}
		o["tls"] = t
	default:
		return awProfile{}, awInvalid
	}
	switch q.Get("type") {
	case "", "tcp", "raw":
	case "ws":
		path := awOptional(q.Get("path"))
		if path == "" {
			path = "/"
		}
		host := awOptional(q.Get("host"))
		if host == "" {
			host = h
		}
		o["transport"] = awMap{"type": "ws", "path": path, "headers": awMap{"Host": host}}
	case "grpc":
		o["transport"] = awMap{"type": "grpc", "service_name": awOptional(q.Get("serviceName"))}
	default:
		return awProfile{}, awInvalid
	}
	o["tag"] = u.Fragment
	return awValidate(o)
}

// awOtherLink translates a conservative subset of common proxy URI formats.
// Unsupported or insecure variants are skipped instead of silently weakened.
func awOtherLink(line string) (awProfile, error) {
    if strings.HasPrefix(line, "vmess://") {
        encoded := strings.TrimPrefix(line, "vmess://")
        var b []byte
        var err error
        for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
            b, err = enc.DecodeString(strings.TrimSpace(encoded))
            if err == nil { break }
        }
        if err != nil { return awProfile{}, awInvalid }
        var m map[string]any
        if json.Unmarshal(b, &m)!=nil { return awProfile{}, awInvalid }
        host, _ := m["add"].(string)
        port, e := strconv.Atoi(fmt.Sprint(m["port"]))
        uuid, _ := m["id"].(string)
        aid, err := strconv.Atoi(fmt.Sprint(m["aid"]))
        if m["aid"]==nil { aid=0;err=nil }
        if e!=nil || err!=nil || aid!=0 || !awHost(host) || port<1 || port>65535 || !awUUID.MatchString(uuid) { return awProfile{}, awInvalid }
        sec, _ := m["scy"].(string)
        if sec=="" { sec="auto" }
        if sec!="auto" && sec!="aes-128-gcm" && sec!="chacha20-poly1305" && sec!="none" { return awProfile{}, awInvalid }
        o:=awMap{"type":"vmess","server":host,"server_port":port,"uuid":uuid,"security":sec,"alter_id":0}
        tlsMode, _ := m["tls"].(string)
        if tlsMode!="" && tlsMode!="none" && tlsMode!="tls" { return awProfile{}, awInvalid }
        if tlsMode=="tls" {
            sni, _ := m["sni"].(string);if sni=="" { sni=host }
            o["tls"]=awMap{"enabled":true,"server_name":sni}
        }
        network, _ := m["net"].(string)
        switch network {
        case "", "tcp":
        case "ws":
            path, _ := m["path"].(string);if path=="" { path="/" }
            h, _ := m["host"].(string);if h=="" { h=host }
            o["transport"]=awMap{"type":"ws","path":path,"headers":awMap{"Host":h}}
        case "grpc":
            service, _ := m["path"].(string)
            o["transport"]=awMap{"type":"grpc","service_name":service}
        default: return awProfile{}, awInvalid
        }
        name, _ := m["ps"].(string);if name=="" { name=host }
        return awProfileOf(name,o),nil
    }
    u,e:=url.Parse(line)
    if e!=nil || u.User==nil { return awProfile{},awInvalid }
    host:=u.Hostname();port,e:=strconv.Atoi(u.Port())
    if e!=nil || port<1 || port>65535 || !awHost(host) { return awProfile{},awInvalid }
    q:=u.Query()
    name,_:=url.QueryUnescape(u.Fragment);if name=="" { name=host }
    switch u.Scheme {
    case "trojan":
        password,_:=u.User.Password()
        if password!="" || u.User.Username()=="" { return awProfile{},awInvalid }
        if v:=awOptional(q.Get("allowInsecure"));v!="" && v!="0" && v!="false" { return awProfile{},awInvalid }
        if v:=q.Get("security");v!="" && v!="tls" { return awProfile{},awInvalid }
        sn:=awOptional(q.Get("sni"));if sn=="" { sn=host }
        tls:=awMap{"enabled":true,"server_name":sn}
        if fp:=awOptional(q.Get("fp"));fp!="" { tls["utls"]=awMap{"enabled":true,"fingerprint":fp} }
        o:=awMap{"type":"trojan","server":host,"server_port":port,"password":u.User.Username(),"tls":tls}
        switch q.Get("type") {
        case "", "tcp", "raw":
        case "ws":
            path:=q.Get("path");if path=="" {path="/"}
            h:=q.Get("host");if h=="" {h=host}
            o["transport"]=awMap{"type":"ws","path":path,"headers":awMap{"Host":h}}
        case "grpc":o["transport"]=awMap{"type":"grpc","service_name":q.Get("serviceName")}
        default:return awProfile{},awInvalid
        }
        return awProfileOf(name,o),nil
    case "hysteria2", "hy2":
        if v:=q.Get("insecure");v!="" && v!="0" && v!="false" {return awProfile{},awInvalid}
        password:=u.User.Username()
        if v,ok:=u.User.Password();ok { password+=":"+v }
        if password=="" {return awProfile{},awInvalid}
        sn:=awOptional(q.Get("sni"));if sn=="" {sn=host}
        tls:=awMap{"enabled":true,"server_name":sn}
        if v:=q.Get("alpn");v!="" {tls["alpn"]=strings.Split(v,",")}
        o:=awMap{"type":"hysteria2","server":host,"server_port":port,"password":password,"tls":tls}
        return awProfileOf(name,o),nil
    default:return awProfile{},awInvalid
    }
}

var awUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func awValidate(o awMap) (awProfile, error) {
	host, _ := o["server"].(string)
	n, e := strconv.Atoi(fmt.Sprint(o["server_port"]))
	if !awKeys(o, "type server server_port uuid tag flow tls transport packet_encoding multiplex") || o["type"] != "vless" || !awHost(host) || e != nil || n < 1 || n > 65535 || !awUUID.MatchString(fmt.Sprint(o["uuid"])) {
		return awProfile{}, awInvalid
	}
	if encoding, ok := o["packet_encoding"]; ok && encoding != "" && encoding != "xudp" && encoding != "packetaddr" {
        return awProfile{}, awInvalid
    }
    if val, ok := o["multiplex"]; ok {
        m, valid := val.(map[string]any)
        if !valid || !awKeys(m,"enabled protocol padding max_connections") || m["enabled"] != true {
            return awProfile{}, awInvalid
        }
        if protocol, ok := m["protocol"].(string); ok && protocol != "smux" && protocol != "yamux" && protocol != "h2mux" {
            return awProfile{}, awInvalid
        }
        if pad, ok := m["padding"]; ok { if _, valid := pad.(bool); !valid { return awProfile{}, awInvalid } }
        if con, ok := m["max_connections"]; ok {
            n, valid := con.(float64)
            if !valid || n < 1 || n > 64 || n != float64(int(n)) { return awProfile{}, awInvalid }
        }
    }
	if f, ok := o["flow"]; ok && f != "" && f != "xtls-rprx-vision" {
		return awProfile{}, awInvalid
	}
	if x, ok := o["tls"]; ok {
		t, ok := x.(map[string]any)
		if !ok || !awKeys(t, "enabled server_name insecure alpn utls reality") || t["insecure"] != nil && t["insecure"] != false {
			return awProfile{}, awInvalid
		}
		if u, ok := t["utls"]; ok {
			m, ok := u.(map[string]any)
			if !ok || !awKeys(m, "enabled fingerprint") {
				return awProfile{}, awInvalid
			}
		}
		if r, ok := t["reality"]; ok {
			m, ok := r.(map[string]any)
			if !ok || !awKeys(m, "enabled public_key short_id") {
				return awProfile{}, awInvalid
			}
			k, e := base64.RawURLEncoding.DecodeString(fmt.Sprint(m["public_key"]))
			sid, _ := m["short_id"].(string)
			b, er := hex.DecodeString(sid)
			if e != nil || len(k) != 32 || er != nil || len(b) > 8 {
				return awProfile{}, awInvalid
			}
		}
	}
	if x, ok := o["transport"]; ok {
		t, ok := x.(map[string]any)
		if !ok {
			return awProfile{}, awInvalid
		}
		switch t["type"] {
		case "ws":
			if !awKeys(t, "type headers path") {
				return awProfile{}, awInvalid
			}
			if h, ok := t["headers"]; ok {
				m, ok := h.(map[string]any)
				if !ok || !awKeys(m, "Host") {
					return awProfile{}, awInvalid
				}
			}
		case "grpc":
			if !awKeys(t, "type service_name") {
				return awProfile{}, awInvalid
			}
		default:
			return awProfile{}, awInvalid
		}
	}
	name, _ := o["tag"].(string)
	delete(o, "tag")
	if name == "" {
		name = host
	}
	return awProfileOf(name, o), nil
}
// Xray JSON outbounds are not sing-box outbounds. Convert a conservative
// subset of VLESS with TCP/WS/gRPC and authenticated TLS or REALITY.
// Unsupported security and network modes are rejected, not downgraded.
func awXrayOutbound(v awMap) (awMap,bool) {
    if v["protocol"]!="vless" {return nil,false}
    settings,ok:=v["settings"].(map[string]any);if !ok {return nil,false}
    next,ok:=settings["vnext"].([]any);if !ok || len(next)!=1 {return nil,false}
    target,ok:=next[0].(map[string]any);if !ok {return nil,false}
    host,_:=target["address"].(string)
    port,err:=strconv.Atoi(fmt.Sprint(target["port"]))
    users,ok:=target["users"].([]any)
    if err!=nil || !awHost(host) || port<1 || port>65535 || !ok || len(users)!=1 {return nil,false}
    user,ok:=users[0].(map[string]any);if !ok {return nil,false}
    uuid,_:=user["id"].(string);if !awUUID.MatchString(uuid) {return nil,false}
    if enc,ok:=user["encryption"].(string);ok && enc!="" && enc!="none" {return nil,false}
    out:=awMap{"type":"vless","server":host,"server_port":port,"uuid":uuid}
    if flow,ok:=user["flow"].(string);ok && flow!="" {out["flow"]=flow}
    if name,ok:=v["tag"].(string);ok {out["tag"]=name}
    if packet,ok:=settings["packetEncoding"].(string);ok && packet!="" {
        if packet!="xudp" && packet!="packetaddr" {return nil,false}
        out["packet_encoding"]=packet
    }
    stream,ok:=v["streamSettings"].(map[string]any)
    if !ok {return nil,false}
    security,_:=stream["security"].(string)
    switch security {
    case "tls","reality":
        key:="tlsSettings"
        if security=="reality" {key="realitySettings"}
        options,ok:=stream[key].(map[string]any);if !ok {return nil,false}
        if v,ok:=options["allowInsecure"].(bool);ok && v {return nil,false}
        if v,ok:=options["insecure"].(bool);ok && v {return nil,false}
        tls:=awMap{"enabled":true}
        if s,ok:=options["serverName"].(string);ok && awOptional(s)!="" {tls["server_name"]=s}
        if a,ok:=options["alpn"].([]any);ok {
            names:=[]string{}
            for _,val:=range a {s,ok:=val.(string);if !ok{return nil,false};names=append(names,s)}
            if len(names)>0 {tls["alpn"]=names}
        }
        if fp,ok:=options["fingerprint"].(string);ok && awOptional(fp)!="" {
            tls["utls"]=awMap{"enabled":true,"fingerprint":fp}
        }
        if security=="reality" {
            key,_:=options["publicKey"].(string)
            sid,_:=options["shortId"].(string)
            tls["reality"]=awMap{"enabled":true,"public_key":key,"short_id":sid}
        }
        out["tls"]=tls
    default:
        return nil,false
    }
    network,_:=stream["network"].(string)
    switch network {
    case "","tcp","raw":
        if tcp,ok:=stream["tcpSettings"].(map[string]any);ok {
            if header,ok:=tcp["header"].(map[string]any);ok && header["type"]!="none" && header["type"]!=nil {return nil,false}
        }
    case "ws":
        ws,ok:=stream["wsSettings"].(map[string]any);if !ok {return nil,false}
        path,_:=ws["path"].(string);if path=="" {path="/"}
        t:=awMap{"type":"ws","path":path}
        if headers,ok:=ws["headers"].(map[string]any);ok {
            if h,ok:=headers["Host"].(string);ok && h!="" {t["headers"]=awMap{"Host":h}}
        }
        out["transport"]=t
    case "grpc":
        grpc,ok:=stream["grpcSettings"].(map[string]any);if !ok {return nil,false}
        service,_:=grpc["serviceName"].(string)
        if mode,ok:=grpc["multiMode"].(bool);ok && mode {return nil,false}
        out["transport"]=awMap{"type":"grpc","service_name":service}
    default:
        return nil,false
    }
    return out,true
}

// Flatten bounded subscription envelopes used by providers that group a
// profile's outbound(s) under "outbounds" with a "remarks" display name.
// Only recognized maps/URIs are followed; opaque strings aren't decoded.
func awFlattenInputs(inputs []any) []any {
    flattened:=make([]any,0,len(inputs))
    appendItem:=func(v any,name string){
        if len(flattened)>=512 {return}
        if m,ok:=v.(map[string]any);ok{
            if _,has:=m["protocol"];has {
                if converted,valid:=awXrayOutbound(m);valid {
                    if name!="" {converted["tag"]=name}
                    flattened=append(flattened,converted)
                }
                return
            }
            if _,has:=m["type"];has {
                copy:=make(map[string]any,len(m)+1)
                for k,v:=range m {copy[k]=v}
                if tag,ok:=copy["tag"].(string);!ok || tag=="" {
                    if name!="" {copy["tag"]=name}
                }
                flattened=append(flattened,copy)
                return
            }
            if _,has:=m["url"];has {flattened=append(flattened,m)}
            return
        }
        if s,ok:=v.(string);ok { flattened=append(flattened,s) }
    }
    for _,item:=range inputs {
        m,ok:=item.(map[string]any)
        if !ok { appendItem(item,"");continue }
        if _,has:=m["type"];has {appendItem(item,"");continue}
        if _,has:=m["protocol"];has {appendItem(item,"");continue}
        if _,has:=m["url"];has {appendItem(item,"");continue}
        name,_:=m["remarks"].(string)
        if name=="" {name,_=m["name"].(string)}
        switch inner:=m["outbounds"].(type){
        case []any:
            for _,v:=range inner {appendItem(v,name)}
        case map[string]any:
            appendItem(inner,name)
        }
    }
    return flattened
}

func ImportSubscription(raw string) (string, error) {
	if len(raw) > 1<<20 {
		return "", awInvalid
	}
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") && !strings.Contains(s, "://") {
		s = strings.Join(strings.Fields(s), "")
		decoded := false
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			b, e := enc.DecodeString(s)
			if e == nil {
				s = strings.TrimSpace(string(b))
				decoded = true
				break
			}
		}
		if !decoded {
			return "", awInvalid
		}
	}
	var inputs []any
	switch {
	case strings.HasPrefix(s, "["):
		if json.Unmarshal([]byte(s), &inputs) != nil {
			return "", awInvalid
		}
	case strings.HasPrefix(s, "{"):
		var m map[string][]any
		if json.Unmarshal([]byte(s), &m) != nil {
			return "", awInvalid
		}
		inputs = m["servers"]
		if inputs == nil {
			inputs = m["outbounds"]
		}
	default:
		for _, v := range strings.Split(s, "\n") {
			if v = strings.TrimSpace(v); strings.HasPrefix(v, "vless://") || strings.HasPrefix(v, "trojan://") || strings.HasPrefix(v, "hy2://") || strings.HasPrefix(v, "hysteria2://") || strings.HasPrefix(v, "vmess://") {
                inputs = append(inputs, v)
            }
		}
	}
	if len(inputs) > 512 {
		return "", awInvalid
	}
    inputs=awFlattenInputs(inputs)
	out := []awProfile{}
	seen := map[string]bool{}
	for _, item := range inputs {
		var p awProfile
		var e error
		switch v := item.(type) {
		case string:
            if strings.HasPrefix(v,"vless://") { p,e=awLink(v) } else { p,e=awOtherLink(v) }
		case map[string]any:
			if link, ok := v["url"].(string); ok {
                if strings.HasPrefix(link,"vless://") { p,e=awLink(link) } else { p,e=awOtherLink(link) }
			} else {
				p, e = awValidate(v)
			}
		default:
			continue
		}
		if e == nil && !seen[p.ID] {
			seen[p.ID] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "", awInvalid
	}
	return awJSON(out), nil
}
