package libbox

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const awTestID = "42e17584-457e-49ec-a916-c5a426b2bbac"

func TestKeys(t *testing.T) {
	out, err := NewWarpKeys()
	if err != nil {
		t.Fatal(err)
	}
	var k map[string][]byte
	if err := json.Unmarshal([]byte(out), &k); err != nil {
		t.Fatal(err)
	}
	sk, err := ecdh.X25519().NewPrivateKey(k["private"])
	if err != nil || !sk.PublicKey().Equal(mustPublic(t, k["public"])) {
		t.Fatal("public/private mismatch")
	}
}
func mustPublic(t *testing.T, k []byte) *ecdh.PublicKey {
	pub, err := ecdh.X25519().NewPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
func TestSubscriptions(t *testing.T) {
	uri := "vless://" + awTestID + "@example.com:443?security=tls&type=ws&path=%2Ftest#One"
	values := []string{uri + "\n" + uri, base64.RawURLEncoding.EncodeToString([]byte(uri)), awJSON([]string{uri}), awJSON(awMap{"servers": []awMap{{"url": uri}}}), awJSON(awMap{"outbounds": []awMap{{"type": "vless", "uuid": awTestID, "server": "example.com", "server_port": 443}}})}
	for _, v := range values {
		out, err := ImportSubscription(v)
		var p []awProfile
		if err != nil || json.Unmarshal([]byte(out), &p) != nil || len(p) != 1 {
			t.Fatal("import or deduplication")
		}
	}
}
func TestRejectUnsafeOrUnsupported(t *testing.T) {
	for _, query := range []string{"type=xhttp", "allowInsecure=1", "security=reality&pbk=x", "type=grpc&mode=multi"} {
		if _, e := ImportSubscription("vless://" + awTestID + "@example.com:443?" + query); e == nil {
			t.Fatal(query)
		}
	}
	if _, e := ImportSubscription(strings.Repeat("a", 1048577)); e == nil {
		t.Fatal("size limit")
	}
}
func TestWireGuard(t *testing.T) {
	k := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 32)))
	ini := "[Interface]\nPrivateKey = " + k + "\nAddress = 10.77.0.2/32, fd00::2/128\n[Peer]\nPublicKey = " + k + "\nEndpoint = [2606:4700::1]:2408\nAllowedIPs = 0.0.0.0/0, ::/0\nReserved = 13, 22, 31"
	if _, e := ImportWarp(ini); e != nil {
		t.Fatal(e)
	}
	if _, e := ImportWarp(ini + "\nJc = 5"); e == nil {
		t.Fatal("AWG extension accepted")
	}
}

func TestMixedProtocolSubscription(t *testing.T) {
    vless := "vless://" + awTestID + "@example.com:443?security=tls&type=ws#vless"
    trojan := "trojan://secret@example.com:443?security=tls&type=ws&path=%2Ftest#trojan"
    hy2 := "hysteria2://secret@example.com:443?sni=example.com#hy2"
    vmessData := awJSON(awMap{"v":"2","ps":"vmess","add":"example.com","port":"443","id":awTestID,"aid":"0","scy":"auto","tls":"tls","net":"ws","path":"/"})
    vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessData))
    mixed := strings.Join([]string{vless,trojan,hy2,vmess},"\n")
    for _, raw := range []string{mixed,base64.StdEncoding.EncodeToString([]byte(mixed))} {
        result,err:=ImportSubscription(raw)
        if err!=nil { t.Fatal(err) }
        var profiles []awProfile
        if json.Unmarshal([]byte(result),&profiles)!=nil || len(profiles)!=4 { t.Fatalf("got %d mixed profiles",len(profiles)) }
        types:=map[string]bool{}
        for _,p:=range profiles {types[p.Config["type"].(string)]=true}
        for _,protocol:=range []string{"vless","trojan","hysteria2","vmess"} {
            if !types[protocol] { t.Fatalf("missing %s",protocol) }
        }
    }
}
func TestRejectInsecureMixedLinks(t *testing.T) {
    for _,link:=range []string{
        "trojan://password@example.com:443?allowInsecure=1",
        "hysteria2://password@example.com:443?insecure=1",
    } {
        if _,err:=ImportSubscription(link);err==nil {t.Fatal("insecure configuration accepted")}
    }
}

func TestHappwnerNullOptionalValues(t *testing.T) {
    uri:="vless://"+awTestID+"@example.com:2083?encryption=none&flow=&fp=null&pbk=null&security=tls&sid=null&sni=null&type=tcp#United%20Kingdom"
    raw,err:=ImportSubscription(uri)
    if err!=nil {t.Fatalf("failed to import URI with null placeholders: %v",err)}
    var profiles []awProfile
    if err=json.Unmarshal([]byte(raw),&profiles);err!=nil || len(profiles)!=1 {t.Fatal("missing VLESS profile")}
    tls,ok:=profiles[0].Config["tls"].(map[string]any)
    if !ok || tls["server_name"]!="example.com" {t.Fatal("null SNI not normalized")}
    if _,exists:=tls["utls"];exists {t.Fatal("null fingerprint must not enable utls")}
    if _,exists:=tls["reality"];exists {t.Fatal("null Reality fields must not enable Reality")}
}

func TestMihomoConvertedVlessSettingsSurviveImport(t *testing.T) {
    config:=awMap{
        "type":"vless","server":"example.org","server_port":2083,"uuid":awTestID,
        "tag":"United Kingdom","packet_encoding":"xudp",
        "tls":awMap{"enabled":true,"utls":awMap{"enabled":true,"fingerprint":"firefox"}},
        "multiplex":awMap{"enabled":true,"protocol":"smux","padding":true,"max_connections":4},
    }
    raw,err:=ImportSubscription(awJSON([]awMap{config}))
    if err!=nil {t.Fatal(err)}
    var nodes []awProfile
    if err=json.Unmarshal([]byte(raw),&nodes);err!=nil || len(nodes)!=1 {t.Fatal("no imported VLESS profile")}
    node:=nodes[0].Config
    if node["packet_encoding"]!="xudp" {t.Fatal("packet encoding was discarded")}
    mux,ok:=node["multiplex"].(map[string]any)
    if !ok || mux["protocol"]!="smux" || mux["padding"]!=true || mux["max_connections"]!=float64(4) {t.Fatal("smux settings discarded")}
    tls,ok:=node["tls"].(map[string]any)
    if !ok {t.Fatal("TLS missing")}
    utls,ok:=tls["utls"].(map[string]any)
    if !ok || utls["fingerprint"]!="firefox" {t.Fatal("uTLS fingerprint missing")}
}

func TestNestedProviderOutboundsSubscription(t *testing.T) {
    node:=awMap{"type":"vless","server":"example.org","server_port":2083,
        "uuid":awTestID,"tls":awMap{"enabled":true,
            "utls":awMap{"enabled":true,"fingerprint":"firefox"}},
        "packet_encoding":"xudp","multiplex":awMap{"enabled":true,
            "protocol":"smux","padding":true,"max_connections":4}}
    cases:=[]string{
        awJSON([]awMap{{"remarks":"United Kingdom","outbounds":[]awMap{node}}}),
        awJSON([]awMap{{"remarks":"United Kingdom","outbounds":node}}),
        awJSON(awMap{"servers":[]awMap{{"remarks":"United Kingdom","outbounds":[]awMap{node}}}}),
    }
    for _,raw:=range cases {
        result,err:=ImportSubscription(raw)
        if err!=nil {t.Fatal(err)}
        var nodes []awProfile
        if err=json.Unmarshal([]byte(result),&nodes);err!=nil || len(nodes)!=1 {t.Fatal("nested profile not imported")}
        if nodes[0].Name!="United Kingdom" {t.Fatalf("remarks missing: %q",nodes[0].Name)}
        if nodes[0].Config["packet_encoding"]!="xudp" {t.Fatal("xudp discarded")}
    }
}
func TestNestedProviderOpaqueStringsNotTreatedAsServers(t *testing.T) {
    raw:=awJSON([]awMap{{"remarks":"test","outbounds":"encrypted_payload"}})
    if _,err:=ImportSubscription(raw);err==nil {t.Fatal("opaque outbound string accepted")}
}

func TestXrayNestedProviderVLESS(t *testing.T) {
    xray:=awMap{
        "protocol":"vless","tag":"proxy",
        "settings":awMap{"vnext":[]any{awMap{
            "address":"example.org","port":2083,"users":[]any{awMap{
                "id":awTestID,"encryption":"none"}}}}},
        "streamSettings":awMap{
            "network":"tcp","security":"tls",
            "tlsSettings":awMap{"serverName":"example.org","fingerprint":"firefox"},
        },
    }
    raw:=awJSON([]awMap{{"remarks":"United Kingdom","outbounds":[]any{xray,
        awMap{"protocol":"freedom","tag":"direct"},
        awMap{"protocol":"blackhole","tag":"block"}}}})
    result,err:=ImportSubscription(raw)
    if err!=nil {t.Fatal(err)}
    var p []awProfile
    if err=json.Unmarshal([]byte(result),&p);err!=nil || len(p)!=1 {t.Fatal("expected one supported Xray VLESS")}
    if p[0].Name!="United Kingdom" {t.Fatalf("wrong profile name %q",p[0].Name)}
    tls,ok:=p[0].Config["tls"].(map[string]any)
    if !ok {t.Fatal("TLS missing")}
    utls,ok:=tls["utls"].(map[string]any)
    if !ok || utls["fingerprint"]!="firefox" {t.Fatal("Firefox fingerprint missing")}
}
func TestXrayUnsupportedTransportIsNotDowngraded(t *testing.T) {
    xray:=awMap{
        "protocol":"vless","settings":awMap{"vnext":[]any{awMap{
            "address":"example.org","port":443,"users":[]any{awMap{"id":awTestID}}}}},
        "streamSettings":awMap{"security":"tls","network":"xhttp","tlsSettings":awMap{}},
    }
    if _,err:=ImportSubscription(awJSON([]awMap{{"remarks":"test","outbounds":[]any{xray}}}));err==nil {
        t.Fatal("unsupported xhttp was silently accepted")
    }
}
func TestXrayPlaintextIsNotImportedAsTLS(t *testing.T) {
    xray:=awMap{
        "protocol":"vless","settings":awMap{"vnext":[]any{awMap{
            "address":"example.org","port":443,"users":[]any{awMap{"id":awTestID}}}}},
        "streamSettings":awMap{"security":"none","network":"tcp"},
    }
    if _,err:=ImportSubscription(awJSON([]awMap{{"outbounds":[]any{xray}}}));err==nil{
        t.Fatal("plaintext Xray link should not bypass secure-only converter")
    }
}
