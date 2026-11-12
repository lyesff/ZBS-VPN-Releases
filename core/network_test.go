// SPDX-License-Identifier: GPL-3.0-or-later
package libbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type awStaticMonitor struct{ interfaceMonitorStub }

func (*awStaticMonitor) Start() error { return nil }
func (*awStaticMonitor) Close() error { return nil }

type awTestPlatform struct{ platformInterfaceStub }

func (*awTestPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return &awStaticMonitor{}
}
func TestAwModeConfigs(t *testing.T) {
	dir := os.Getenv("AUTOWARP_FIXTURES")
	if dir == "" {
		t.Skip("set AUTOWARP_FIXTURES")
	}
	for i := 0; i < 5; i++ {
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("mode-%d.json", i)))
		if err != nil {
			t.Fatal(err)
		}
		if err = CheckConfig(string(data)); err != nil {
			t.Fatal(i, err)
		}
	}
}
func TestAwVless(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "grpc"} {
		t.Run(network, func(t *testing.T) {
			ln, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			ln.Close()
			const id = "42e17584-457e-49ec-a916-c5a426b2bbac"
			extra := ""
			if network == "ws" {
				extra = `,"transport":{"type":"ws","path":"/test"}`
			}
			if network == "grpc" {
				extra = `,"transport":{"type":"grpc","service_name":"check"}`
			}
			cfg := fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":"%s"}]%s}],"outbounds":[{"type":"direct","tag":"test-server-exit"},{"type":"vless","tag":"test-client","server":"127.0.0.1","server_port":%d,"uuid":"%s"%s}]}`, port, id, extra, port, id, extra)
			ctx := service.ContextWith[adapter.PlatformInterface](baseContext(nil), &awTestPlatform{})
			opts, e := parseConfig(ctx, cfg)
			if e != nil {
				t.Fatal(e)
			}
			core, e := box.New(box.Options{Context: ctx, Options: opts})
			if e != nil {
				t.Fatal(e)
			}
			defer core.Close()
			if e = core.Start(); e != nil {
				t.Fatal(e)
			}
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through-vless") }))
			defer origin.Close()
			ob, _ := core.Outbound().Outbound("test-client")
			tr := origin.Client().Transport.(*http.Transport).Clone()
			tr.DisableKeepAlives = true
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
			}
			c := http.Client{Transport: tr, Timeout: 5 * time.Second}
			res, e := c.Get(origin.URL)
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			data, e := io.ReadAll(res.Body)
			if e != nil || string(data) != "through-vless" {
				t.Fatal("wrong data")
			}
		})
	}
}

func TestAwWireGuardChains(t *testing.T) {
	for _, mode := range []string{"wg", "vless-over-wg", "wg-over-vless"} {
		t.Run(mode, func(t *testing.T) {
			keys := func() map[string]string {
				v, e := NewWarpKeys()
				if e != nil {
					t.Fatal(e)
				}
				var k map[string]string
				if e = json.Unmarshal([]byte(v), &k); e != nil {
					t.Fatal(e)
				}
				return k
			}
			server, client := keys(), keys()
			udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			wp := udp.LocalAddr().(*net.UDPAddr).Port
			udp.Close()
			tcp, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			vp := tcp.Addr().(*net.TCPAddr).Port
			tcp.Close()
			const id = "42e17584-457e-49ec-a916-c5a426b2bbac"
			start := func(cfg string) *box.Box {
				ctx := service.ContextWith[adapter.PlatformInterface](baseContext(nil), &awTestPlatform{})
				opts, e := parseConfig(ctx, cfg)
				if e != nil {
					t.Fatal(e)
				}
				b, e := box.New(box.Options{Context: ctx, Options: opts})
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { b.Close() })
				if e = b.Start(); e != nil {
					t.Fatal(e)
				}
				return b
			}
			start(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":"%s"}]}],"endpoints":[{"type":"wireguard","tag":"remote-peer","address":["10.77.0.1/32"],"listen_port":%d,"private_key":"%s","peers":[{"public_key":"%s","allowed_ips":["10.77.0.2/32"]}]}],"outbounds":[{"type":"direct","tag":"exit"}],"route":{"final":"exit"}}`, vp, id, wp, server["private"], client["public"]))
			host, ve, we, entry := "127.0.0.1", "", "", "wg"
			if mode == "wg-over-vless" {
				we = `,"detour":"vless"`
			}
			if mode == "vless-over-wg" {
				host = "10.77.0.1"
				ve = `,"detour":"wg"`
				entry = "vless"
			}
			core := start(fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"selector","tag":"vpn","outbounds":["%s"]},{"type":"vless","tag":"vless","server":"%s","server_port":%d,"uuid":"%s"%s}],"endpoints":[{"type":"wireguard","tag":"wg","address":["10.77.0.2/32"],"private_key":"%s","peers":[{"address":"127.0.0.1","port":%d,"public_key":"%s","allowed_ips":["0.0.0.0/0"]}]%s}]}`, entry, host, vp, id, ve, client["private"], wp, server["public"], we))
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through-wireguard") }))
			defer origin.Close()
			p := origin.Listener.Addr().(*net.TCPAddr).Port
			tr := origin.Client().Transport.(*http.Transport).Clone()
			ob, _ := core.Outbound().Outbound("vpn")
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				h := "10.77.0.1"
				if mode == "vless-over-wg" {
					h = "127.0.0.1"
				}
				return ob.DialContext(ctx, network, M.ParseSocksaddr(net.JoinHostPort(h, fmt.Sprint(p))))
			}
			defer tr.CloseIdleConnections()
			c := http.Client{Transport: tr, Timeout: 6 * time.Second}
			resp, e := c.Get(origin.URL)
			if e != nil {
				t.Fatal(e)
			}
			defer resp.Body.Close()
			b, e := io.ReadAll(resp.Body)
			if e != nil || string(b) != "through-wireguard" {
				t.Fatal("wrong payload")
			}
		})
	}
}

// Exercise the same command-server lifecycle used by Android, including a
// cancellation while the outbound is waiting for a TLS peer that never replies.
func TestAwShutdownAndRestart(t *testing.T) {
	dir := t.TempDir()
	if err := Setup(&SetupOptions{BasePath: dir, WorkingPath: dir, TempPath: dir}); err != nil {
		t.Fatal(err)
	}
	ctx := service.ContextWith[adapter.PlatformInterface](baseContext(nil), &awTestPlatform{})
	server := &CommandServer{StartedService: daemon.NewStartedService(daemon.ServiceOptions{Context: ctx})}
	defer server.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	cfg := fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"selector","tag":"vpn","outbounds":["one"]},{"type":"vless","tag":"one","server":"127.0.0.1","server_port":%d,"uuid":"42e17584-457e-49ec-a916-c5a426b2bbac"}],"route":{"final":"vpn"}}`, port)
	if err := server.StartOrReloadService("{", &OverrideOptions{}); err == nil {
		t.Fatal("accepted invalid configuration")
	}
	for cycle := 0; cycle < 2; cycle++ {
		if err := server.StartOrReloadService(cfg, &OverrideOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := server.ChooseRoute("missing"); err == nil {
			t.Fatal("accepted absent route")
		}
		if err := server.ChooseRoute("one"); err != nil {
			t.Fatal(err)
		}
		if cycle == 0 {
			token := NewProbeToken()
			done := make(chan error, 1)
			go func() { _, err := server.ProbeRoute("one", false, token); done <- err }()
			select {
			case c := <-accepted:
				defer c.Close()
			case <-time.After(3 * time.Second):
				t.Fatal("probe did not dial")
			}
			token.Cancel()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("probe reported success after cancellation")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("probe did not cancel promptly")
			}
		}
		closed := make(chan error, 1)
		go func() { closed <- server.CloseService() }()
		select {
		case e := <-closed:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("libbox shutdown blocked")
		}
		if server.Instance() != nil {
			t.Fatal("core still owns an instance")
		}
	}
}
