// SPDX-License-Identifier: GPL-3.0-or-later
package libbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

func (s *CommandServer) ChooseRoute(tag string) error {
	i := s.Instance()
	if i == nil {
		return errors.New("offline")
	}
	ob, _ := i.Box().Outbound().Outbound("vpn")
	g, ok := ob.(*group.Selector)
	if !ok || !g.SelectOutbound(tag) {
		return awInvalid
	}
	return nil
}

type ProbeToken struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewProbeToken() *ProbeToken {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	return &ProbeToken{ctx: ctx, cancel: cancel}
}
func (t *ProbeToken) Cancel() { t.cancel() }
// Probe failures intentionally expose only a fixed diagnostic code.
// Raw transport errors may contain hostnames, tokens, or other private data.
func awProbeFailure(err error) error {
    if errors.Is(err, context.DeadlineExceeded) { return errors.New("probe_timeout") }
    if errors.Is(err, context.Canceled) { return errors.New("probe_cancelled") }
    var dnsErr *net.DNSError
    if errors.As(err, &dnsErr) { return errors.New("probe_dns") }
    var certErr x509.UnknownAuthorityError
    if errors.As(err, &certErr) { return errors.New("probe_tls_certificate") }
    var urlErr *url.Error
    if errors.As(err, &urlErr) {
        if urlErr.Timeout() { return errors.New("probe_timeout") }
    }
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Timeout() { return errors.New("probe_timeout") }
    if errors.Is(err, syscall.ENETUNREACH) { return errors.New("probe_network_unreachable") }
    if errors.Is(err, syscall.EHOSTUNREACH) { return errors.New("probe_host_unreachable") }
    if errors.Is(err, syscall.ECONNREFUSED) { return errors.New("probe_connection_refused") }
    if errors.Is(err, syscall.ECONNRESET) { return errors.New("probe_connection_reset") }
    if errors.Is(err, syscall.EPIPE) { return errors.New("probe_connection_closed") }
    var tlsErr tls.RecordHeaderError
    if errors.As(err, &tlsErr) { return errors.New("probe_tls_handshake") }
    return errors.New("probe_transport")
}

func (s *CommandServer) ProbeRoute(tag string, warp bool, token *ProbeToken) (string, error) {
	i := s.Instance()
	if i == nil {
		return "", errors.New("offline")
	}
	ob, ok := i.Box().Outbound().Outbound(tag)
	if !ok {
		return "", awInvalid
	}
	ctx := token.ctx
	defer token.Cancel()
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
		return ob.DialContext(ctx, n, M.ParseSocksaddr("1.1.1.1:443"))
	}}
	defer tr.CloseIdleConnections()
	c := http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://one.one.one.one/cdn-cgi/trace", nil)
	start := time.Now()
	r, e := c.Do(req)
	if e != nil {
		return "", awProbeFailure(e)
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 8193))
	if e != nil || len(b) > 8192 {
        return "", errors.New("probe_trace_body")
    }
    if r.StatusCode != 200 {
        return "", fmt.Errorf("probe_http_%d", r.StatusCode)
    }
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			m[k] = v
		}
	}
	if net.ParseIP(m["ip"]) == nil {
        return "", errors.New("probe_trace_ip")
    }
    if warp && m["warp"] != "on" && m["warp"] != "plus" {
        return "", errors.New("probe_warp_not_confirmed")
    }
	return awJSON(awMap{"ms": time.Since(start).Milliseconds(), "ip": m["ip"]}), nil
}
