package upstream

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// 账号绑定的 trojan / anytls 代理必须真的承载上游请求：请求经隧道到达 HTTP 目标，
// 且不能用环境变量代理或直连替代。
func TestAccountTunnelProxyCarriesRequests(t *testing.T) {
	const banner = "tunnel-account-ok"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, banner)
	}))
	defer origin.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	targetURL := "http://" + net.JoinHostPort(host, port) + "/"

	cases := []struct {
		name  string
		start func(t *testing.T, password string) (string, int, func())
	}{
		{"trojan", startTrojanServer},
		{"anytls", startAnyTLSServer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const password = "acct-pass"
			nodeHost, nodePort, stopNode := tc.start(t, password)
			defer stopNode()
			raw := tc.name + "://" + password + "@" + net.JoinHostPort(nodeHost, itoa(nodePort)) + "?sni=test.local"

			client := New()
			account := &auth.Auth{UID: "u1", AccessToken: "token", Proxy: raw}
			hc, err := client.httpClientFor(account, false)
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			transport := &http.Transport{}
			if hc.Transport != nil {
				transport = hc.Transport.(*http.Transport)
			}
			tunnelClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			resp, err := tunnelClient.Get(targetURL)
			if err != nil {
				t.Fatalf("request through %s tunnel: %v", tc.name, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
			if !strings.HasPrefix(string(body), banner) {
				t.Fatalf("body=%q want banner", string(body))
			}
		})
	}
}

// 绑定代理但节点不可达时必须直接失败，不能悄悄回落直连。
func TestAccountTunnelProxyDoesNotFallBackDirect(t *testing.T) {
	client := New()
	account := &auth.Auth{UID: "u2", AccessToken: "token", Proxy: "trojan://pw@127.0.0.1:1?sni=test.local"}
	hc, err := client.httpClientFor(account, false)
	if err != nil {
		t.Fatalf("dialer construction should succeed, got %v", err)
	}
	transport, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", hc.Transport)
	}
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	if _, err := httpClient.Get("http://127.0.0.1:1/"); err == nil {
		t.Fatal("unreachable tunnel node must fail instead of falling back")
	}
}
