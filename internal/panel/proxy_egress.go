package panel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
	"github.com/fmyd666/workbuddy2api-panel/internal/upstream"
)

const proxyExitIPProbeURL = "https://api.ipify.org/"

// probeProxyExitIP makes a bounded HTTP request through the configured proxy and
// returns the public address observed by the fixed IP-echo service. It never falls
// back to the process' environment proxy or to a direct connection.
func probeProxyExitIP(ctx context.Context, rawProxy string) (string, error) {
	return probeProxyExitIPTo(ctx, rawProxy, proxyExitIPProbeURL)
}

// probeProxyExitIPTo is kept package-private so tests can exercise real proxy handshakes
// against a local echo target. Production call sites only pass proxyExitIPProbeURL.
func probeProxyExitIPTo(ctx context.Context, rawProxy, targetURL string) (string, error) {
	uTarget, targetErr := url.Parse(targetURL)
	if targetErr != nil || uTarget == nil || (uTarget.Scheme != "https" && uTarget.Scheme != "http") || uTarget.User != nil || uTarget.Fragment != "" {
		return "", fmt.Errorf("proxy_test_invalid_target")
	}
	stored, _, err := auth.NormalizeProxy(rawProxy)
	if err != nil || stored == "" {
		return "", fmt.Errorf("proxy_test_invalid_proxy")
	}
	proxyURL, err := url.Parse(stored)
	if err != nil || proxyURL == nil {
		return "", fmt.Errorf("proxy_test_invalid_proxy")
	}
	scheme := strings.ToLower(proxyURL.Scheme)
	tunnel := scheme == "trojan" || scheme == "anytls"
	// 隧道协议多一次「本机→节点 TLS 握手 + 认证」，香港节点实测 1~2s，
	// 沿用直连档的 3s/5s 会把健康的隧道误判成失败。
	dialTimeout := 3 * time.Second
	headerTimeout := 3 * time.Second
	clientTimeout := 5 * time.Second
	if tunnel {
		dialTimeout = 8 * time.Second
		headerTimeout = 8 * time.Second
		clientTimeout = 12 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   headerTimeout,
		ResponseHeaderTimeout: headerTimeout,
		DisableKeepAlives:     true,
	}
	switch scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "socks5h":
		dialURL := *proxyURL
		dialURL.Scheme = "socks5"
		dialer, dialErr := proxy.FromURL(&dialURL, proxy.Direct)
		if dialErr != nil {
			return "", fmt.Errorf("proxy_test_invalid_proxy")
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				return contextDialer.DialContext(ctx, network, address)
			}
			return dialer.Dial(network, address)
		}
	case "trojan", "anytls":
		// 加密隧道：探测同样经隧道发请求，测出来的才是账号真实的出口 IP。
		dialTunnel, dialErr := upstream.ProxyTunnelDialer(stored)
		if dialErr != nil {
			return "", fmt.Errorf("proxy_test_invalid_proxy")
		}
		transport.DialContext = dialTunnel
	default:
		return "", fmt.Errorf("proxy_test_invalid_proxy")
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: clientTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("proxy_test_failed")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("proxy_test_failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy_test_failed")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 129))
	if err != nil || len(body) == 0 || len(body) > 128 {
		return "", fmt.Errorf("proxy_test_invalid_response")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !publicAddr(ip) {
		return "", fmt.Errorf("proxy_test_invalid_response")
	}
	return ip.Unmap().String(), nil
}
