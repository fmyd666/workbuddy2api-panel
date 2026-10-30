package upstream

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestProxyTunnelLiveInterop 用真实订阅节点验证 trojan / anytls 互通与真实出口 IP。
// 默认跳过：需要把节点列表放到 WORKBUDDY_LIVE_TUNNEL_FILE 指向的文件里（每行一个
// trojan:// 或 anytls:// URI）。凭据只从该文件读取，测试代码本身不含任何节点信息。
func TestProxyTunnelLiveInterop(t *testing.T) {
	path := os.Getenv("WORKBUDDY_LIVE_TUNNEL_FILE")
	if path == "" {
		t.Skip("set WORKBUDDY_LIVE_TUNNEL_FILE to run live tunnel interop")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read node file: %v", err)
	}
	var nodes []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "trojan://") || strings.HasPrefix(line, "anytls://") {
			nodes = append(nodes, line)
			if len(nodes) == 6 {
				break
			}
		}
	}
	if len(nodes) == 0 {
		t.Fatal("no tunnel nodes in the provided file")
	}
	for _, node := range nodes {
		scheme := strings.SplitN(node, "://", 2)[0]
		dial, err := ProxyTunnelDialer(node)
		if err != nil {
			t.Fatalf("%s dialer: %v", scheme, err)
		}
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: dial}, Timeout: 15 * time.Second}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org/", nil)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			t.Fatalf("%s live request failed: %v", scheme, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		cancel()
		ip := strings.TrimSpace(string(body))
		if ip == "" {
			t.Fatalf("%s returned an empty exit IP", scheme)
		}
		t.Logf("%s exit=%s", scheme, ip)

		// WorkBuddy 上游也必须经同一隧道可达（TLS + SNI 正常）。
		upCtx, upCancel := context.WithTimeout(context.Background(), 15*time.Second)
		upReq, _ := http.NewRequestWithContext(upCtx, http.MethodGet, "https://copilot.tencent.com/", nil)
		upResp, upErr := client.Do(upReq)
		if upErr != nil {
			upCancel()
			t.Fatalf("%s upstream request failed: %v", scheme, upErr)
		}
		_ = upResp.Body.Close()
		upCancel()
		if upResp.StatusCode >= 500 {
			t.Fatalf("%s upstream status %d", scheme, upResp.StatusCode)
		}
		t.Logf("%s upstream status=%d", scheme, upResp.StatusCode)
	}
}
