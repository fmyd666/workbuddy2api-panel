package panel

import (
	"strings"
	"testing"
)

// 订阅里 trojan / anytls 节点必须“可绑定”且带名字入库；ss/vless 等仍只报元数据。
func TestProxyImportAcceptsTunnelNodes(t *testing.T) {
	content := strings.Join([]string{
		"trojan://pa55@node.example:443?sni=www.example.com#香港01",
		"anytls://pa55@node2.example:8443?sni=www.example.com#日本02",
		"ss://YWVzOnBhc3M@proxy.example:8388#skip",
	}, "\n")
	entries, unsupported, errs := parseProxyImport(content)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(unsupported) != 1 {
		t.Fatalf("unsupported=%v", unsupported)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want 2", len(entries))
	}
	types := map[string]bool{}
	for _, e := range entries {
		types[e.Type] = e.Selectable
		if !strings.HasPrefix(e.Raw, "trojan://") && !strings.HasPrefix(e.Raw, "anytls://") {
			t.Fatalf("raw=%q", e.Raw)
		}
		if e.Name == "" {
			t.Fatalf("tunnel node lost its name: %+v", e)
		}
		if e.ID == "" {
			t.Fatalf("tunnel node has no id: %+v", e)
		}
	}
	if !types["trojan"] || !types["anytls"] {
		t.Fatalf("tunnel nodes must be selectable: %v", types)
	}
}

func TestProxyImportAcceptsClashTunnelNodes(t *testing.T) {
	content := strings.Join([]string{
		"proxies:",
		"  - name: 香港专线",
		"    type: trojan",
		"    server: node.example",
		"    port: 27100",
		"    password: pa55",
		"    sni: sni-a.example",
		"    skip-cert-verify: true",
		"  - name: 日本节点",
		"    type: anytls",
		"    server: node2.example",
		"    port: 24150",
		"    password: pa55",
		"    sni: sni-b.example",
	}, "\n")
	entries, unsupported, errs := parseProxyImport(content)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(unsupported) != 0 || len(entries) != 2 {
		t.Fatalf("entries=%d unsupported=%v", len(entries), unsupported)
	}
	for _, e := range entries {
		if !e.Selectable {
			t.Fatalf("clash tunnel node not selectable: %+v", e)
		}
		if strings.Contains(e.Raw, "skip-cert-verify") {
			t.Fatalf("clash-only field leaked into the proxy URL: %q", e.Raw)
		}
		if !strings.Contains(e.Raw, "sni=") {
			t.Fatalf("sni lost during import: %q", e.Raw)
		}
	}
}
