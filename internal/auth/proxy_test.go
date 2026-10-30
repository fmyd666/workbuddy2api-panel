package auth

import (
	"strings"
	"testing"
)

func TestNormalizeProxy(t *testing.T) {
	stored, key, err := NormalizeProxy("  ")
	if err != nil || stored != "" || key != "" {
		t.Fatalf("empty: stored=%q key=%q err=%v", stored, key, err)
	}
	stored, key, err = NormalizeProxy("1.2.3.4:1080")
	if err != nil {
		t.Fatal(err)
	}
	if stored != "socks5h://1.2.3.4:1080" || key != "@1.2.3.4:1080" {
		t.Fatalf("bare: stored=%q key=%q", stored, key)
	}
	stored, key, err = NormalizeProxy("socks5://sess:secret@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}
	if key != "sess@proxy.example:1080" {
		t.Fatalf("key=%q", key)
	}
	if _, _, err = NormalizeProxy("ftp://1.2.3.4:21"); err == nil {
		t.Fatal("expected scheme error")
	}
	if _, _, err = NormalizeProxy("http://1.2.3.4"); err == nil {
		t.Fatal("expected port error")
	}
	red := RedactProxy(stored)
	if red == stored || !containsAll(red, "****") {
		t.Fatalf("redact=%q stored=%q", red, stored)
	}
}

func containsAll(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestNormalizeProxyTunnelSchemes(t *testing.T) {
	stored, key, err := NormalizeProxy("trojan://pa%40ss@node.example:443?sni=www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "trojan://") || !strings.Contains(stored, "sni=") {
		t.Fatalf("stored=%q", stored)
	}
	if key != "node.example:443" {
		t.Fatalf("key must not carry the node password: %q", key)
	}
	if strings.Contains(key, "pa") {
		t.Fatalf("key leaked password material: %q", key)
	}
	stored, key, err = NormalizeProxy("anytls://secret@node2.example:8443?sni=www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "anytls://") || key != "node2.example:8443" {
		t.Fatalf("stored=%q key=%q", stored, key)
	}
	if _, _, err := NormalizeProxy("trojan://node.example:443"); err == nil {
		t.Fatal("trojan without password must be rejected")
	}
	red := RedactProxy(stored)
	if strings.Contains(red, "secret") || !strings.Contains(red, "****") {
		t.Fatalf("redact leaked credentials: %q", red)
	}
}
