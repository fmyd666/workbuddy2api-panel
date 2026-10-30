package pool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

func seedProxyAcct(t *testing.T, p *Pool, uid, dir string) *auth.Auth {
	t.Helper()
	fp := filepath.Join(dir, uid+".json")
	a := &auth.Auth{UID: uid, AccessToken: "at-" + uid, RefreshToken: "rt", FilePath: fp}
	if err := a.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	p.Add(a)
	return a
}

func TestSetAccountProxyExclusive(t *testing.T) {
	p := New("")
	dir := t.TempDir()
	a := seedProxyAcct(t, p, "a", dir)
	b := seedProxyAcct(t, p, "b", dir)
	red, err := p.SetAccountProxy("a", "sess:secret@10.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(red, "****") || strings.Contains(red, "secret") {
		t.Fatalf("redacted=%q", red)
	}
	if _, err := p.SetAccountProxy("b", "socks5://sess:other@10.0.0.1:1080"); err == nil {
		t.Fatal("same user@host:port must be exclusive")
	}
	if b.Proxy != "" {
		t.Fatalf("rejected bind mutated second account: %q", b.Proxy)
	}
	red2, err := p.SetAccountProxy("b", "other@10.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(red2, "other") || strings.Contains(red2, "secret") || !strings.Contains(red2, "****@") {
		t.Fatalf("proxy credentials should be fully redacted: %q", red2)
	}
	raw, err := os.ReadFile(a.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := auth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loaded.Proxy, "socks5h://") {
		t.Fatalf("stored=%q", loaded.Proxy)
	}
	if _, err := p.SetAccountProxy("missing", "1.2.3.4:1"); err != ErrAccountNotFound {
		t.Fatalf("missing err=%v", err)
	}
}

func TestAssignProxiesSkipsBound(t *testing.T) {
	p := New("")
	dir := t.TempDir()
	seedProxyAcct(t, p, "c", dir)
	seedProxyAcct(t, p, "a", dir)
	seedProxyAcct(t, p, "b", dir)
	if _, err := p.SetAccountProxy("b", "http://10.1.1.1:8080"); err != nil {
		t.Fatal(err)
	}
	got, err := p.AssignProxies([]string{"", "# comment", "10.0.0.2:1080", "10.0.0.3:1080", "10.0.0.4:1080"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("assigned=%+v", got)
	}
	if got[0].UID != "a" || got[1].UID != "c" {
		t.Fatalf("order=%+v want a then c (b already bound)", got)
	}
	if _, err := p.AssignProxies([]string{"10.0.0.2:1080"}); err == nil {
		t.Fatal("rebinding an in-use proxy must fail")
	}
}
