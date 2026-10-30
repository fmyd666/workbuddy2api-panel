package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
)

func newReplacePanel(t *testing.T) (*Panel, *pool.Pool, string) {
	t.Helper()
	dir := t.TempDir()
	pl := pool.New("")
	p := &Panel{cfg: Config{Pool: pl, AuthDir: dir}}
	seed := &auth.Auth{UID: "seed", AccessToken: "at-seed", FilePath: filepath.Join(dir, "workbuddy-seed.json"), Proxy: "socks5h://10.5.0.1:1080"}
	if err := seed.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	if err := pl.Add(seed); err != nil {
		t.Fatal(err)
	}
	return p, pl, dir
}

func TestPersistAccountAndAddRefusesDuplicateProxyWithoutWriting(t *testing.T) {
	p, _, dir := newReplacePanel(t)
	candidate := &auth.Auth{UID: "newcomer", AccessToken: "at-new", FilePath: filepath.Join(dir, "workbuddy-newcomer.json"), Proxy: "socks5h://10.5.0.1:1080"}
	err := p.persistAccountAndAdd(candidate, true, "")
	if err == nil || !strings.Contains(err.Error(), "proxy already bound") {
		t.Fatalf("err=%v want duplicate-binding rejection", err)
	}
	if _, statErr := os.Stat(candidate.FilePath); !os.IsNotExist(statErr) {
		t.Fatalf("rejected account left a credential file behind: %v", statErr)
	}
	if p.cfg.Pool.AuthByUID("newcomer") != nil {
		t.Fatal("rejected account entered the pool")
	}
}

func TestPersistAccountAndAddDisabledImportDoesNotOverwrite(t *testing.T) {
	p, _, dir := newReplacePanel(t)
	path := filepath.Join(dir, "workbuddy-seed.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := &auth.Auth{UID: "seed", AccessToken: "at-overwrite", FilePath: path, Proxy: "socks5h://10.5.0.9:1080"}
	if err := p.persistAccountAndAdd(duplicate, false, "imported disabled by request"); err == nil {
		t.Fatal("disabled import of an existing uid must fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed disabled import rewrote the existing credential file")
	}
	if got := p.cfg.Pool.AuthByUID("seed").AccessTokenValue(); got != "at-seed" {
		t.Fatalf("pool credential changed to %q", got)
	}
}

func TestPersistAccountAndAddPreservesExistingBindingFromDisk(t *testing.T) {
	p, pl, dir := newReplacePanel(t)
	path := filepath.Join(dir, "workbuddy-seed.json")
	// Simulate a restart where the file carries a binding but the account is not yet pooled.
	if got := pl.Remove("seed"); got == nil {
		t.Fatal("seed account missing")
	}
	replacement := &auth.Auth{UID: "seed", AccessToken: "at-refreshed", FilePath: path}
	if err := p.persistAccountAndAdd(replacement, true, ""); err != nil {
		t.Fatal(err)
	}
	if got := p.cfg.Pool.AuthByUID("seed").ProxyValue(); got != "socks5h://10.5.0.1:1080" {
		t.Fatalf("binding lost on credential refresh: %q", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := auth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AccessToken != "at-refreshed" || parsed.Proxy != "socks5h://10.5.0.1:1080" {
		t.Fatalf("persisted token=%q proxy=%q", parsed.AccessToken, parsed.Proxy)
	}
}
