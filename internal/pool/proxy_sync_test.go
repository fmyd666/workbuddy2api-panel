package pool

import (
	"testing"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// duplicateProxyKey reports which proxy key is bound to more than one UID.
func duplicateProxyKey(p *Pool) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	seen := map[string]string{}
	for uid, e := range p.byUID {
		key := auth.ProxyKey(e.a.ProxyValue())
		if key == "" {
			continue
		}
		if owner, ok := seen[key]; ok && owner != uid {
			return key, true
		}
		seen[key] = uid
	}
	return "", false
}

func TestSyncToDirRejectsDuplicateIncomingBindings(t *testing.T) {
	p := New("")
	incoming := []*auth.Auth{
		{UID: "a", AccessToken: "at-a", Proxy: "socks5h://10.9.0.1:1080"},
		{UID: "b", AccessToken: "at-b", Proxy: "socks5h://10.9.0.1:1080"},
		{UID: "c", AccessToken: "at-c", Proxy: "socks5h://10.9.0.2:1080"},
	}
	p.SyncToDir(incoming)
	if key, dup := duplicateProxyKey(p); dup {
		t.Fatalf("duplicate proxy key %q entered the pool", key)
	}
	// Fail closed: the loser of a duplicate binding is not admitted at all. Admitting it
	// as direct would put two accounts on the host's shared exit, which is worse than
	// leaving it out (and the panel logs an ERROR for the operator).
	if total, _, _, _, _, _ := p.CountsDetailedWithPaused(); total != 2 {
		t.Fatalf("accounts=%d want 2 (conflicting newcomer refused)", total)
	}
	owner := ""
	for _, uid := range []string{"a", "b"} {
		if a := p.AuthByUID(uid); a != nil && auth.ProxyKey(a.ProxyValue()) != "" {
			if owner != "" {
				t.Fatalf("both a and b kept the same binding")
			}
			owner = uid
		}
	}
	if owner == "" {
		t.Fatal("no account kept the shared binding")
	}
	if p.AuthByUID("c") == nil {
		t.Fatal("unrelated account must still load")
	}
}

func TestSyncToDirKeepsPreviousBindingWhenIncomingConflicts(t *testing.T) {
	p := New("")
	p.SyncToDir([]*auth.Auth{
		{UID: "a", AccessToken: "at-a", Proxy: "socks5h://10.9.1.1:1080"},
		{UID: "b", AccessToken: "at-b", Proxy: "socks5h://10.9.1.2:1080"},
	})
	// b now arrives with a's key: b must keep its previous distinct binding rather
	// than silently borrowing a's exit IP.
	p.SyncToDir([]*auth.Auth{
		{UID: "a", AccessToken: "at-a2", Proxy: "socks5h://10.9.1.1:1080"},
		{UID: "b", AccessToken: "at-b2", Proxy: "socks5h://10.9.1.1:1080"},
	})
	if key, dup := duplicateProxyKey(p); dup {
		t.Fatalf("duplicate proxy key %q after reload", key)
	}
	if got := auth.ProxyKey(p.AuthByUID("b").ProxyValue()); got != "10.9.1.2:1080" && got != "@10.9.1.2:1080" {
		t.Fatalf("b kept %q, want its previous 10.9.1.2 binding", got)
	}
}

func TestSyncToDirDropsInvalidBinding(t *testing.T) {
	p := New("")
	p.SyncToDir([]*auth.Auth{{UID: "a", AccessToken: "at-a", Proxy: "socks5h://10.9.2.1:1080"}})
	p.SyncToDir([]*auth.Auth{{UID: "a", AccessToken: "at-a", Proxy: "ftp://10.9.2.1:21"}})
	if key, dup := duplicateProxyKey(p); dup {
		t.Fatalf("duplicate proxy key %q", key)
	}
	if got := p.AuthByUID("a").ProxyValue(); got != "socks5h://10.9.2.1:1080" {
		t.Fatalf("invalid incoming binding replaced a valid one: %q", got)
	}
}
