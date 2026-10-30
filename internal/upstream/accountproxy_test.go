package upstream

import (
	"net/http"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

func TestHTTPClientForDirectAndRefused(t *testing.T) {
	c := New()
	a := &auth.Auth{UID: "u", AccessToken: "at"}
	got, err := c.httpClientFor(a, false)
	if err != nil || got != c.HTTP {
		t.Fatalf("direct client=%v err=%v", got, err)
	}
	a.Proxy = "ftp://1.2.3.4:21"
	if _, err = c.httpClientFor(a, false); err == nil {
		t.Fatal("invalid proxy must fail closed")
	}
	a.Proxy = "http://127.0.0.1:9"
	hc, err := c.httpClientFor(a, false)
	if err != nil {
		t.Fatal(err)
	}
	if hc == c.HTTP {
		t.Fatal("proxied client must not share the direct client")
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatalf("http proxy transport missing Proxy func: %#v", hc.Transport)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	pu, err := tr.Proxy(req)
	if err != nil || pu.Host != "127.0.0.1:9" {
		t.Fatalf("proxy url=%v err=%v", pu, err)
	}
	chat, err := c.httpClientFor(a, true)
	if err != nil || chat.Timeout != 0 || chat.Transport != hc.Transport {
		t.Fatalf("chat client timeout=%s shared=%v err=%v", chat.Timeout, chat.Transport == hc.Transport, err)
	}
	if c.HTTP.Timeout != 120*time.Second {
		t.Fatalf("shared timeout changed: %s", c.HTTP.Timeout)
	}
}
