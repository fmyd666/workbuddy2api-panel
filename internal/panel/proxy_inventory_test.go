package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
)

func TestNormalizeProxyImportInput(t *testing.T) {
	cases := []struct {
		name, text, rawURL, wantText, wantURL string
		wantErr                               bool
	}{
		{name: "dedicated url", rawURL: " https://example.test/feed?token=x ", wantURL: "https://example.test/feed?token=x"},
		{name: "pasted url in textarea", text: "  https://example.test/feed?token=x  ", wantURL: "https://example.test/feed?token=x"},
		{name: "plain http proxy remains text", text: "http://proxy.example:8080", wantText: "http://proxy.example:8080"},
		{name: "ported proxy path is still text", text: "http://proxy.example:8080/path?token=x", wantText: "http://proxy.example:8080/path?token=x"},
		{name: "default https port path is still text", text: "https://proxy.example:443/path", wantText: "https://proxy.example:443/path"},
		{name: "raw proxy content", text: "socks5://proxy.example:1080", wantText: "socks5://proxy.example:1080"},
		{name: "same both fields rejected backend", text: "https://example.test/feed", rawURL: "https://example.test/feed", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, rawURL, err := normalizeProxyImportInput(tc.text, tc.rawURL)
			if (err != nil) != tc.wantErr || text != tc.wantText || rawURL != tc.wantURL {
				t.Fatalf("got text=%q url=%q err=%v", text, rawURL, err)
			}
		})
	}
}

func TestProxyImportFormatsAndRedaction(t *testing.T) {
	input := "http://user:secret@proxy.example:8080/path?token=hidden\n127.0.0.1:1080:alice:pass%3Aword\nanytls://alice:secret@edge.example:443?token=hidden"
	entries, unsupported, errs := parseProxyImport(input)
	// anytls 现在是可绑定的隧道协议（程序自己拨号），所以三条都能入库。
	if len(entries) != 3 || len(unsupported) != 0 || len(errs) != 0 {
		t.Fatalf("entries=%d unsupported=%v errors=%v", len(entries), unsupported, errs)
	}
	got := redactProxy(entries[0].Raw)
	if strings.Contains(got, "secret") || strings.Contains(got, "token") || strings.Contains(got, "/path") {
		t.Fatalf("unredacted display %q", got)
	}
	if entries[1].Type != "socks5h" || !strings.Contains(entries[1].Raw, "alice:pass%253Aword") {
		t.Fatalf("host:port:user:pass parse: %+v", entries[1])
	}
	if entries[2].Type != "anytls" || !entries[2].Selectable {
		t.Fatalf("anytls node should be a selectable tunnel: %+v", entries[2])
	}
	if got := redactProxy(entries[2].Raw); strings.Contains(got, "secret") || strings.Contains(got, "token") {
		t.Fatalf("anytls display leaked credentials: %q", got)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("socks5://u:p@proxy.example:1081"))
	gotEntries, _, errs := parseProxyImport(encoded)
	if len(gotEntries) != 1 || len(errs) != 0 {
		t.Fatalf("base64 result=%+v errors=%v", gotEntries, errs)
	}
	deep := encoded
	for n := 0; n < maxProxyImportDepth+3; n++ {
		deep = base64.StdEncoding.EncodeToString([]byte(deep))
	}
	_, _, errs = parseProxyImport(deep)
	if len(errs) == 0 || errs[0]["message"] != "base64 nesting too deep" {
		t.Fatalf("expected depth limit error, got %v", errs)
	}
	_, _, errs = parseProxyImport(strings.Repeat("x", maxProxyImportBytes+1))
	if len(errs) == 0 {
		t.Fatal("expected oversized import error")
	}
}

func TestClashImportBlockFlowQuotesAndBoundary(t *testing.T) {
	content := strings.Join([]string{
		"mixed-port: 7890", "proxies:",
		"  - name: \"primary, west\"", "    type: http", "    server: proxy.example", "    port: 8080",
		"    username: \"user:a\"", "    password: \"secret,with,commas\"",
		"  - {name: 'flow, east', type: socks5, server: socks.example, port: 1080, username: flow, password: 'p,ass'}",
		"proxy-groups:", "  - name: fallback", "    type: select", "    proxies: [primary, west]",
	}, "\n")
	entries, _, errs := parseProxyImport(content)
	if len(entries) != 2 || len(errs) != 0 {
		t.Fatalf("Clash entries=%+v errors=%v", entries, errs)
	}
	if entries[0].Name != "primary, west" || !strings.Contains(entries[0].Raw, "user%3Aa") {
		t.Fatalf("quoted block parse %+v", entries[0])
	}
	if entries[1].Name != "flow, east" || !strings.Contains(entries[1].Raw, "p,ass") {
		t.Fatalf("flow map parse %+v", entries[1])
	}
	plain := "http://proxy.example:8080/proxies:label"
	if hasRootClashProxySection(plain) {
		t.Fatal("plain proxy falsely classified as Clash")
	}
	got, _, errs := parseProxyImport(plain)
	if len(got) != 1 || len(errs) != 0 {
		t.Fatalf("plain proxy dispatch got=%+v errs=%v", got, errs)
	}
	boundary := strings.Join([]string{"proxies:", "  - {name: one, type: http, server: one.example, port: 80}", "other:", "  - name: ignored", "    type: socks5", "    server: ignored.example", "    port: 1080"}, "\n")
	got, _, errs = parseProxyImport(boundary)
	if len(got) != 1 || len(errs) != 0 {
		t.Fatalf("section boundary got=%+v errs=%v", got, errs)
	}
}

func TestProxyInventoryCorruptStateAndPersistenceRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{\"not\":\"an array\"}"), 0600); err != nil {
		t.Fatal(err)
	}
	inv := newProxyInventory(path)
	if inv.loadErr == nil {
		t.Fatal("non-array state should be rejected")
	}
	p := New(Config{Pool: pool.New(""), ProxyFile: path})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/api/proxies", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt state status=%d body=%s", rec.Code, rec.Body.String())
	}
	dir := t.TempDir()
	p = New(Config{Pool: pool.New(""), ProxyFile: filepath.Join(dir, "proxies.json")})
	inv = p.inventory()
	inv.mu.Lock()
	inv.path = dir
	inv.mu.Unlock()
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/panel/api/proxies/import", strings.NewReader("{\"text\":\"http://proxy.example:8080\"}")))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence failure got %d: %s", rec.Code, rec.Body.String())
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if len(inv.items) != 0 {
		t.Fatalf("failed import left entries: %+v", inv.items)
	}
}

func TestProxyInventoryBindCanonicalDeleteAndDuplicate(t *testing.T) {
	dir := t.TempDir()
	pl := pool.New("")
	a := &auth.Auth{UID: "u1", AccessToken: "token", FilePath: filepath.Join(dir, "auth.json")}
	pl.Add(a)
	p := New(Config{Pool: pl, ProxyFile: filepath.Join(dir, "proxies.json")})
	importBody := "{\"text\":\"socks5h://user:pass@proxy.example:1080\"}"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/panel/api/proxies/import", strings.NewReader(importBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response["imported"] != float64(1) {
		t.Fatalf("import response=%v err=%v", response, err)
	}
	inv := p.inventory()
	inv.mu.Lock()
	var id string
	for id = range inv.items {
		break
	}
	inv.mu.Unlock()
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/panel/api/accounts/u1/proxy", strings.NewReader("{\"proxy_id\":\""+id+"\"}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("select status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := a.ProxyValue(); got != "socks5h://user:pass@proxy.example:1080" {
		t.Fatalf("selected proxy=%q", got)
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/panel/api/proxies/"+id, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("canonical bound delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/panel/api/proxies/import", strings.NewReader(importBody)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "\"skipped\":1") {
		t.Fatalf("duplicate not skipped status=%d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubscriptionAddressDenylistAndURLValidation(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "168.63.129.16", "2001:db8::1", "::1"} {
		if publicAddr(netip.MustParseAddr(raw)) {
			t.Errorf("publicAddr(%s)=true", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicAddr(netip.MustParseAddr(raw)) {
			t.Errorf("publicAddr(%s)=false", raw)
		}
	}
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	u, _ := url.Parse("https://example.test/feed")
	if validateSubscriptionURL(context.Background(), resolver, u) == nil {
		t.Fatal("private DNS answer accepted")
	}
	u, _ = url.Parse("https://user:secret@example.test/feed")
	if validateSubscriptionURL(context.Background(), resolver, u) == nil {
		t.Fatal("userinfo accepted")
	}
	u, _ = url.Parse("file:///etc/passwd")
	if validateSubscriptionURL(context.Background(), resolver, u) == nil {
		t.Fatal("non-http scheme accepted")
	}
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type failDialer struct {
	got []string
}

func (d *failDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.got = append(d.got, network+" "+address)
	return nil, os.ErrPermission
}

func TestSubscriptionFetchFailureClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "blocked address", err: subscriptionFetchFailure("blocked_address"), want: "blocked_address"},
		{name: "redirect cap", err: subscriptionFetchFailure("too_many_redirects"), want: "too_many_redirects"},
		{name: "timeout", err: context.DeadlineExceeded, want: "request_timeout"},
		{name: "dns", err: &net.DNSError{Err: "lookup failed", Name: "secret.example"}, want: "dns_failed"},
		{name: "connection reset", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection reset")}, want: "network_error"},
		{name: "opaque", err: errors.New("opaque"), want: "upstream_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := subscriptionFetchFailureCode(tc.err); got != tc.want {
				t.Fatalf("failure code=%q want %q", got, tc.want)
			}
			if strings.Contains(subscriptionFetchFailureCode(tc.err), "secret") {
				t.Fatal("failure code must not include source URL data")
			}
		})
	}
}

func TestSubscriptionFetchHandlerDoesNotEchoURL(t *testing.T) {
	secretURL := "https://example.test/feed?token=do-not-echo"
	p := New(Config{Pool: pool.New(""), ProxyFile: filepath.Join(t.TempDir(), "proxies.json")})
	rec := httptest.NewRecorder()
	body := `{"url":"` + secretURL + `"}`
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/panel/api/proxies/import", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "do-not-echo") || strings.Contains(rec.Body.String(), "example.test") {
		t.Fatalf("response echoed sensitive URL data: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "subscription_fetch_failed: ") {
		t.Fatalf("missing stable fetch error: %s", rec.Body.String())
	}
}

func TestSubscriptionRedirectPolicyAndPinnedDial(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	safe, _ := http.NewRequest(http.MethodGet, "https://example.test/next", nil)
	if err := checkProxySubscriptionRedirect(resolver, safe, []*http.Request{{}}); err != nil {
		t.Fatalf("safe redirect rejected: %v", err)
	}
	if err := checkProxySubscriptionRedirect(resolver, safe, []*http.Request{{}, {}, {}}); err == nil {
		t.Fatal("redirect limit not enforced")
	}
	privateResolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.7")}, nil
	})
	if err := checkProxySubscriptionRedirect(privateResolver, safe, []*http.Request{{}}); err == nil {
		t.Fatal("private redirect target accepted")
	}
	d := &failDialer{}
	tr := proxySubscriptionTransport(resolver, d)
	_, err := tr.DialContext(context.Background(), "tcp", "example.test:443")
	if err == nil {
		t.Fatal("stub dialer should fail")
	}
	if len(d.got) != 1 || d.got[0] != "tcp 1.1.1.1:443" {
		t.Fatalf("dial was not pinned to validated IP: %v", d.got)
	}
	d.got = nil
	tr = proxySubscriptionTransport(privateResolver, d)
	_, err = tr.DialContext(context.Background(), "tcp", "example.test:443")
	if err == nil || len(d.got) != 0 {
		t.Fatalf("private target reached dialer: err=%v calls=%v", err, d.got)
	}
}
