package panel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

const maxProxyImportBytes = 2 << 20
const proxyFetchTimeout = 12 * time.Second

type proxySubscriptionFetchError struct {
	code string
}

func (e *proxySubscriptionFetchError) Error() string { return e.code }

func subscriptionFetchFailure(code string) error {
	return &proxySubscriptionFetchError{code: code}
}

func subscriptionFetchFailureCode(err error) string {
	var fetchErr *proxySubscriptionFetchError
	if errors.As(err, &fetchErr) && fetchErr.code != "" {
		return fetchErr.code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request_timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "request_timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_failed"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network_error"
	}
	return "upstream_unavailable"
}

type proxyInventory struct {
	mu      sync.Mutex
	path    string
	items   map[string]proxyEntry
	loadErr error
}
type proxyEntry struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Raw        string           `json:"raw"`
	Type       string           `json:"type"`
	Selectable bool             `json:"selectable"`
	LastTest   *proxyTestResult `json:"last_test,omitempty"`
}
type proxyTestResult struct {
	OK        bool      `json:"ok"`
	LatencyMS int64     `json:"latency_ms"`
	ExitIP    string    `json:"exit_ip,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}
type proxyInventoryDTO struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Proxy      string           `json:"proxy"`
	Type       string           `json:"type"`
	Selectable bool             `json:"selectable"`
	BoundUIDs  []string         `json:"bound_uids"`
	LastTest   *proxyTestResult `json:"last_test,omitempty"`
}

func validProxyInventoryEntry(e proxyEntry) bool {
	if !validProxyID(e.ID) || e.Raw == "" {
		return false
	}
	if len(e.ID) == 20 && e.ID != legacyProxyID(e.Raw) {
		return false
	}
	u, err := url.Parse(e.Raw)
	if err != nil || u == nil || u.Hostname() == "" || u.Port() == "" {
		return false
	}
	if e.Selectable {
		stored, _, err := auth.NormalizeProxy(e.Raw)
		return err == nil && stored == e.Raw && proxyType(e.Raw) == e.Type
	}
	if strings.ToLower(u.Scheme) != e.Type {
		return false
	}
	switch e.Type {
	case "anytls", "ss", "trojan", "vless", "vmess":
		return true
	default:
		return false
	}
}

func newProxyInventory(path string) *proxyInventory {
	i := &proxyInventory{path: path, items: map[string]proxyEntry{}}
	if path == "" {
		return i
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return i
	}
	if err != nil {
		i.loadErr = err
		return i
	}
	var items []proxyEntry
	if err = json.Unmarshal(b, &items); err != nil || items == nil {
		i.loadErr = errors.New("invalid proxy inventory file")
		return i
	}
	legacyIDs := false
	for _, e := range items {
		if !validProxyInventoryEntry(e) {
			i.loadErr = errors.New("invalid proxy inventory file")
			i.items = map[string]proxyEntry{}
			return i
		}
		if _, duplicate := i.items[e.ID]; duplicate {
			i.loadErr = errors.New("invalid proxy inventory file")
			i.items = map[string]proxyEntry{}
			return i
		}
		if len(e.ID) == 20 {
			// Migrate legacy SHA-derived public IDs so credentials are no longer exposed to
			// offline guessing through an unsalted digest.
			newID := proxyID(e.Raw)
			if newID == "" {
				i.loadErr = errors.New("proxy inventory ID generation failed")
				i.items = map[string]proxyEntry{}
				return i
			}
			e.ID = newID
			legacyIDs = true
		}
		if _, duplicate := i.items[e.ID]; duplicate {
			i.loadErr = errors.New("invalid proxy inventory file")
			i.items = map[string]proxyEntry{}
			return i
		}
		i.items[e.ID] = e
	}
	if legacyIDs {
		if err := i.persistLocked(); err != nil {
			i.loadErr = errors.New("proxy inventory migration failed")
			i.items = map[string]proxyEntry{}
			return i
		}
	}
	return i
}
func (i *proxyInventory) persistLocked() error {
	if i.path == "" {
		return errors.New("proxy inventory persistence path unavailable")
	}
	items := make([]proxyEntry, 0, len(i.items))
	for _, e := range i.items {
		items = append(items, e)
	}
	sort.Slice(items, func(a, b int) bool { return items[a].ID < items[b].ID })
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(i.path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(i.path), "."+filepath.Base(i.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err = tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, i.path)
}
func proxyID(_ string) string {
	// Opaque random IDs avoid exposing an offline verifier derived from credential-bearing URLs.
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(id[:])
}
func legacyProxyID(raw string) string {
	// Accept only the historical digest during one-time state migration; new IDs are random.
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:10])
}
func validProxyID(id string) bool {
	if len(id) != 32 && len(id) != 20 { // 20 hex chars are legacy IDs migrated on load.
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
func inventoryProxyKey(e proxyEntry) string {
	if !e.Selectable {
		return ""
	}
	return auth.ProxyKey(e.Raw)
}
func proxyType(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return "unknown"
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5h", "socks5":
		return strings.ToLower(u.Scheme)
	default:
		return strings.ToLower(u.Scheme)
	}
}
func redactProxy(raw string) string { return auth.RedactProxy(raw) }
func clashProxySectionHeader(trim string) bool {
	return trim == "proxies:" || strings.HasPrefix(trim, "proxies: #") || trim == "proxies: []" || strings.HasPrefix(trim, "proxies: [] #")
}
func hasRootClashProxySection(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if len(line) == len(strings.TrimLeft(line, " \t")) && clashProxySectionHeader(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}
func (p *Panel) inventory() *proxyInventory { return p.proxyInventoryStore }
func (p *Panel) proxyImport(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	var body struct {
		Text string `json:"text"`
		URL  string `json:"url"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&body) != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	text, subscriptionURL, err := normalizeProxyImportInput(body.Text, body.URL)
	if err != nil {
		writeErr(w, 400, "provide text or url")
		return
	}
	body.Text, body.URL = text, subscriptionURL
	content := body.Text
	if strings.TrimSpace(body.URL) != "" {
		var err error
		content, err = fetchProxySubscription(r.Context(), strings.TrimSpace(body.URL))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "subscription_fetch_failed: "+subscriptionFetchFailureCode(err))
			return
		}
	}
	if strings.TrimSpace(content) == "" {
		writeErr(w, 400, "empty import")
		return
	}
	parsed, unsupported, errorsList := parseProxyImport(content)
	i := p.inventory()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.loadErr != nil {
		writeErr(w, 500, "inventory unavailable")
		return
	}
	added, skipped := 0, 0
	var newlyAdded []string
	keys := make(map[string]struct{}, len(i.items))
	for _, existing := range i.items {
		if key := inventoryProxyKey(existing); key != "" {
			keys[key] = struct{}{}
		}
	}
	for _, e := range parsed {
		key := inventoryProxyKey(e)
		_, sameID := i.items[e.ID]
		_, sameEndpoint := keys[key]
		if sameID || (key != "" && sameEndpoint) {
			skipped++
			continue
		}
		i.items[e.ID] = e
		if key != "" {
			keys[key] = struct{}{}
		}
		newlyAdded = append(newlyAdded, e.ID)
		added++
	}
	if added > 0 {
		if err := i.persistLocked(); err != nil {
			for _, id := range newlyAdded {
				delete(i.items, id)
			}
			writeErr(w, 500, "inventory persistence failed")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "imported": added, "skipped": skipped, "unsupported": unsupported, "errors": errorsList})
}
func parseProxyImport(content string) ([]proxyEntry, []map[string]any, []map[string]any) {
	return parseProxyImportDepth(content, 0)
}

const maxProxyImportDepth = 5

func parseProxyImportDepth(content string, depth int) ([]proxyEntry, []map[string]any, []map[string]any) {
	content = strings.TrimSpace(content)
	if depth > maxProxyImportDepth {
		return nil, nil, []map[string]any{{"line": 0, "message": "base64 nesting too deep"}}
	}
	if len(content) > maxProxyImportBytes {
		return nil, nil, []map[string]any{{"line": 0, "message": "import too large"}}
	}
	if decoded, ok := decodeBase64Text(content); ok {
		return parseProxyImportDepth(decoded, depth+1)
	}
	if hasRootClashProxySection(content) {
		return parseClashImport(content)
	}
	// Parse one proxy per line after the optional subscription envelope.
	var entries []proxyEntry
	var unsupported, errs []map[string]any
	lines := strings.Split(content, "\n")
	if len(lines) > 10000 {
		return nil, nil, []map[string]any{{"line": 0, "message": "too many lines"}}
	}
	for n, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if lower := strings.ToLower(s); strings.HasPrefix(lower, "trojan://") || strings.HasPrefix(lower, "anytls://") {
			// 加密隧道协议：程序自己拨号，节点连同凭据一起入库（inventory 文件 0600）。
			name := ""
			if idx := strings.Index(s, "#"); idx >= 0 {
				if unescaped, err := url.PathUnescape(s[idx+1:]); err == nil {
					name = unescaped
				}
			}
			addProxyEntry(&entries, s, name, n+1, &errs)
			continue
		}
		if strings.HasPrefix(s, "vless://") || strings.HasPrefix(s, "vmess://") || strings.HasPrefix(s, "ss://") {
			typ := strings.ToLower(strings.SplitN(s, ":", 2)[0])
			unsupported = append(unsupported, map[string]any{"line": n + 1, "type": typ})
			continue
		}
		if decoded, ok := decodeBase64Text(s); ok {
			more, unsup, bad := parseProxyImportDepth(decoded, depth+1)
			entries = append(entries, more...)
			unsupported = append(unsupported, unsup...)
			errs = append(errs, bad...)
			continue
		}
		if strings.Count(s, ":") == 3 {
			parts := strings.SplitN(s, ":", 4)
			if port, err := strconv.Atoi(parts[1]); err == nil && port > 0 && port <= 65535 {
				u := url.UserPassword(parts[2], parts[3])
				addProxyEntry(&entries, "socks5://"+u.String()+"@"+net.JoinHostPort(parts[0], parts[1]), "", n+1, &errs)
				continue
			}
		}
		addProxyEntry(&entries, s, "", n+1, &errs)
	}
	return entries, unsupported, errs
}
func addProxyEntry(entries *[]proxyEntry, raw, name string, line int, errs *[]map[string]any) {
	stored, _, err := auth.NormalizeProxy(raw)
	if err != nil {
		*errs = append(*errs, map[string]any{"line": line, "message": "invalid or unsupported proxy"})
		return
	}
	name = safeProxyName(name, stored)
	id := proxyID(stored)
	if id == "" {
		*errs = append(*errs, map[string]any{"line": line, "message": "proxy ID generation failed"})
		return
	}
	*entries = append(*entries, proxyEntry{ID: id, Name: name, Raw: stored, Type: proxyType(stored), Selectable: true})
}
func (p *Panel) proxies(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	i := p.inventory()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.loadErr != nil {
		writeErr(w, 500, "inventory unavailable")
		return
	}
	bound := map[string][]string{}
	for _, a := range p.cfg.Pool.List() {
		if account := p.cfg.Pool.AuthByUID(a.UID); account != nil {
			if raw := account.ProxyValue(); raw != "" {
				bound[auth.ProxyKey(raw)] = append(bound[auth.ProxyKey(raw)], a.UID)
			}
		}
	}
	out := make([]proxyInventoryDTO, 0, len(i.items))
	for _, e := range i.items {
		uids := bound[inventoryProxyKey(e)]
		sort.Strings(uids)
		out = append(out, proxyInventoryDTO{ID: e.ID, Name: e.Name, Proxy: redactProxy(e.Raw), Type: e.Type, Selectable: e.Selectable, BoundUIDs: uids, LastTest: e.LastTest})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	writeJSON(w, 200, map[string]any{"ok": true, "proxies": out})
}
func (p *Panel) deleteProxy(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	p.proxyOpMu.Lock()
	defer p.proxyOpMu.Unlock()
	id := r.PathValue("id")
	i := p.inventory()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.loadErr != nil {
		writeErr(w, 500, "inventory unavailable")
		return
	}
	e, exists := i.items[id]
	if !exists {
		writeErr(w, 404, "proxy not found")
		return
	}
	key := inventoryProxyKey(e)
	for _, status := range p.cfg.Pool.List() {
		if account := p.cfg.Pool.AuthByUID(status.UID); account != nil && key != "" && auth.ProxyKey(account.ProxyValue()) == key {
			writeErr(w, 409, "proxy is assigned")
			return
		}
	}
	if _, ok := i.items[id]; !ok {
		writeErr(w, 404, "proxy not found")
		return
	}
	old := i.items[id]
	delete(i.items, id)
	if err := i.persistLocked(); err != nil {
		i.items[id] = old
		writeErr(w, 500, "inventory persistence failed")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (p *Panel) testProxy(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	id := r.PathValue("id")
	i := p.inventory()
	i.mu.Lock()
	if i.loadErr != nil {
		i.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, "inventory unavailable")
		return
	}
	e, ok := i.items[id]
	i.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "proxy not found")
		return
	}
	if !e.Selectable {
		writeErr(w, http.StatusBadRequest, "unsupported proxy")
		return
	}
	t0 := time.Now()
	probeBudget := 7 * time.Second
	if scheme, _, normErr := auth.NormalizeProxy(e.Raw); normErr == nil && (scheme == "trojan" || scheme == "anytls") {
		probeBudget = 14 * time.Second // 隧道多一次 TLS + 认证，放宽探测预算
	}
	ctx, cancel := context.WithTimeout(r.Context(), probeBudget)
	defer cancel()
	exitIP, probeErr := probeProxyExitIP(ctx, e.Raw)
	result := proxyTestResult{OK: probeErr == nil, ExitIP: exitIP, LatencyMS: time.Since(t0).Milliseconds(), CheckedAt: time.Now().UTC()}
	p.proxyOpMu.Lock()
	defer p.proxyOpMu.Unlock()
	i.mu.Lock()
	current, exists := i.items[id]
	if !exists || current.Raw != e.Raw {
		i.mu.Unlock()
		writeErr(w, http.StatusConflict, "proxy changed during test")
		return
	}
	previous := current.LastTest
	current.LastTest = &result
	i.items[id] = current
	persistErr := i.persistLocked()
	if persistErr != nil {
		current.LastTest = previous
		i.items[id] = current
	}
	i.mu.Unlock()
	if persistErr != nil {
		writeErr(w, http.StatusInternalServerError, "inventory persistence failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}
func setNoStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

type subscriptionResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func resolvePublicSubscriptionHost(ctx context.Context, resolver subscriptionResolver, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicAddr(ip) {
			return nil, subscriptionFetchFailure("blocked_address")
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, subscriptionFetchFailure("dns_failed")
	}
	for _, ip := range ips {
		if !publicAddr(ip) {
			return nil, subscriptionFetchFailure("blocked_address")
		}
	}
	return ips, nil
}

func validateSubscriptionURL(ctx context.Context, resolver subscriptionResolver, u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
		return subscriptionFetchFailure("invalid_url")
	}
	_, err := resolvePublicSubscriptionHost(ctx, resolver, u.Hostname())
	return err
}

func checkProxySubscriptionRedirect(resolver subscriptionResolver, req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return subscriptionFetchFailure("too_many_redirects")
	}
	return validateSubscriptionURL(req.Context(), resolver, req.URL)
}

type subscriptionDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func proxySubscriptionTransport(resolver subscriptionResolver, dialer subscriptionDialer) *http.Transport {
	return &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := resolvePublicSubscriptionHost(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}}
}

func fetchProxySubscription(ctx context.Context, raw string) (string, error) {
	return fetchProxySubscriptionWith(ctx, raw, net.DefaultResolver, &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second})
}

func fetchProxySubscriptionWith(ctx context.Context, raw string, resolver subscriptionResolver, dialer subscriptionDialer) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", subscriptionFetchFailure("invalid_url")
	}
	if err := validateSubscriptionURL(ctx, resolver, u); err != nil {
		return "", err
	}
	if dialer == nil {
		return "", subscriptionFetchFailure("network_error")
	}
	transport := proxySubscriptionTransport(resolver, dialer)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: proxyFetchTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return checkProxySubscriptionRedirect(resolver, req, via)
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", subscriptionFetchFailure("invalid_url")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", subscriptionFetchFailure(subscriptionFetchFailureCode(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", subscriptionFetchFailure("upstream_http_" + strconv.Itoa(resp.StatusCode))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyImportBytes+1))
	if err != nil {
		return "", subscriptionFetchFailure("response_read_failed")
	}
	if len(b) > maxProxyImportBytes {
		return "", subscriptionFetchFailure("response_too_large")
	}
	return string(b), nil
}

func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	blocked := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("168.63.129.16/32"), netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("2001:db8::/32"),
		// Well-known and local-use NAT64 prefixes can translate an apparently public IPv6
		// destination into a private IPv4 target behind a translator.
		netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	}
	for _, prefix := range blocked {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
