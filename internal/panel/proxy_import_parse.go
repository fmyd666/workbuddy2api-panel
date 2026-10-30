package panel

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// normalizeProxyImportInput accepts a whole HTTP(S) subscription URL pasted in either UI field.
// An explicit host:port is treated as a proxy endpoint even when it has a path/query;
// users can always use the dedicated URL field to disambiguate subscriptions on custom ports.
func normalizeProxyImportInput(text, rawURL string) (string, string, error) {
	text = strings.TrimSpace(text)
	rawURL = strings.TrimSpace(rawURL)
	if text != "" && rawURL != "" {
		return "", "", errors.New("provide text or url")
	}
	if rawURL == "" && text != "" {
		u, err := url.Parse(text)
		if err == nil && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Hostname() != "" && !hasExplicitURLPort(text) && (u.RawQuery != "" || (u.Path != "" && u.Path != "/")) {
			return "", text, nil
		}
	}
	return text, rawURL, nil
}

func hasExplicitURLPort(raw string) bool {
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		raw = raw[scheme+3:]
	}
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		raw = raw[at+1:]
	}
	if end := strings.IndexAny(raw, "/?#"); end >= 0 {
		raw = raw[:end]
	}
	if strings.HasPrefix(raw, "[") {
		close := strings.LastIndex(raw, "]")
		return close >= 0 && len(raw) > close+1 && raw[close+1] == ':'
	}
	return strings.LastIndex(raw, ":") > 0
}

// firstNonEmptyString returns the first non-empty value (Clash aliases password/passwd/auth).
func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func safeProxyName(name, raw string) string {
	name = strings.TrimSpace(name)
	lower := strings.ToLower(name)
	if name == "" || len(name) > 96 || strings.ContainsAny(name, "@:/?#=&%") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "passwd") {
		return redactProxy(raw)
	}
	return name
}

func decodeBase64Text(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil && len(b) > 0 && !strings.ContainsRune(string(b), 0) {
			return string(b), true
		}
	}
	return "", false
}

func parseClashPair(s string) (string, string, bool) {
	// Strip YAML comments only when they occur outside a quoted scalar.
	quote := byte(0)
	escaped := false
	for idx := 0; idx < len(s); idx++ {
		c := s[idx]
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' || c == '\'' {
			if quote == 0 {
				quote = c
			} else if quote == c {
				quote = 0
			}
			continue
		}
		if quote == 0 && c == '#' && (idx == 0 || s[idx-1] == ' ' || s[idx-1] == '\t') {
			s = strings.TrimRight(s[:idx], " \t")
			break
		}
	}
	quote = 0
	escaped = false
	for n := 0; n < len(s); n++ {
		c := s[n]
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' || c == '\'' {
			if quote == 0 {
				quote = c
			} else if quote == c {
				quote = 0
			}
			continue
		}
		if quote != 0 {
			continue
		}
		if c == ':' && quote == 0 {
			key := strings.TrimSpace(s[:n])
			value := strings.TrimSpace(s[n+1:])
			if value == "" {
				return "", "", false
			}
			if value[0] == '"' && len(value) >= 2 && value[len(value)-1] == '"' {
				if decoded, err := strconv.Unquote(value); err == nil {
					value = decoded
				}
			} else {
				value = strings.Trim(value, "'")
			}
			return key, value, key != ""
		}
	}
	return "", "", false
}

func parseClashFlowMap(s string) (map[string]string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, false
	}
	s = strings.TrimSpace(s[1 : len(s)-1])
	values := map[string]string{}
	if s == "" {
		return values, true
	}
	start, quote := 0, byte(0)
	escaped := false
	for n := 0; n <= len(s); n++ {
		if n < len(s) {
			c := s[n]
			if escaped {
				escaped = false
				continue
			}
			if quote == '"' && c == '\\' {
				escaped = true
				continue
			}
			if c == '"' || c == '\'' {
				if quote == 0 {
					quote = c
				} else if quote == c {
					quote = 0
				}
				continue
			}
			if quote != 0 || c != ',' {
				continue
			}
		}
		part := strings.TrimSpace(s[start:n])
		key, value, ok := parseClashPair(part)
		if !ok {
			return nil, false
		}
		values[key] = value
		start = n + 1
	}
	if quote != 0 {
		return nil, false
	}
	return values, true
}

func parseClashImport(content string) ([]proxyEntry, []map[string]any, []map[string]any) {
	lines := strings.Split(content, "\n")
	var entries []proxyEntry
	var unsupported, errs []map[string]any
	inBlock := false
	values := map[string]string{}
	startLine := 0
	flush := func() {
		if len(values) == 0 {
			return
		}
		line := startLine
		typ := strings.ToLower(values["type"])
		if typ == "ss" || typ == "vless" || typ == "vmess" || typ == "hysteria2" || typ == "tuic" {
			host, port := values["server"], values["port"]
			if host == "" || port == "" {
				errs = append(errs, map[string]any{"line": line, "message": "invalid unsupported proxy entry"})
				values = map[string]string{}
				return
			}
			// Unsupported nodes are reported by protocol only; never persist their raw
			// credential-bearing fields in the proxy inventory.
			unsupported = append(unsupported, map[string]any{"line": line, "type": typ})
			values = map[string]string{}
			return
		}
		if typ == "trojan" || typ == "anytls" {
			// 加密隧道协议：由程序自己拨号（见 upstream.ProxyTunnelDialer）。
			host, port := values["server"], values["port"]
			n, err := strconv.Atoi(port)
			password := firstNonEmptyString(values["password"], values["passwd"], values["auth"])
			if host == "" || err != nil || n < 1 || n > 65535 || strings.TrimSpace(password) == "" {
				errs = append(errs, map[string]any{"line": line, "message": "invalid tunnel proxy entry"})
				values = map[string]string{}
				return
			}
			u := url.URL{Scheme: typ, Host: net.JoinHostPort(host, port), User: url.User(password)}
			q := url.Values{}
			if sni := firstNonEmptyString(values["sni"], values["servername"], values["peer"]); sni != "" {
				q.Set("sni", sni)
			}
			if strings.EqualFold(values["skip-cert-verify"], "true") || strings.EqualFold(values["allowinsecure"], "true") {
				q.Set("verify", "0")
			}
			if len(q) > 0 {
				u.RawQuery = q.Encode()
			}
			stored, _, err := auth.NormalizeProxy(u.String())
			if err != nil {
				errs = append(errs, map[string]any{"line": line, "message": "invalid tunnel proxy entry"})
				values = map[string]string{}
				return
			}
			entries = append(entries, proxyEntry{ID: proxyID(stored), Name: safeProxyName(values["name"], stored), Raw: stored, Type: proxyType(stored), Selectable: true})
			values = map[string]string{}
			return
		}
		switch typ {
		case "socks5":
			typ = "socks5h"
		case "http", "https":
		default:
			errs = append(errs, map[string]any{"line": line, "message": "unsupported or invalid proxy entry"})
			values = map[string]string{}
			return
		}
		host, port := values["server"], values["port"]
		n, err := strconv.Atoi(port)
		if host == "" || err != nil || n < 1 || n > 65535 {
			errs = append(errs, map[string]any{"line": line, "message": "invalid proxy entry"})
			values = map[string]string{}
			return
		}
		raw := typ + "://" + net.JoinHostPort(host, port)
		if values["username"] != "" {
			u, _ := url.Parse(raw)
			u.User = url.UserPassword(values["username"], values["password"])
			raw = u.String()
		}
		stored, _, err := auth.NormalizeProxy(raw)
		if err != nil {
			errs = append(errs, map[string]any{"line": line, "message": "invalid or unsupported proxy"})
			values = map[string]string{}
			return
		}
		name := safeProxyName(values["name"], stored)
		entries = append(entries, proxyEntry{ID: proxyID(stored), Name: name, Raw: stored, Type: proxyType(stored), Selectable: true})
		values = map[string]string{}
	}
	for n, line := range lines {
		trim := strings.TrimSpace(line)
		if clashProxySectionHeader(trim) {
			if strings.HasPrefix(trim, "proxies: [") {
				// Flat inline proxy lists are YAML, not individual proxy records.
				flush()
				inBlock = false
				continue
			}
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if trim == "-" {
			flush()
			startLine = n + 1
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 && !strings.HasPrefix(trim, "-") {
			flush()
			inBlock = false
			continue
		}
		if strings.HasPrefix(trim, "-") {
			flush()
			startLine = n + 1
			trim = strings.TrimSpace(strings.TrimPrefix(trim, "-"))
			if flow, ok := parseClashFlowMap(trim); ok {
				values = flow
				flush()
				continue
			}
		}
		if key, value, ok := parseClashPair(trim); ok {
			values[key] = value
		}
	}
	flush()
	return entries, unsupported, errs
}
