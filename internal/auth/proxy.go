package auth

import (
	"fmt"
	"net/url"
	"strings"
)

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// NormalizeProxy 把面板输入归一成可落盘的代理 URL，并给出一号一 IP 的占用键。
//
// 空串 = 直连（stored/key 都为空，不算错误）。
// 无 scheme 的 host:port 或 user:pass@host:port 按 socks5 处理（IP 列表最常见的写法）。
// socks5 升成 socks5h：域名解析走代理，避免本机 DNS 把账号关联到同一解析出口。
//
// 占用键是 user@host:port（不含 scheme、不含密码）。同一条出口不能绑两个号；
// 用户名不同视为不同会话（住宅代理常用用户名区分 IP），允许并存。
func NormalizeProxy(raw string) (stored, key string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Never include raw proxy input: it may contain a password.
		return "", "", fmt.Errorf("invalid proxy URL")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks5":
		scheme = "socks5h"
	case "socks5h", "http", "https":
	case "trojan", "anytls":
		// 协议自带加密隧道：userinfo 是节点密码，不是 session 用户名，绝不能进占用键。
	default:
		return "", "", fmt.Errorf("unsupported proxy scheme %q (use socks5, http, https, trojan, anytls)", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return "", "", fmt.Errorf("proxy must include host and port")
	}
	u.Scheme = scheme
	u.Fragment = ""
	if scheme == "trojan" || scheme == "anytls" {
		if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
			return "", "", fmt.Errorf("%s proxy requires a password", scheme)
		}
		// 占用键只含 host:port：同一落地节点不能给两个号，key 里不出现密码。
		return u.String(), strings.ToLower(host) + ":" + port, nil
	}
	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	return u.String(), strings.ToLower(user) + "@" + strings.ToLower(host) + ":" + port, nil
}

// ProxyKey 返回已落盘代理 URL 的占用键。空或无法解析时返回空（不参与占用）。
func ProxyKey(stored string) string {
	_, key, err := NormalizeProxy(stored)
	if err != nil {
		return ""
	}
	return key
}

// RedactProxy removes all credential and opaque URL components for panel display.
func RedactProxy(stored string) string {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return ""
	}
	u, err := url.Parse(stored)
	if err != nil || u.Host == "" {
		return "invalid"
	}
	maskedUser := u.User != nil
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	if maskedUser {
		return u.Scheme + "://****@" + u.Host
	}
	return u.Scheme + "://" + u.Host
}
