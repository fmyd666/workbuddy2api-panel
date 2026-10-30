package upstream

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// proxyClients 一条出口代理独占的 HTTP / 聊天客户端。
// 必须与直连 Transport 分开：共享连接池按目标主机复用，两个号打到同一上游
// 会捡到同一条连接，IP 隔离就破了。
type proxyClients struct {
	http *http.Client
	chat *http.Client
}

// CloseIdleConnections releases keep-alive connections owned by this client.
// It covers the shared clients and every per-proxy client without dropping the
// proxy cache itself, so in-flight requests remain valid and future requests
// reuse the same isolated transport. Callers use this during config reload or
// graceful shutdown to avoid retaining old connections.
func (c *Client) CloseIdleConnections() {
	if c == nil {
		return
	}
	clients := make([]*http.Client, 0, 2)
	if c.HTTP != nil {
		clients = append(clients, c.HTTP)
	}
	if c.ChatHTTP != nil && c.ChatHTTP != c.HTTP {
		clients = append(clients, c.ChatHTTP)
	}
	c.proxyMu.Lock()
	for _, pair := range c.proxyCache {
		if pair == nil {
			continue
		}
		if pair.http != nil {
			clients = append(clients, pair.http)
		}
		if pair.chat != nil && pair.chat != pair.http {
			clients = append(clients, pair.chat)
		}
	}
	c.proxyMu.Unlock()
	for _, client := range clients {
		if client != nil {
			client.CloseIdleConnections()
		}
	}
}

// httpClientFor 返回该账号应使用的出站客户端。
//
// 未绑定代理：沿用共享客户端（含环境变量代理），与改前一致。
// 已绑定：只用该代理自己的 Transport。解析或拨号器构造失败时直接报错，
// 不回落直连——回落会把本该隔离的号暴露在同一出口上。
func (c *Client) httpClientFor(a *auth.Auth, chat bool) (*http.Client, error) {
	raw := ""
	if a != nil {
		raw = strings.TrimSpace(a.ProxyValue())
	}
	if raw == "" {
		if chat {
			return c.chatHTTP(), nil
		}
		return c.HTTP, nil
	}
	stored, _, err := auth.NormalizeProxy(raw)
	if err != nil {
		return nil, fmt.Errorf("account proxy refused (no direct fallback): %w", err)
	}
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	if c.proxyCache == nil {
		c.proxyCache = map[string]*proxyClients{}
	}
	pair := c.proxyCache[stored]
	if pair == nil {
		u, perr := url.Parse(stored)
		if perr != nil {
			return nil, fmt.Errorf("account proxy refused (no direct fallback): %w", perr)
		}
		tr, terr := c.transportFor(u)
		if terr != nil {
			return nil, fmt.Errorf("account proxy refused (no direct fallback): %w", terr)
		}
		timeout := 120 * time.Second
		if c != nil && c.HTTP != nil && c.HTTP.Timeout > 0 {
			timeout = c.HTTP.Timeout
		}
		pair = &proxyClients{
			http: &http.Client{Timeout: timeout, Transport: tr},
			chat: &http.Client{Timeout: 0, Transport: tr},
		}
		c.proxyCache[stored] = pair
	}
	if chat {
		return pair.chat, nil
	}
	return pair.http, nil
}

// do 用账号自己的出口发请求（JSON / 搜索 / 模型探测等非聊天长流）。
func (c *Client) do(a *auth.Auth, req *http.Request) (*http.Response, error) {
	hc, err := c.httpClientFor(a, false)
	if err != nil {
		return nil, err
	}
	return hc.Do(req)
}

func (c *Client) baseTransport() *http.Transport {
	if c != nil && c.HTTP != nil {
		if tr, ok := c.HTTP.Transport.(*http.Transport); ok && tr != nil {
			return tr.Clone()
		}
	}
	return newTransport()
}

func (c *Client) transportFor(u *url.URL) (*http.Transport, error) {
	tr := c.baseTransport()
	tr.Proxy = nil
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
		return tr, nil
	case "socks5", "socks5h":
		dialURL := *u
		dialURL.Scheme = "socks5"
		d, err := proxy.FromURL(&dialURL, proxy.Direct)
		if err != nil {
			return nil, err
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return d.Dial(network, addr)
		}
		return tr, nil
	case "trojan", "anytls":
		// 加密隧道协议：tr.Proxy 保持 nil（环境变量代理也不能介入），
		// 所有目标地址都由自带拨号器自己加密转发。
		dialTunnel, err := ProxyTunnelDialer(u.String())
		if err != nil {
			return nil, err
		}
		tr.DialContext = dialTunnel
		return tr, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}
