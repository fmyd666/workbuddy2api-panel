package panel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
)

// accountProxy 设置或清除单个账号的出口代理。body: {"proxy":"socks5://..."}，空串=直连。
func (p *Panel) accountProxy(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var body struct {
		Proxy   string `json:"proxy"`
		ProxyID string `json:"proxy_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p.proxyOpMu.Lock()
	defer p.proxyOpMu.Unlock()
	if body.ProxyID != "" && body.Proxy != "" {
		writeErr(w, http.StatusBadRequest, "provide proxy_id or proxy")
		return
	}
	raw := body.Proxy
	if body.ProxyID != "" {
		i := p.inventory()
		i.mu.Lock()
		e, ok := i.items[body.ProxyID]
		loadErr := i.loadErr
		i.mu.Unlock()
		if loadErr != nil {
			writeErr(w, http.StatusInternalServerError, "inventory unavailable")
			return
		}
		if !ok || !e.Selectable {
			writeErr(w, http.StatusNotFound, "proxy not found or unsupported")
			return
		}
		raw = e.Raw
	}
	redacted, err := p.cfg.Pool.SetAccountProxy(uid, raw)
	if err != nil {
		if errors.Is(err, pool.ErrAccountNotFound) {
			writeErr(w, http.StatusNotFound, "account not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uid": uid, "proxy": redacted})
}

// assignProxies 把多行代理按 UID 顺序绑到还没有出口的账号。
// body: {"text":"一行一个"} 或 {"proxies":["..."]}。
func (p *Panel) assignProxies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text    string   `json:"text"`
		Proxies []string `json:"proxies"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p.proxyOpMu.Lock()
	defer p.proxyOpMu.Unlock()
	lines := body.Proxies
	if strings.TrimSpace(body.Text) != "" {
		lines = append(lines, strings.Split(body.Text, "\n")...)
	}
	assigned, err := p.cfg.Pool.AssignProxies(lines)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "assigned": assigned, "count": len(assigned)})
}
