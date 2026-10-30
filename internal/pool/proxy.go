package pool

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// ErrAccountNotFound 面板按 UID 改代理时账号不在池里。
var ErrAccountNotFound = fmt.Errorf("account not found")

// ProxyBind 一次成功绑定。Proxy 是打码后的 URL，面板可直接展示。
type ProxyBind struct {
	UID   string `json:"uid"`
	Proxy string `json:"proxy"`
}

// SetAccountProxy 把一个账号绑到一条出口，或传空串改回直连。
// 同一 user@host:port 不能绑两个号。写入失败时内存回滚，不留半更新。
// 返回值是打码后的代理（直连为空串）。
func (p *Pool) SetAccountProxy(uid, raw string) (string, error) {
	uid = strings.TrimSpace(uid)
	stored, key, err := auth.NormalizeProxy(raw)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok {
		return "", ErrAccountNotFound
	}
	if key != "" {
		if owner := p.proxyOwnerLocked(key, uid); owner != "" {
			return "", fmt.Errorf("proxy already bound to %s", owner)
		}
	}
	a := e.a
	a.Lock()
	prev := a.Proxy
	a.Proxy = stored
	a.Unlock()
	if err := a.SaveAtomic(); err != nil {
		a.Lock()
		a.Proxy = prev
		a.Unlock()
		return "", err
	}
	log.Printf("INFO: [pool] proxy uid=%s %s", uid, proxyLog(stored))
	return auth.RedactProxy(stored), nil
}

// AssignProxies 把多行代理按 UID 顺序绑到还没有出口的账号。
// 空行和 # 注释跳过。输入里的重复、或已经绑在别的号上的出口，整批拒绝，不部分写入。
// 代理比空号多时，多出来的不绑；空号比代理多时，剩下的保持直连。
func (p *Pool) AssignProxies(lines []string) ([]ProxyBind, error) {
	type item struct {
		stored string
		key    string
	}
	var items []item
	seen := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		stored, key, err := auth.NormalizeProxy(line)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy on input line %d: %w", len(items)+1, err)
		}
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate proxy in input: %s", auth.RedactProxy(stored))
		}
		seen[key] = struct{}{}
		items = append(items, item{stored: stored, key: key})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no proxies")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	used := map[string]string{}
	var free []string
	for uid, e := range p.byUID {
		if k := auth.ProxyKey(e.a.ProxyValue()); k != "" {
			used[k] = uid
			continue
		}
		free = append(free, uid)
	}
	sort.Strings(free)
	for _, it := range items {
		if owner, ok := used[it.key]; ok {
			return nil, fmt.Errorf("proxy already bound to %s", owner)
		}
	}
	n := len(items)
	if n > len(free) {
		n = len(free)
	}
	type bind struct {
		uid    string
		stored string
		prev   string
		a      *auth.Auth
	}
	binds := make([]bind, 0, n)
	for i := 0; i < n; i++ {
		e := p.byUID[free[i]]
		e.a.Lock()
		prev := e.a.Proxy
		e.a.Proxy = items[i].stored
		e.a.Unlock()
		binds = append(binds, bind{uid: free[i], stored: items[i].stored, prev: prev, a: e.a})
	}

	out := make([]ProxyBind, 0, len(binds))
	accounts := make([]*auth.Auth, len(binds))
	for i := range binds {
		accounts[i] = binds[i].a
	}
	if err := auth.SaveAtomicBatch(accounts); err != nil {
		for _, b := range binds {
			b.a.Lock()
			b.a.Proxy = b.prev
			b.a.Unlock()
		}
		return nil, fmt.Errorf("save proxy assignment batch: %w", err)
	}
	for _, b := range binds {
		out = append(out, ProxyBind{UID: b.uid, Proxy: auth.RedactProxy(b.stored)})
		log.Printf("INFO: [pool] proxy uid=%s %s", b.uid, proxyLog(b.stored))
	}
	return out, nil
}

func (p *Pool) proxyOwnerLocked(key, exceptUID string) string {
	for uid, e := range p.byUID {
		if uid == exceptUID {
			continue
		}
		if auth.ProxyKey(e.a.ProxyValue()) == key {
			return uid
		}
	}
	return ""
}

func proxyLog(stored string) string {
	if stored == "" {
		return "direct"
	}
	return auth.RedactProxy(stored)
}
