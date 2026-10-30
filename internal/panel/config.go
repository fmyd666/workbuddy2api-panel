// config.go 面板配置页接口：读取当前配置、校验并保存（热生效 + 重启项标注）。
//
// 分工：cmd/server 持有 Config 类型与校验逻辑（Load/normalize），此处只做
// HTTP 编排——GET 回显、POST 透传给注入的 SaveConfig 闭包（由 main 完成
// "校验 → 落盘 → 热应用 → 返回需重启字段列表"）。
package panel

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// getConfig 返回当前配置文件内容与路径（前端按 schema 渲染表单）。
func (p *Panel) getConfig(w http.ResponseWriter, r *http.Request) {
	if p.cfg.LoadConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		log.Printf("panel: load config failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "config_load_failed")
		return
	}
	safeCfg, redacted, configured, err := panelConfigResponse(cfg)
	if err != nil {
		log.Printf("panel: sanitize config failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "config_unavailable")
		return
	}
	apiKeySource := "unset"
	if os.Getenv("WB2A_API_KEY") != "" {
		apiKeySource = "environment"
	} else if containsString(configured, "api_key") {
		apiKeySource = "file"
	}
	promptFileSource := "unset"
	if os.Getenv("WB2A_PROMPT_FILE") != "" {
		promptFileSource = "environment"
	} else if containsString(configured, "prompt.file") {
		promptFileSource = "file"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"path":               filepath.Base(p.cfg.ConfigPath),
		"config":             safeCfg,
		"redacted_fields":    redacted,
		"configured_fields":  configured,
		"api_key_source":     apiKeySource,
		"prompt_file_source": promptFileSource,
	})
}

// panelConfigResponse deliberately omits secrets and local filesystem paths. The
// config editor submits only changed form fields; omitted keys remain preserved by
// saveConfig's deep merge, so hiding a secret here cannot clear it accidentally.
var panelConfigRedactedFields = []string{
	"api_key", "auth_dir", "state_file",
	"upstream.device_token", "upstream.device_token_file",
	"upstash.url", "upstash.token", "prompt.file",
}

func panelConfigResponse(cfg any) (map[string]any, []string, []string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil, nil, err
	}
	configured := configuredConfigFields(out)
	delete(out, "api_key")
	delete(out, "auth_dir")
	delete(out, "state_file")
	if upstream, ok := out["upstream"].(map[string]any); ok {
		delete(upstream, "device_token")
		delete(upstream, "device_token_file")
		for _, key := range []string{"chat_base", "billing_base"} {
			if value, ok := upstream[key].(string); ok && value != "" {
				upstream[key] = safeEndpoint(value)
			}
		}
	}
	if global, ok := out["global"].(map[string]any); ok {
		for _, key := range []string{"chat_base", "billing_base"} {
			if value, ok := global[key].(string); ok && value != "" {
				global[key] = safeEndpoint(value)
			}
		}
	}
	if cn, ok := out["cn"].(map[string]any); ok {
		if value, ok := cn["chat_base"].(string); ok && value != "" {
			cn["chat_base"] = safeEndpoint(value)
		}
	}
	if upstash, ok := out["upstash"].(map[string]any); ok {
		delete(upstash, "url")
		delete(upstash, "token")
	}
	if prompt, ok := out["prompt"].(map[string]any); ok {
		delete(prompt, "file")
	}
	return out, append([]string(nil), panelConfigRedactedFields...), configured, nil
}

func configuredConfigFields(out map[string]any) []string {
	var fields []string
	for _, field := range panelConfigRedactedFields {
		parts := strings.Split(field, ".")
		value := any(out)
		for _, part := range parts {
			group, ok := value.(map[string]any)
			if !ok {
				value = nil
				break
			}
			value = group[part]
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			fields = append(fields, field)
		}
	}
	return fields
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func safeEndpoint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return "[configured]"
	}
	host := strings.ToLower(u.Hostname())
	if u.Port() != "" {
		host = net.JoinHostPort(host, u.Port())
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

// saveConfig 保存配置：body 直接是配置 JSON（前端按 schema 组装完整对象）。
// SaveConfig 闭包内部完成校验+落盘+热应用；校验失败返回 400 且不写盘。
func (p *Panel) saveConfig(w http.ResponseWriter, r *http.Request) {
	if p.cfg.SaveConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		log.Printf("panel: read config body failed: %v", err)
		writeErr(w, http.StatusBadRequest, "config_request_invalid")
		return
	}
	if !json.Valid(raw) {
		writeErr(w, http.StatusBadRequest, "config_request_invalid")
		return
	}
	restartRequired, err := p.cfg.SaveConfig(raw)
	if err != nil {
		log.Printf("panel: save config failed: %v", err)
		writeErr(w, http.StatusBadRequest, "config_save_failed")
		return
	}
	if restartRequired == nil {
		restartRequired = []string{}
	}
	log.Printf("panel: 配置已保存（热生效完成；需重启字段 %d 个）", len(restartRequired))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restart_required": restartRequired,
	})
}
