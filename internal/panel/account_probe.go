package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/logfmt"
	"github.com/fmyd666/workbuddy2api-panel/internal/upstream"
)

// accountTest 用一个账号真实跑一次对话，供面板「测试」按钮做连通性验证。
//
// 与「余额」「签到」不同，这里必须真的打一次 /v1/chat/completions：
// 只有真调用才能同时验证 token 有效、模型权限、代理出口与上游可用性。
// 因此固定小 max_tokens（默认 64）以控制积分消耗，并支持自定义提示词与模型。
type accountTestRequest struct {
	Model     string `json:"model"`
	Prompt    string `json:"prompt"`
	MaxTokens int    `json:"max_tokens"`
	Mode      string `json:"mode"`
}

type accountTestResponse struct {
	OK        bool     `json:"ok"`
	Model     string   `json:"model"`
	Reply     string   `json:"reply"`
	ElapsedMs int64    `json:"elapsed_ms"`
	Steps     []string `json:"steps"`
	Error     string   `json:"error,omitempty"`
}

func (p *Panel) accountTest(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if p.cfg.Upstream == nil {
		writeErr(w, http.StatusServiceUnavailable, "upstream unavailable")
		return
	}
	acct := p.cfg.Pool.AuthByUID(uid)
	if acct == nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	var body accountTestRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	}
	model := strings.TrimSpace(body.Model)
	if model == "" {
		model = "deepseek-v4.1-flash"
	}
	// 面板下拉给的是带 realm 前缀的路由名（cn:/global:）。前缀是网关侧的路由协议，
	// 上游只认裸名：/v1 正式链路在 handler 里 rewriteModel 后才出站，本测试链路直接
	// 调上游、不复用那段重写，必须在这里自己剥。否则稳定 11102
	// 「model [cn:xxx] service info not found」——线上 16 次 11102 全部是带前缀的名字。
	modelNote := ""
	if bare := bareTestModel(model); bare != model {
		model = bare
		modelNote = "（已剥去 realm 前缀，上游只认裸名）"
	}
	prompt := strings.TrimSpace(body.Prompt)
	if prompt == "" {
		prompt = "hi"
	}
	mode := strings.TrimSpace(body.Mode)
	if mode != "stream" {
		mode = "normal"
	}
	maxTokens := body.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 64
	}
	if maxTokens > 256 {
		maxTokens = 256
	}

	steps := []string{"开始测试账号: " + logfmt.Label(acct.UID, acct.Nickname), "账号类型: " + accountKind(acct)}
	if proxy := acct.ProxyValue(); proxy != "" {
		steps = append(steps, "出口代理: "+redactProxy(proxy))
	} else {
		steps = append(steps, "出口代理: 直连")
	}
	steps = append(steps, "使用模型: "+model+modelNote, "发送测试消息: \""+prompt+"\"", "正在通过 /v1/chat/completions 测试连接")

	payload, err := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens": maxTokens,
		"stream":     mode == "stream",
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build payload: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	start := time.Now()
	rc, status, respBody, err := p.cfg.Upstream.ChatStreamContext(ctx, acct, payload, "", upstream.ChatMeta{})
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, accountTestResponse{OK: false, Model: model, ElapsedMs: elapsed, Steps: steps,
			Error: "请求失败: " + describeTestError(err, respBody)})
		return
	}
	var raw []byte
	if rc != nil {
		defer rc.Close()
		raw, _ = io.ReadAll(io.LimitReader(rc, 1<<20))
	}
	if len(raw) == 0 {
		raw = respBody
	}
	if status != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		msg, truncated := truncateTestError(msg, 1200)
		errorText := "上游返回 " + http.StatusText(status) + " (" + itoa(status) + "): " + msg
		if truncated {
			errorText += "（错误内容较长，已安全截断；完整原因请查看运行日志）"
		}
		writeJSON(w, http.StatusOK, accountTestResponse{OK: false, Model: model, ElapsedMs: elapsed, Steps: steps,
			Error: errorText})
		return
	}

	reply := extractReply(raw)
	if reply == "" {
		reply = "(空响应)"
	}
	steps = append(steps, "已通过 /v1/chat/completions 验证", "响应:", reply, "✓ 测试完成!")
	writeJSON(w, http.StatusOK, accountTestResponse{OK: true, Model: model, Reply: reply, ElapsedMs: elapsed, Steps: steps})
}

// bareTestModel 剥去网关路由用的 realm 前缀（cn:/global:），返回上游认的裸模型名。
// 前缀必须是精确的小写枚举，与 /v1 的 resolveModel 同口径；非前缀冒号（模型名自带
// 冒号）原样保留。
func bareTestModel(model string) string {
	if i := strings.IndexByte(model, ':'); i > 0 {
		switch model[:i] {
		case "cn", "global":
			return model[i+1:]
		}
	}
	return model
}

// describeTestError 生成测试弹窗的错误文本。upstream.Error.Msg 为日志截断过
// （200 字节），这里改用完整响应体，并优先展示上游给出的中文 displayMsg。
func describeTestError(err error, body []byte) string {
	var ue *upstream.Error
	if !errors.As(err, &ue) || len(body) == 0 {
		return err.Error()
	}
	raw := strings.TrimSpace(string(body))
	var env struct {
		Code       int    `json:"code"`
		Msg        string `json:"msg"`
		DisplayMsg struct {
			Zh string `json:"zh"`
			En string `json:"en"`
		} `json:"displayMsg"`
	}
	head := "upstream " + ue.Kind.String() + " (http " + itoa(ue.Status) + ")"
	if json.Unmarshal(body, &env) == nil && (env.Msg != "" || env.DisplayMsg.Zh != "" || env.DisplayMsg.En != "") {
		var parts []string
		if s := env.DisplayMsg.Zh; s != "" {
			parts = append(parts, s)
		} else if s := env.DisplayMsg.En; s != "" {
			parts = append(parts, s)
		}
		if env.Code != 0 || env.Msg != "" {
			parts = append(parts, "code="+itoa(env.Code)+" msg="+env.Msg)
		}
		text, cut := truncateTestError(strings.Join(parts, "\n"), 1200)
		if cut {
			text += "（已截断）"
		}
		return head + ": " + text
	}
	text, cut := truncateTestError(raw, 1200)
	if cut {
		text += "（错误内容较长，已安全截断；完整原因请查看运行日志）"
	}
	return head + ": " + text
}

// truncateTestError 按 Unicode 字符而非 UTF-8 字节截断，避免中文 JSON 被切成乱码。
func truncateTestError(s string, max int) (string, bool) {
	if max <= 0 || len([]rune(s)) <= max {
		return s, false
	}
	return string([]rune(s)[:max]), true
}

// extractReply 从非流式响应里取助手文本；兼容 reasoning_content 与流式残片。
func extractReply(raw []byte) string {
	var resp struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			Text string `json:"text"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &resp) == nil {
		for _, c := range resp.Choices {
			if s := strings.TrimSpace(c.Message.Content); s != "" {
				return s
			}
			if s := strings.TrimSpace(c.Delta.Content); s != "" {
				return s
			}
			if s := strings.TrimSpace(c.Text); s != "" {
				return s
			}
			if s := strings.TrimSpace(c.Message.ReasoningContent); s != "" {
				return s
			}
		}
	}
	// 流式 SSE 残片：取所有 data: 行里的 delta.content 拼接。
	var sb strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		chunk := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if chunk == "" || chunk == "[DONE]" {
			continue
		}
		var ev struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(chunk), &ev) == nil {
			for _, c := range ev.Choices {
				sb.WriteString(c.Delta.Content)
			}
		}
	}
	return strings.TrimSpace(sb.String())
}

func accountKind(a interface{ IsEnterprise() bool }) string {
	if a.IsEnterprise() {
		return "enterprise"
	}
	return "apikey"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
