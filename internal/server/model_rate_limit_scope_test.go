package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
	"github.com/fmyd666/workbuddy2api-panel/internal/upstream"
)

// TestApplyErrorPolicyModelScopedRateLimit 锚定 429 的冷却范围：
//
// 上游 6000 与 6004 携带完全相同的 msg（「…重置，您也可以切换其他模型继续使用。」），
// 只按 code 6004 判定会把 6000 当成账号级限流——整个账号被关到重置墙钟，而实际
// 换个模型就能用（2026-10-29 实测：当日 429 全部集中在 cn:kimi-k3.1-pro，其它
// 模型 0 次；被 6000 冷却的账号改用 deepseek/glm 均返回 200）。
//
// 期望：带「可换模型」文案的 429 只锁该模型（账号不 Cooling、其它模型仍可选）；
// 不带该文案的 429 仍按账号级软冷却（回归保护，避免一律豁免把限流号放回池子）。
// rateLimitedHintBody 构造上游「可换模型」形态的 429 文案。
// 重置时刻取相对未来的时间：写死日期会随真实时间流逝变成「已过期」，
// 池子据此判定无需冷却，测试便会无故失败（时间炸弹）。
func rateLimitedHintBody() string {
	reset := time.Now().In(time.FixedZone("UTC+8", 8*3600)).Add(2 * time.Hour).Format("2006-01-02 15:04:05")
	return `{"code":6000,"msg":"您的使用量已超出频率限制，将在 ` + reset + ` UTC+8 重置，您也可以切换其他模型继续使用。","requestId":"758cf8500f56213f15810a6d384e4cd4"}`
}

func TestApplyErrorPolicyModelScopedRateLimit(t *testing.T) {
	hintBody := rateLimitedHintBody()

	p := pool.New("")
	if err := p.Add(&auth.Auth{UID: "u1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Config{Pool: p, SoftCooldown: 600 * time.Second})

	h.applyErrorPolicy("u1", upstream.ErrSoftRate, hintBody, "kimi-k3.1-pro", nil)

	st, ok := p.Status("u1")
	if !ok {
		t.Fatal("account disappeared")
	}
	if st.Cooling {
		t.Fatalf("模型级 429 不应整体冷却账号（整号冷却会白关一个仍可服务其它模型的号）: %+v", st)
	}
	if len(st.RateLimitedModels) != 1 || st.RateLimitedModels[0].Model != "kimi-k3.1-pro" {
		t.Fatalf("应记录 kimi-k3.1-pro 的模型级限流台账: %+v", st.RateLimitedModels)
	}
	if st.RateLimitedModels[0].Kind != "rate_limit" {
		t.Errorf("台账 kind=%q want rate_limit", st.RateLimitedModels[0].Kind)
	}
	if a := p.PickExcludingForModel(nil, "kimi-k3.1-pro"); a != nil {
		t.Errorf("被模型级限流的模型不应再被选中: %v", a.UID)
	}
	if a := p.PickExcludingForModel(nil, "deepseek-v4.1-flash"); a == nil || a.UID != "u1" {
		t.Errorf("其它模型应仍可选，got %v", a)
	}

	// 对照：没有「可换模型」文案的 429 仍是账号级软冷却。
	const accountLevel = `{"code":6000,"msg":"usage limit exceeded"}`
	h.applyErrorPolicy("u1", upstream.ErrSoftRate, accountLevel, "deepseek-v4.1-flash", nil)
	if st, _ := p.Status("u1"); !st.Cooling || st.CoolKind != "soft_rate" {
		t.Fatalf("无「可换模型」文案的 429 应整体冷却账号: %+v", st)
	}
}

// TestChatModelScopedRateLimitEndToEnd 端到端：上游真实形态的 429（code 6000 +
// 「您也可以切换其他模型继续使用」）打到 kimi 请求上时，网关必须
//  1. 换号并让客户端拿到 200；
//  2. 只把 kimi 记进模型级限流台账，账号本身不 Cooling；
//  3. 该账号对其它模型仍可被选中（整号冷却会白关一个能用的号）。
func TestChatModelScopedRateLimitEndToEnd(t *testing.T) {
	rateBody := rateLimitedHintBody()
	calls := map[string]int{}
	up := newFakeUpstream(t, func(authz string) (int, string, bool) {
		calls[authz]++
		if authz == "Bearer at-bad" {
			return 429, rateBody, false
		}
		return 200, sseOK, true
	})
	p := testPoolWith(
		&auth.Auth{UID: "bad", AccessToken: "at-bad", ExpiresAt: 9999999999},
		&auth.Auth{UID: "good", AccessToken: "at-good", ExpiresAt: 9999999999},
	)
	// 让 bad 积分更高被先选中（与既有轮换测试同一确定性手法）。
	p.SetCredits("bad", 2000, 0)
	p.SetCredits("good", 1000, 0)
	h := NewHandler(Config{Pool: p, Upstream: up, SoftCooldown: time.Minute})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"kimi-k3.1-pro","messages":[]}`)))
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if calls["Bearer at-bad"] != 1 || calls["Bearer at-good"] != 1 {
		t.Errorf("calls=%v want bad/good 各 1 次", calls)
	}

	bad, _ := p.Status("bad")
	if bad.Cooling {
		t.Fatalf("模型级 429 不得整号冷却: %+v", bad)
	}
	if len(bad.RateLimitedModels) != 1 || bad.RateLimitedModels[0].Model != "kimi-k3.1-pro" {
		t.Fatalf("应只记录 kimi-k3.1-pro 的模型级限流: %+v", bad.RateLimitedModels)
	}
	if a := p.PickExcludingForModel(nil, "kimi-k3.1-pro"); a == nil || a.UID != "good" {
		t.Fatalf("kimi 请求应改选 good，got %v", a)
	}
	if a := p.PickExcludingForModel(nil, "deepseek-v4.1-flash"); a == nil || a.UID != "bad" {
		t.Fatalf("其它模型应仍可选中 bad（积分为高优先），got %v", a)
	}
}
