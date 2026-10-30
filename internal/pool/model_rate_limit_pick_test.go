package pool

import (
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// TestFallbackSkipsModelCooledForRequestedModel 全冷却兜底不得把「对该模型正在
// 模型级限流」的账号捞回来。
//
// 背景：兜底（pickEarliestExpiryLocked）为「可能已恢复」的号准备，原本只看账号级
// 截止，对模型级冷却无感。实测同一 (账号, 模型) 在同一重置窗口内被兜底反复选中、
// 重复吃 429 达 77 次（某账号 / cn:kimi-k3.1-pro）。
func TestFallbackSkipsModelCooledForRequestedModel(t *testing.T) {
	withNoPickGap(t)
	p := New("")
	p.SetCostExploreInterval(0)
	a := &auth.Auth{UID: "u1"}
	auth.BackfillRealmFor(a, "cn")
	if err := p.Add(a); err != nil {
		t.Fatal(err)
	}
	// 账号级软冷却 → healthy 候选为空，强制走兜底路径。
	p.Cooldown("u1", CoolSoft, 2*time.Minute, "test")
	// 顺序不能反：Cooldown 会清掉参与路由的模型级冷却。
	p.CooldownSoftForModel("u1", time.Minute, time.Now().Add(time.Hour), "kimi-k3.1-pro", "429 model rate limit")

	if got := p.PickExcludingForRealm(nil, "kimi-k3.1-pro", "cn"); got != nil {
		t.Fatalf("模型级限流中的号不得被兜底选中: %v", got.UID)
	}
	if got := p.PickExcludingForRealm(nil, "deepseek-v4.1-flash", "cn"); got == nil {
		t.Fatal("其它模型仍应能从兜底路径拿到该账号")
	}
}

// TestCooldownSoftForModelEmptyModelFallsBackToAccount 无模型维度（搜索路径传空
// model）时必须退回账号级软冷却：写入空模型键既不参与路由（永远匹配不到真实
// 模型），又会让限流号完好无损地留在池子里。
func TestCooldownSoftForModelEmptyModelFallsBackToAccount(t *testing.T) {
	p := New("")
	if err := p.Add(&auth.Auth{UID: "u1"}); err != nil {
		t.Fatal(err)
	}
	p.CooldownSoftForModel("u1", time.Minute, time.Now().Add(time.Hour), "", "429 model rate limit")

	st, ok := p.Status("u1")
	if !ok {
		t.Fatal("account disappeared")
	}
	if !st.Cooling || st.CoolKind != "soft_rate" {
		t.Fatalf("空模型维度应退回账号级软冷却: %+v", st)
	}
	if len(st.RateLimitedModels) != 0 {
		t.Fatalf("不得写入空模型键: %+v", st.RateLimitedModels)
	}
}
