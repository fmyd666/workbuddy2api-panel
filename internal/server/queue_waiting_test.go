package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
	"github.com/fmyd666/workbuddy2api-panel/internal/upstream"
)

const queueWaitingBody = `{"code":6020,"msg":"queue.waiting.title","requestId":"f5ba5ec78c90a173651fdfb74024414e","data":{"queue_position":5699,"queue_size":"999+","retry_after":40,"estimated_wait":29470}}`

// 6020「排队中」必须归到 ErrUpstreamQueue：既不是账号故障，也不能当普通限流。
func TestClassifyQueueWaiting(t *testing.T) {
	if got := upstream.Classify(http.StatusTooManyRequests, queueWaitingBody); got != upstream.ErrUpstreamQueue {
		t.Fatalf("classify=%v want ErrUpstreamQueue", got)
	}
	// 无 429 状态码但 body 带排队文案（防御口径）也要识别。
	if got := upstream.Classify(http.StatusOK, queueWaitingBody); got != upstream.ErrUpstreamQueue {
		t.Fatalf("classify(200 body)=%v want ErrUpstreamQueue", got)
	}
	// 边界：6021 仍是渠道满载，6004 仍是模型级限流，6000 仍是账号级软限流。
	if got := upstream.Classify(http.StatusTooManyRequests, `{"code":6021,"msg":"queue.full.title"}`); got != upstream.ErrUpstreamBusy {
		t.Fatalf("6021=%v want ErrUpstreamBusy", got)
	}
	if got := upstream.Classify(http.StatusTooManyRequests, `{"code":6004,"msg":"model rate limit"}`); got != upstream.ErrSoftRate {
		t.Fatalf("6004=%v want ErrSoftRate", got)
	}
	if got := upstream.Classify(http.StatusTooManyRequests, `{"code":6000,"msg":"usage limit"}`); got != upstream.ErrSoftRate {
		t.Fatalf("6000=%v want ErrSoftRate", got)
	}
}

func TestParseQueueRetryAfter(t *testing.T) {
	if d, ok := upstream.ParseQueueRetryAfter(queueWaitingBody); !ok || d != 40*time.Second {
		t.Fatalf("retry_after parse: d=%v ok=%v", d, ok)
	}
	if d, ok := upstream.ParseQueueRetryAfter(`{"data":{"estimated_wait":2500}}`); !ok || d != 2500*time.Millisecond {
		t.Fatalf("estimated_wait parse: d=%v ok=%v", d, ok)
	}
	if _, ok := upstream.ParseQueueRetryAfter(`{"code":6020}`); ok {
		t.Fatal("missing retry fields must report false")
	}
}

// 核心回归：排队错误**不得**给账号写冷却（历史 bug：罚 600s 白关一个健康号）。
func TestQueueWaitingDoesNotCooldownAccount(t *testing.T) {
	p := pool.New("")
	if err := p.Add(&auth.Auth{UID: "u1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Config{Pool: p, SoftCooldown: 600 * time.Second})

	for i := 0; i < 3; i++ {
		h.applyErrorPolicy("u1", upstream.ErrUpstreamQueue, queueWaitingBody, "kimi-k3.1-pro", nil)
		st, ok := p.Status("u1")
		if !ok {
			t.Fatal("account disappeared")
		}
		if st.Cooling || st.CoolRemaining > 0 {
			t.Fatalf("call %d: 排队不应产生账号冷却: %+v", i+1, st)
		}
		if st.SoftStreak != 0 {
			t.Fatalf("call %d: 排队不应累计 soft_streak: %d", i+1, st.SoftStreak)
		}
	}
	// 对照：同样 body 若误判成 ErrSoftRate 会立刻冷却——确认对照组仍然生效，
	// 避免测试因为 applyErrorPolicy 整体失效而“假通过”。
	h.applyErrorPolicy("u1", upstream.ErrSoftRate, queueWaitingBody, "kimi-k3.1-pro", nil)
	if st, _ := p.Status("u1"); !st.Cooling {
		t.Fatal("control group: ErrSoftRate should cool down the account")
	}
}

func TestQueueRetryAfterFallsBackToHeaderThen30s(t *testing.T) {
	if got := queueRetryAfter(nil, queueWaitingBody); got != 40*time.Second {
		t.Fatalf("body retry_after: %v", got)
	}
	if got := queueRetryAfter(&upstream.Error{RetryAfter: 12 * time.Second}, `{"code":6020}`); got != 12*time.Second {
		t.Fatalf("header fallback: %v", got)
	}
	if got := queueRetryAfter(nil, `{"code":6020}`); got != 30*time.Second {
		t.Fatalf("default: %v", got)
	}
}
