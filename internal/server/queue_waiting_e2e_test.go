package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// 端到端：上游回 6020 排队时，网关必须 503 + Retry-After=上游 retry_after，
// 只打一次上游（不放大轮转），且**不给账号写冷却**（历史 bug：罚 600s）。
func TestChatQueueWaitingIs503WithoutCooldown(t *testing.T) {
	var upstreamCalls int
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		upstreamCalls++
		return http.StatusTooManyRequests, queueWaitingBody, false
	})
	p := testPoolWith(
		&auth.Auth{UID: "q1", AccessToken: "at-q1", ExpiresAt: 9999999999},
		&auth.Auth{UID: "q2", AccessToken: "at-q2", ExpiresAt: 9999999999},
	)
	h := NewHandler(Config{Pool: p, Upstream: up, SoftCooldown: 600 * time.Second})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"kimi-k3.1-pro","messages":[{"role":"user","content":"hi"}]}`)))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d want 503 body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "40" {
		t.Fatalf("Retry-After=%q want 40", got)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls=%d want 1 (queue must not amplify rotation)", upstreamCalls)
	}
	for _, uid := range []string{"q1", "q2"} {
		st, ok := p.Status(uid)
		if !ok {
			t.Fatalf("account %s missing", uid)
		}
		if st.Cooling || st.CoolRemaining > 0 {
			t.Fatalf("account %s should stay healthy after queueing: %+v", uid, st)
		}
	}
	if body := rec.Body.String(); !strings.Contains(body, "queue.waiting") && !strings.Contains(body, "upstream_queue") {
		t.Fatalf("body should carry queue semantics: %s", body)
	}
}
