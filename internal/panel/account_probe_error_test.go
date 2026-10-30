package panel

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/fmyd666/workbuddy2api-panel/internal/upstream"
)

func TestDescribeTestErrorUsesFullBody(t *testing.T) {
	body := []byte(`{"code":11102,"msg":"model [cn:deepseek-v4-flash] service info not found","requestId":"6b13a7eb9ea6676704332d4998698681","displayMsg":{"en":"Model unavailable. Please switch models","zh":"当前模型暂不可用，请切换其他模型"}}`)
	err := &upstream.Error{Kind: upstream.ErrModelBlocked, Status: 400, Msg: string(body[:200])}
	got := describeTestError(err, body)
	if !strings.Contains(got, "当前模型暂不可用，请切换其他模型") || !strings.Contains(got, "code=11102") {
		t.Fatalf("missing full message: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("invalid utf8: %q", got)
	}
}

func TestTruncateTestErrorRuneSafe(t *testing.T) {
	s, cut := truncateTestError(strings.Repeat("中", 10), 3)
	if !cut || s != "中中中" {
		t.Fatalf("got %q %v", s, cut)
	}
}

func TestBareTestModel(t *testing.T) {
	cases := map[string]string{
		"cn:deepseek-v4.1-flash": "deepseek-v4.1-flash",
		"global:kimi-k3.1-pro":   "kimi-k3.1-pro",
		"deepseek-v4.1-flash":    "deepseek-v4.1-flash",
		"qwen:2.5-max":           "qwen:2.5-max", // 非 realm 前缀：原样保留
		"":                       "",
	}
	for in, want := range cases {
		if got := bareTestModel(in); got != want {
			t.Errorf("bareTestModel(%q)=%q want %q", in, got, want)
		}
	}
}
