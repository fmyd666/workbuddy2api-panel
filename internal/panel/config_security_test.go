package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestConfigAPIExcludesSecretsAndFilesystemPaths(t *testing.T) {
	p := New(Config{
		APIKey:     "panel-test-key",
		ConfigPath: "/private/deploy/config.json",
		LoadConfig: func() (any, error) {
			return map[string]any{
				"listen":     ":7863",
				"api_key":    "secret-api-key",
				"auth_dir":   "/private/auths",
				"state_file": "/private/state.json",
				"upstream": map[string]any{
					"device_token":      "secret-device-token",
					"device_token_file": "/private/device-token",
				},
				"upstash": map[string]any{
					"url":   "rediss://private-user:secret-redis@redis.example/0",
					"token": "secret-redis-token",
				},
				"prompt": map[string]any{"file": "/private/system-prompt.md", "mode": "custom"},
			}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
	req.Header.Set("Authorization", "Bearer panel-test-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Path     string         `json:"path"`
		Config   map[string]any `json:"config"`
		Redacted []string       `json:"redacted_fields"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Path != "config.json" {
		t.Fatalf("path=%q, expected basename only", response.Path)
	}
	for _, key := range []string{"api_key", "auth_dir", "state_file"} {
		if _, ok := response.Config[key]; ok {
			t.Errorf("top-level secret/path %q was returned", key)
		}
	}
	for group, keys := range map[string][]string{
		"upstream": {"device_token", "device_token_file"},
		"upstash":  {"url", "token"},
		"prompt":   {"file"},
	} {
		nested, _ := response.Config[group].(map[string]any)
		for _, key := range keys {
			if _, ok := nested[key]; ok {
				t.Errorf("%s.%s was returned", group, key)
			}
		}
	}
	for _, field := range []string{"api_key", "upstream.device_token", "upstream.device_token_file", "upstash.url", "upstash.token", "prompt.file"} {
		found := false
		for _, v := range response.Redacted {
			if v == field {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("redacted_fields missing %q", field)
		}
	}
	for _, forbidden := range []string{"secret-api-key", "secret-device-token", "secret-redis-token", "/private/", "private-user"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("response leaked %q", forbidden)
		}
	}
}

func TestConfigSourceMetadataAndEndpointRedaction(t *testing.T) {
	t.Setenv("WB2A_API_KEY", "env-secret")
	t.Setenv("WB2A_PROMPT_FILE", "/env/private/prompt.md")
	p := New(Config{
		APIKey: "panel-test-key",
		LoadConfig: func() (any, error) {
			return map[string]any{
				"api_key":  "file-secret",
				"prompt":   map[string]any{"file": "/file/private/prompt.md"},
				"upstream": map[string]any{"chat_base": "HTTPS://user:pass@example.com/private/path?token=secret#fragment"},
				"global":   map[string]any{"chat_base": "https://[2001:db8::1]:8443/secret"},
			}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
	req.Header.Set("Authorization", "Bearer panel-test-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		APIKeySource string         `json:"api_key_source"`
		PromptSource string         `json:"prompt_file_source"`
		Configured   []string       `json:"configured_fields"`
		Config       map[string]any `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.APIKeySource != "environment" || response.PromptSource != "environment" {
		t.Fatalf("source metadata: api=%q prompt=%q", response.APIKeySource, response.PromptSource)
	}
	for _, field := range []string{"api_key", "prompt.file"} {
		if !containsString(response.Configured, field) {
			t.Errorf("configured_fields missing %q", field)
		}
	}
	up := response.Config["upstream"].(map[string]any)
	global := response.Config["global"].(map[string]any)
	if got := up["chat_base"]; got != "https://example.com" {
		t.Errorf("upstream endpoint=%v", got)
	}
	if got := global["chat_base"]; got != "https://[2001:db8::1]:8443" {
		t.Errorf("global endpoint=%v", got)
	}
	for _, secret := range []string{"env-secret", "file-secret", "user:pass", "private/path", "token=secret", "fragment", "private/prompt"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("response leaked %q", secret)
		}
	}
}

func TestConfigErrorsAreGeneric(t *testing.T) {
	p := New(Config{APIKey: "panel-test-key", LoadConfig: func() (any, error) { return nil, os.ErrPermission }, SaveConfig: func([]byte) ([]string, error) { return nil, errors.New("secret path /private/config.json") }})
	for _, tc := range []struct {
		method, body, want string
		status             int
	}{
		{http.MethodGet, "", "config_load_failed", http.StatusInternalServerError},
		{http.MethodPost, "{}", "config_save_failed", http.StatusBadRequest},
	} {
		req := httptest.NewRequest(tc.method, "/panel/api/config", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer panel-test-key")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Errorf("%s status=%d body=%s", tc.method, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) || strings.Contains(rec.Body.String(), "/private/config.json") {
			t.Errorf("unexpected error body: %s", rec.Body.String())
		}
	}
	bad := httptest.NewRequest(http.MethodPost, "/panel/api/config", strings.NewReader("{"))
	bad.Header.Set("Authorization", "Bearer panel-test-key")
	badRec := httptest.NewRecorder()
	p.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusBadRequest || !strings.Contains(badRec.Body.String(), "config_request_invalid") || strings.Contains(badRec.Body.String(), "secret path") {
		t.Errorf("malformed body response=%d %s", badRec.Code, badRec.Body.String())
	}
}

func TestSafeEndpointMalformedAndIPv6(t *testing.T) {
	cases := map[string]string{
		"https://u:p@example.com/path?q=secret#frag": "https://example.com",
		"HtTp://[2001:db8::1]:8080/path":             "http://[2001:db8::1]:8080",
		"https://example.com:8443":                   "https://example.com:8443",
		"not a url":                                  "[configured]",
		"/relative/path":                             "[configured]",
	}
	for input, want := range cases {
		if got := safeEndpoint(input); got != want {
			t.Errorf("safeEndpoint(%q)=%q want %q", input, got, want)
		}
	}
}

func TestConfigSourceMetadataFileAndUnset(t *testing.T) {
	t.Setenv("WB2A_API_KEY", "")
	t.Setenv("WB2A_PROMPT_FILE", "")
	for _, tc := range []struct {
		name        string
		cfg         map[string]any
		api, prompt string
	}{
		{name: "file", cfg: map[string]any{"api_key": "file-key", "prompt": map[string]any{"file": "/custom/prompt.md"}}, api: "file", prompt: "file"},
		{name: "unset", cfg: map[string]any{"prompt": map[string]any{"mode": "passthrough"}}, api: "unset", prompt: "unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Config{APIKey: "panel-test-key", LoadConfig: func() (any, error) { return tc.cfg, nil }})
			req := httptest.NewRequest(http.MethodGet, "/panel/api/config", nil)
			req.Header.Set("Authorization", "Bearer panel-test-key")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var got struct {
				API    string `json:"api_key_source"`
				Prompt string `json:"prompt_file_source"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.API != tc.api || got.Prompt != tc.prompt {
				t.Fatalf("source api=%q prompt=%q; want %q/%q", got.API, got.Prompt, tc.api, tc.prompt)
			}
		})
	}
}
