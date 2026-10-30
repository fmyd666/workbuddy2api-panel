package panel

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
)

func TestCockpitImportDisabledDoesNotCallUpstreamAndPersists(t *testing.T) {
	e := upgNewEnv(t)
	e.fake.register("inactive-uid", 1234)
	code, body := e.importCockpit([]map[string]any{{
		"uid":           "inactive-uid",
		"nickname":      "inactive",
		"access_token":  "at-inactive-uid",
		"refresh_token": "rt-inactive-uid",
		"expires_at":    time.Now().Add(365 * 24 * time.Hour).UnixMilli(),
	}}, true)
	if code != 200 || !strings.Contains(body, "\"imported\":1") {
		t.Fatalf("disabled import failed: status=%d body=%s", code, body)
	}
	if calls := e.fake.callCount("inactive-uid"); calls != 0 {
		t.Fatalf("disabled import unexpectedly made %d upstream calls", calls)
	}
	st, ok := e.pool.Status("inactive-uid")
	if !ok || !st.Disabled || st.DisabledReason != "imported disabled by request" {
		t.Fatalf("account not disabled after import: ok=%v disabled=%v", ok, st.Disabled)
	}
	if a := e.pool.Pick(); a != nil {
		t.Fatalf("disabled account selected by pool: uid=%q", a.UID)
	}
	authPath := filepath.Join(e.authDir, "workbuddy-inactive-uid.json")
	authRaw, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("auth file not persisted: %v", err)
	}
	if !json.Valid(authRaw) {
		t.Fatal("persisted auth file is invalid JSON")
	}

	// Pool.Close flushes state.json; reconstruction must keep the account excluded.
	e.pool.Close()
	p2 := pool.New(e.stateFile)
	t.Cleanup(p2.Close)
	auths, err := auth.LoadDir(e.authDir)
	if err != nil {
		t.Fatalf("reload auth directory: %v", err)
	}
	p2.SyncToDir(auths)
	st, ok = p2.Status("inactive-uid")
	if !ok || !st.Disabled || st.DisabledReason != "imported disabled by request" {
		t.Fatalf("disabled state did not survive restart: ok=%v disabled=%v", ok, st.Disabled)
	}
	if a := p2.Pick(); a != nil {
		t.Fatalf("disabled account selected after restart: uid=%q", a.UID)
	}
}

func TestAddDisabledPersistenceFailureRollsBackAccount(t *testing.T) {
	dir := t.TempDir()
	p := pool.New(dir) // an existing directory cannot be replaced by state.json
	defer p.Close()
	err := p.AddDisabled(&auth.Auth{UID: "u", AccessToken: "at"}, "imported disabled by request")
	if err == nil {
		t.Fatal("expected disabled state persistence failure")
	}
	if _, ok := p.Status("u"); ok {
		t.Fatal("failed durable insert left account in pool")
	}
}

func TestCockpitImportDisabledFlagValidation(t *testing.T) {
	e := upgNewEnv(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("disabled", "maybe"); err != nil {
		t.Fatal(err)
	}
	file, err := mw.CreateFormFile("file", "accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("[]")); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/panel/api/import/cockpit", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	e.panel.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid disabled value status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := len(e.pool.List()); got != 0 {
		t.Fatalf("invalid flag imported accounts: count=%d", got)
	}
}
