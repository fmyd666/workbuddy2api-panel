package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fmyd666/workbuddy2api-panel/internal/livecfg"
	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
	"github.com/fmyd666/workbuddy2api-panel/internal/scheduler"
	"github.com/fmyd666/workbuddy2api-panel/internal/upstream"
)

func TestSaveConfigKeepsEnvironmentSecretsAuthoritative(t *testing.T) {
	promptPath := filepath.Join(t.TempDir(), "prompt.md")
	if err := os.WriteFile(promptPath, []byte("environment prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WB2A_API_KEY", "env-key")
	t.Setenv("WB2A_PROMPT_FILE", promptPath)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"prompt":{"mode":"custom"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	live := livecfg.New(livecfg.Snapshot{})
	pool := pool.New("")
	up := upstream.New()
	defer up.CloseIdleConnections()
	scheduler := scheduler.New(scheduler.Config{})
	_, err := saveConfig([]byte(`{"panel":{"package_detail_limit":6}}`), path, live, pool, up, scheduler)
	if err != nil {
		t.Fatal(err)
	}
	if got := live.Load().APIKey; got != "env-key" {
		t.Fatalf("runtime API key=%q", got)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(saved, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["api_key"]; ok {
		t.Fatal("environment API key was written to file")
	}
	prompt, _ := cfg["prompt"].(map[string]any)
	if _, ok := prompt["file"]; ok {
		t.Fatal("environment prompt path was written to file")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.APIKey != "env-key" || loaded.Prompt.File != promptPath {
		t.Fatalf("environment values lost: api=%q prompt=%q", loaded.APIKey, loaded.Prompt.File)
	}
}
