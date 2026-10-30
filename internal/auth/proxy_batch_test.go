package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAtomicBatchPersistsAllBindings(t *testing.T) {
	dir := t.TempDir()
	accounts := []*Auth{
		{AccessToken: "token-a", UID: "a", FilePath: filepath.Join(dir, "workbuddy-a.json")},
		{AccessToken: "token-b", UID: "b", FilePath: filepath.Join(dir, "workbuddy-b.json")},
	}
	for _, a := range accounts {
		if err := a.SaveAtomic(); err != nil {
			t.Fatal(err)
		}
	}
	accounts[0].Proxy = "socks5h://127.0.0.1:1080"
	accounts[1].Proxy = "http://127.0.0.1:8080"
	if err := SaveAtomicBatch(accounts); err != nil {
		t.Fatal(err)
	}
	for _, a := range accounts {
		raw, err := os.ReadFile(a.FilePath)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Proxy != a.Proxy {
			t.Fatalf("account %s proxy=%q want %q", a.UID, parsed.Proxy, a.Proxy)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, proxyAssignmentJournalName)); !os.IsNotExist(err) {
		t.Fatalf("journal remains: %v", err)
	}
}

func TestRecoverProxyAssignmentsRollsBackPreparedTransactionIdempotently(t *testing.T) {
	dir := t.TempDir()
	old := []byte("old-auth-content")
	if err := os.WriteFile(filepath.Join(dir, "workbuddy-a.json"), []byte("partial-new-content"), 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := writeTransactionFile(dir, ".proxy-assign-backup-", old)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := writeTransactionFile(dir, ".proxy-assign-stage-", []byte("staged"))
	if err != nil {
		t.Fatal(err)
	}
	journal := proxyAssignmentJournal{Version: 1, Phase: "prepare", Files: []proxyAssignmentRecord{{Target: "workbuddy-a.json", Backup: backup, Stage: stage, Existed: true}}}
	writeJournalForTest(t, dir, journal)
	if err := RecoverProxyAssignments(dir); err != nil {
		t.Fatal(err)
	}
	if err := RecoverProxyAssignments(dir); err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "workbuddy-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(old) {
		t.Fatalf("restored %q want %q", got, old)
	}
	for _, artifact := range []string{backup, stage, proxyAssignmentJournalName} {
		if _, err := os.Stat(filepath.Join(dir, artifact)); !os.IsNotExist(err) {
			t.Fatalf("artifact %s remains: %v", artifact, err)
		}
	}
}

func TestRecoverProxyAssignmentsKeepsCommittedTargets(t *testing.T) {
	dir := t.TempDir()
	committed := []byte("committed-auth")
	if err := os.WriteFile(filepath.Join(dir, "workbuddy-a.json"), committed, 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := writeTransactionFile(dir, ".proxy-assign-backup-", []byte("old-auth"))
	if err != nil {
		t.Fatal(err)
	}
	stage, err := writeTransactionFile(dir, ".proxy-assign-stage-", []byte("unused-stage"))
	if err != nil {
		t.Fatal(err)
	}
	journal := proxyAssignmentJournal{Version: 1, Phase: "commit", Files: []proxyAssignmentRecord{{Target: "workbuddy-a.json", Backup: backup, Stage: stage, Existed: true}}}
	writeJournalForTest(t, dir, journal)
	if err := RecoverProxyAssignments(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "workbuddy-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(committed) {
		t.Fatalf("target=%q want %q", got, committed)
	}
	if _, err := os.Stat(filepath.Join(dir, proxyAssignmentJournalName)); !os.IsNotExist(err) {
		t.Fatalf("journal remains: %v", err)
	}
}

func writeJournalForTest(t *testing.T, dir string, journal proxyAssignmentJournal) {
	t.Helper()
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, proxyAssignmentJournalName), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
