package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const proxyAssignmentJournalName = ".proxy-assignment.journal.json"

type proxyAssignmentRecord struct {
	Target  string `json:"target"`
	Backup  string `json:"backup,omitempty"`
	Stage   string `json:"stage,omitempty"`
	Existed bool   `json:"existed"`
}

type proxyAssignmentJournal struct {
	Version int                     `json:"version"`
	Phase   string                  `json:"phase"`
	Files   []proxyAssignmentRecord `json:"files"`
}

// SaveAtomicBatch writes auth files as one journaled proxy-assignment transaction.
// Files must share one directory so startup recovery can replay a single journal.
func SaveAtomicBatch(accounts []*Auth) error {
	if len(accounts) == 0 {
		return errors.New("no accounts")
	}
	ordered := append([]*Auth(nil), accounts...)
	paths := make([]string, len(ordered))
	for i, a := range ordered {
		if a == nil {
			return errors.New("nil account")
		}
		if a.FilePath == "" {
			return errors.New("no FilePath set")
		}
		paths[i] = a.FilePath
	}
	dir, err := filepath.Abs(filepath.Dir(paths[0]))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	unlockDir, err := lockAuthDirectory(dir)
	if err != nil {
		return withDockerPermHint(err)
	}
	defer unlockDir()
	canonical, unlockPaths, err := lockAuthPaths(paths)
	if err != nil {
		return fmt.Errorf("invalid auth batch paths: %w", err)
	}
	defer unlockPaths()
	canonicalDir := filepath.Dir(canonical[0])
	for _, path := range canonical {
		if filepath.Dir(path) != canonicalDir {
			return errors.New("proxy assignment batch spans auth directories")
		}
		if path != filepath.Join(canonicalDir, filepath.Base(path)) {
			return errors.New("invalid auth file path")
		}
	}
	if canonicalDir != dir {
		return errors.New("auth directory resolved through symlink; refusing journal transaction")
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].FilePath < ordered[j].FilePath })
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].FilePath == ordered[i].FilePath {
			return errors.New("duplicate auth file in batch")
		}
	}
	for _, a := range ordered {
		a.mu.Lock()
	}
	defer func() {
		for i := len(ordered) - 1; i >= 0; i-- {
			ordered[i].mu.Unlock()
		}
	}()
	for _, a := range ordered {
		if strings.TrimSpace(a.AccessToken) == "" {
			return fmt.Errorf("save refused: empty accessToken (uid=%s)", a.UID)
		}
	}
	if err := recoverProxyAssignment(dir); err != nil {
		return fmt.Errorf("proxy assignment recovery required: %w", err)
	}

	journal := proxyAssignmentJournal{Version: 1, Phase: "prepare"}
	stages := make([]string, 0, len(ordered))
	cleanup := func() error {
		var errs []error
		for _, name := range stages {
			if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
		for _, rec := range journal.Files {
			if rec.Backup != "" {
				if err := os.Remove(filepath.Join(dir, rec.Backup)); err != nil && !os.IsNotExist(err) {
					errs = append(errs, err)
				}
			}
		}
		return errors.Join(errs...)
	}
	for _, a := range ordered {
		name := filepath.Base(a.FilePath)
		if name == "." || name == string(filepath.Separator) || name != filepath.Base(filepath.Clean(name)) {
			_ = cleanup()
			return errors.New("invalid auth file path")
		}
		newRaw, err := marshalProxyAuthLocked(a)
		if err != nil {
			_ = cleanup()
			return err
		}
		rec := proxyAssignmentRecord{Target: name}
		oldRaw, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			rec.Existed = true
			rec.Backup, err = writeTransactionFile(dir, ".proxy-assign-backup-", oldRaw)
			if err != nil {
				_ = cleanup()
				return err
			}
		} else if !os.IsNotExist(err) {
			_ = cleanup()
			return err
		}
		stage, err := writeTransactionFile(dir, ".proxy-assign-stage-", newRaw)
		if err != nil {
			if rec.Backup != "" {
				_ = os.Remove(filepath.Join(dir, rec.Backup))
			}
			_ = cleanup()
			return err
		}
		rec.Stage = stage
		stages = append(stages, filepath.Join(dir, stage))
		journal.Files = append(journal.Files, rec)
	}
	if err := syncDirectory(dir); err != nil {
		_ = cleanup()
		return err
	}
	if err := createProxyAssignmentJournalExclusive(dir, journal); err != nil {
		_ = cleanup()
		return err
	}
	for _, rec := range journal.Files {
		if err := os.Rename(filepath.Join(dir, rec.Stage), filepath.Join(dir, rec.Target)); err != nil {
			rbErr := recoverProxyAssignment(dir)
			if rbErr != nil {
				return errors.Join(fmt.Errorf("commit proxy assignment: %w", err), fmt.Errorf("rollback pending: %w", rbErr))
			}
			return fmt.Errorf("commit proxy assignment: %w", err)
		}
	}
	if err := syncDirectory(dir); err != nil {
		rbErr := recoverProxyAssignment(dir)
		if rbErr != nil {
			return errors.Join(fmt.Errorf("sync proxy assignment targets: %w", err), fmt.Errorf("rollback pending: %w", rbErr))
		}
		return fmt.Errorf("sync proxy assignment targets: %w", err)
	}
	journal.Phase = "commit"
	if err := writeProxyAssignmentJournal(dir, journal); err != nil {
		rbErr := recoverProxyAssignment(dir)
		if rbErr != nil {
			return errors.Join(fmt.Errorf("finalize proxy assignment: %w", err), fmt.Errorf("rollback pending: %w", rbErr))
		}
		return fmt.Errorf("finalize proxy assignment: %w", err)
	}
	if err := recoverProxyAssignment(dir); err != nil {
		return fmt.Errorf("committed proxy assignment cleanup pending: %w", err)
	}
	return nil
}

// RecoverProxyAssignments completes committed transactions or rolls back prepared ones.
func RecoverProxyAssignments(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	unlock, err := lockAuthDirectory(abs)
	if err != nil {
		return withDockerPermHint(err)
	}
	defer unlock()
	return recoverProxyAssignment(abs)
}

func recoverProxyAssignment(dir string) error {
	journalPath := filepath.Join(dir, proxyAssignmentJournalName)
	raw, err := os.ReadFile(journalPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal proxyAssignmentJournal
	if json.Unmarshal(raw, &journal) != nil || journal.Version != 1 || (journal.Phase != "prepare" && journal.Phase != "commit") || len(journal.Files) == 0 {
		return errors.New("invalid proxy assignment journal")
	}
	seen := map[string]bool{}
	for _, rec := range journal.Files {
		if rec.Target == "" || filepath.Base(rec.Target) != rec.Target || strings.Contains(rec.Target, string(filepath.Separator)) || seen[rec.Target] {
			return errors.New("invalid proxy assignment journal target")
		}
		seen[rec.Target] = true
		if rec.Stage == "" || filepath.Base(rec.Stage) != rec.Stage || !strings.HasPrefix(rec.Stage, ".proxy-assign-stage-") {
			return errors.New("invalid proxy assignment journal stage")
		}
		if rec.Backup != "" && (filepath.Base(rec.Backup) != rec.Backup || !strings.HasPrefix(rec.Backup, ".proxy-assign-backup-")) {
			return errors.New("invalid proxy assignment journal backup")
		}
		if rec.Existed && rec.Backup == "" {
			return errors.New("missing proxy assignment backup")
		}
	}
	if journal.Phase == "prepare" {
		for _, rec := range journal.Files {
			target := filepath.Join(dir, rec.Target)
			if rec.Existed {
				backup, err := os.ReadFile(filepath.Join(dir, rec.Backup))
				if err != nil {
					return fmt.Errorf("read proxy assignment backup: %w", err)
				}
				if err := atomicReplaceFile(target, backup); err != nil {
					return fmt.Errorf("restore proxy assignment: %w", err)
				}
			} else if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove incomplete proxy assignment: %w", err)
			}
		}
		if err := syncDirectory(dir); err != nil {
			return fmt.Errorf("sync proxy assignment recovery: %w", err)
		}
	}
	// Remove the journal first. If cleanup is interrupted, orphaned staged/backup files
	// are harmless; if interrupted before this point, all inputs remain for idempotent retry.
	if err := os.Remove(journalPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync proxy assignment journal removal: %w", err)
	}
	var cleanupErrs []error
	for _, rec := range journal.Files {
		for _, name := range []string{rec.Backup, rec.Stage} {
			if name == "" {
				continue
			}
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				cleanupErrs = append(cleanupErrs, err)
			}
		}
	}
	if err := syncDirectory(dir); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}
	return errors.Join(cleanupErrs...)
}

func marshalProxyAuthLocked(a *Auth) ([]byte, error) {
	authDoc := map[string]any{"accessToken": a.AccessToken, "refreshToken": a.RefreshToken, "expiresAt": a.ExpiresAt, "domain": a.Domain, "realm": a.realm}
	if strings.TrimSpace(a.Proxy) != "" {
		authDoc["proxy"] = a.Proxy
	}
	doc := map[string]any{"auth": authDoc, "account": map[string]any{"uid": a.UID, "enterpriseId": a.EnterpriseID, "nickname": a.Nickname}}
	if a.DeviceToken != "" {
		doc["device_token"] = a.DeviceToken
	}
	return json.MarshalIndent(doc, "", "  ")
}

func writeTransactionFile(dir, prefix string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return "", err
	}
	name := filepath.Base(f.Name())
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func writeProxyAssignmentJournal(dir string, journal proxyAssignmentJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return atomicReplaceFile(filepath.Join(dir, proxyAssignmentJournalName), raw)
}

func createProxyAssignmentJournalExclusive(dir string, journal proxyAssignmentJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, proxyAssignmentJournalName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDirectory(dir)
}

func atomicReplaceFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".proxy-assign-write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
