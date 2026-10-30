package panel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fmyd666/workbuddy2api-panel/internal/auth"
)

// persistAccountAndAdd replaces credentials under the proxy-operation lock.
// Existing account bindings are preserved and uniqueness is validated before
// either the file or pool is changed. A rejected pool mutation restores the file.
func (p *Panel) persistAccountAndAdd(a *auth.Auth, preserveProxy bool, disabledReason string) error {
	if a == nil {
		return errors.New("nil account")
	}
	p.proxyOpMu.Lock()
	defer p.proxyOpMu.Unlock()

	if disabledReason != "" {
		if p.cfg.Pool.AuthByUID(a.UID) != nil {
			return errors.New("account already exists")
		}
		if _, err := os.Stat(a.FilePath); err == nil {
			return errors.New("auth file already exists")
		} else if !os.IsNotExist(err) {
			return errors.New("auth file unavailable")
		}
	} else if preserveProxy {
		if old := p.cfg.Pool.AuthByUID(a.UID); old != nil {
			setProxy(a, old.ProxyValue())
		} else if raw, err := os.ReadFile(a.FilePath); err == nil {
			parsed, parseErr := auth.Parse(raw)
			if parseErr != nil {
				return errors.New("existing auth file is invalid")
			}
			setProxy(a, parsed.ProxyValue())
		} else if !os.IsNotExist(err) {
			return errors.New("existing auth file unavailable")
		}
	}

	previous, readErr := os.ReadFile(a.FilePath)
	previousExists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return errors.New("existing auth file unavailable")
	}
	if err := p.cfg.Pool.ValidateAccountProxy(a.UID, a.ProxyValue()); err != nil {
		return err
	}
	if err := a.SaveAtomic(); err != nil {
		return err
	}

	var addErr error
	if disabledReason != "" {
		addErr = p.cfg.Pool.AddDisabled(a, disabledReason)
	} else {
		addErr = p.cfg.Pool.Add(a)
	}
	if addErr == nil {
		return nil
	}
	if restoreErr := restoreAuthFile(a.FilePath, previous, previousExists); restoreErr != nil {
		return errors.Join(fmt.Errorf("pool rejected auth replacement: %w", addErr), fmt.Errorf("restore auth file: %w", restoreErr))
	}
	return addErr
}

func setProxy(a *auth.Auth, proxy string) {
	a.Lock()
	a.Proxy = proxy
	a.Unlock()
}

func restoreAuthFile(path string, contents []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncAuthDir(filepath.Dir(path))
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".auth-restore-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncAuthDir(dir)
}

func syncAuthDir(dir string) error {
	h, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer h.Close()
	return h.Sync()
}
