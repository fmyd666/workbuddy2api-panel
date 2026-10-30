//go:build linux

package auth

import (
	"os"
	"path/filepath"
	"syscall"
)

func lockAuthDirectoryProcess(dir string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(dir, ".proxy-assignment.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
