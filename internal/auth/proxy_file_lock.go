package auth

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var authPathLockRegistry sync.Map      // canonical auth path -> *sync.Mutex
var authDirectoryLockRegistry sync.Map // canonical auth directory -> *sync.Mutex

func lockAuthDirectory(dir string) (func(), error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	key, err := filepath.EvalSymlinks(abs)
	if err != nil {
		key = abs
	}
	key = filepath.Clean(key)
	value, _ := authDirectoryLockRegistry.LoadOrStore(key, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	unlockProcess, err := lockAuthDirectoryProcess(key)
	if err != nil {
		mu.Unlock()
		return nil, err
	}
	return func() { unlockProcess(); mu.Unlock() }, nil
}

func canonicalAuthPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		dir, err = filepath.Abs(filepath.Dir(abs))
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// lockAuthPaths serializes SaveAtomic and multi-file proxy transactions by target path,
// even when callers hold distinct Auth objects for the same file.
func lockAuthPaths(paths []string) ([]string, func(), error) {
	canonical := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			return nil, nil, os.ErrInvalid
		}
		resolved, err := canonicalAuthPath(path)
		if err != nil {
			return nil, nil, err
		}
		canonical = append(canonical, resolved)
	}
	sort.Strings(canonical)
	for idx := 1; idx < len(canonical); idx++ {
		if canonical[idx] == canonical[idx-1] {
			return nil, nil, os.ErrInvalid
		}
	}
	locks := make([]*sync.Mutex, 0, len(canonical))
	for _, key := range canonical {
		value, _ := authPathLockRegistry.LoadOrStore(key, &sync.Mutex{})
		mu := value.(*sync.Mutex)
		mu.Lock()
		locks = append(locks, mu)
	}
	unlock := func() {
		for idx := len(locks) - 1; idx >= 0; idx-- {
			locks[idx].Unlock()
		}
	}
	return canonical, unlock, nil
}
