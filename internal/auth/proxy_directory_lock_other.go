//go:build !linux

package auth

func lockAuthDirectoryProcess(string) (func(), error) { return func() {}, nil }
