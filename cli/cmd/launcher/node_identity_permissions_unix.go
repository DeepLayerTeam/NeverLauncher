//go:build !windows

package main

import (
	"fmt"
	"os"
)

func restrictNodeIdentityPermissions0199(path string) error {
	return os.Chmod(path, 0o600)
}

func verifyNodeIdentityPermissions0199(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("Для файла идентификации узла %s требуются закрытые права доступа 0600", path)
	}
	return nil
}
