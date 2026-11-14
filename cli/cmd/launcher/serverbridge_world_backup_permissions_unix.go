//go:build !windows

package main

import (
	"errors"
	"os"
)

func worldBackupVerifyPrivateDir02810(_ string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0077 != 0 {
		return errors.New("Каталог резервного копирования игрового мира: требуется закрытый каталог с правами 0700")
	}
	return nil
}
