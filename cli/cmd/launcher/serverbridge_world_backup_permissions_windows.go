//go:build windows

package main

import "os"

func worldBackupVerifyPrivateDir02810(path string, fi os.FileInfo) error {
	return hostPrivateCheck(path, fi)
}
