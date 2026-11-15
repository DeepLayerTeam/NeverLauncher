//go:build !windows

package discordrpc

import (
	"errors"
	"io"
)

func openWindowsPipe(string) (io.ReadWriteCloser, error) {
	return nil, errors.New("Windows IPC unavailable")
}
