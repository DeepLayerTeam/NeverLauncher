//go:build !linux || !amd64

package linuxsandbox

import (
	"errors"
	"net/http"
	"os/exec"
)

type Policy struct {
	FilesystemRead, FilesystemWrite, NetworkOutbound, Secrets []string
	MaxMemoryBytes                                            int64
	MaxProcesses, MaxCPUPercent, TimeoutSeconds               int
}
type Options struct {
	Policy                  Policy
	PayloadRoot, Entrypoint string
	Args, Environment       []string
	HostURL                 string
	HostHandler             http.Handler
}
type Handle struct{ Cmd *exec.Cmd }

func (*Handle) Close()                 {}
func (*Handle) Abort()                 {}
func (*Handle) Started() error         { return errors.New("sandbox-not-supported") }
func Available() error                 { return errors.New("sandbox-requires-linux-amd64") }
func Prepare(Options) (*Handle, error) { return nil, Available() }
