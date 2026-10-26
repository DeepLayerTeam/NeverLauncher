//go:build !windows

package windowssandbox

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

func (*Handle) Started() error         { return errors.New("windows-appcontainer-not-supported") }
func (*Handle) Close()                 {}
func (*Handle) PID() int               { return 0 }
func Available() error                 { return errors.New("windows-appcontainer-not-supported") }
func Prepare(Options) (*Handle, error) { return nil, Available() }

func (*Handle) HostPipe() string { return "" }
