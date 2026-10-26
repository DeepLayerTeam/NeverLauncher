//go:build !darwin

package macossandbox

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

func Available() error                 { return errors.New("macos-signed-app-sandbox-helper-not-supported") }
func Prepare(Options) (*Handle, error) { return nil, Available() }
func (h *Handle) Started() error       { return Available() }
func (h *Handle) Close()               {}
func (h *Handle) PID() int             { return 0 }
func (h *Handle) HostPipe() string     { return "" }
