package extensionhost

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/linuxsandbox"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/macossandbox"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/windowssandbox"
)

// A sandbox can be reported as isolated only after Started has confirmed that
// the kernel applied its process identity and resource boundary. This is not
// inferred from the manifest or the successful spawning of a bootstrapper.
type extensionSandbox03111 struct {
	Cmd     *exec.Cmd
	linux   *linuxsandbox.Handle
	windows *windowssandbox.Handle
	macos   *macossandbox.Handle
}

func (s *extensionSandbox03111) Close() {
	if s == nil {
		return
	}
	if s.linux != nil {
		s.linux.Close()
	}
	if s.windows != nil {
		s.windows.Close()
	}
	if s.macos != nil {
		s.macos.Close()
	}
}
func (s *extensionSandbox03111) Started() error {
	if s == nil {
		return fmt.Errorf("sandbox-not-prepared")
	}
	if s.linux != nil {
		return s.linux.Started()
	}
	if s.windows != nil {
		return s.windows.Started()
	}
	if s.macos != nil {
		return s.macos.Started()
	}
	return fmt.Errorf("sandbox-platform-not-implemented")
}
func (s *extensionSandbox03111) PID() int {
	if s != nil && s.macos != nil {
		return s.macos.PID()
	}
	if s != nil && s.windows != nil {
		return s.windows.PID()
	}
	if s != nil && s.Cmd != nil && s.Cmd.Process != nil {
		return s.Cmd.Process.Pid
	}
	return 0
}
func prepareExtensionSandbox03111(root, entrypoint string, cmd *exec.Cmd, baseURL string, handler http.Handler, policy *model.ExtensionSandboxPolicy) (*extensionSandbox03111, error) {
	if policy == nil || policy.Mode != "isolated" {
		return nil, fmt.Errorf("sandbox-policy-not-isolated")
	}
	switch runtime.GOOS {
	case "linux":
		h, e := linuxsandbox.Prepare(linuxsandbox.Options{PayloadRoot: root, Entrypoint: entrypoint, Args: cmd.Args[1:], Environment: cmd.Env, HostURL: baseURL, HostHandler: handler,
			Policy: linuxsandbox.Policy{FilesystemRead: policy.FilesystemRead, FilesystemWrite: policy.FilesystemWrite, NetworkOutbound: policy.NetworkOutbound, Secrets: policy.Secrets,
				MaxMemoryBytes: policy.MaxMemoryBytes, MaxProcesses: policy.MaxProcesses, MaxCPUPercent: policy.MaxCPUPercent, TimeoutSeconds: policy.TimeoutSeconds}})
		if e != nil {
			return nil, e
		}
		return &extensionSandbox03111{Cmd: h.Cmd, linux: h}, nil
	case "windows":
		h, e := windowssandbox.Prepare(windowssandbox.Options{PayloadRoot: root, Entrypoint: entrypoint, Args: cmd.Args[1:], Environment: cmd.Env, HostURL: baseURL, HostHandler: handler,
			Policy: windowssandbox.Policy{FilesystemRead: policy.FilesystemRead, FilesystemWrite: policy.FilesystemWrite, NetworkOutbound: policy.NetworkOutbound, Secrets: policy.Secrets,
				MaxMemoryBytes: policy.MaxMemoryBytes, MaxProcesses: policy.MaxProcesses, MaxCPUPercent: policy.MaxCPUPercent, TimeoutSeconds: policy.TimeoutSeconds}})
		if e != nil {
			return nil, e
		}
		return &extensionSandbox03111{Cmd: h.Cmd, windows: h}, nil
	case "darwin":
		h, e := macossandbox.Prepare(macossandbox.Options{PayloadRoot: root, Entrypoint: entrypoint, Args: cmd.Args[1:], Environment: cmd.Env, HostURL: baseURL, HostHandler: handler,
			Policy: macossandbox.Policy{FilesystemRead: policy.FilesystemRead, FilesystemWrite: policy.FilesystemWrite, NetworkOutbound: policy.NetworkOutbound, Secrets: policy.Secrets,
				MaxMemoryBytes: policy.MaxMemoryBytes, MaxProcesses: policy.MaxProcesses, MaxCPUPercent: policy.MaxCPUPercent, TimeoutSeconds: policy.TimeoutSeconds}})
		if e != nil {
			return nil, e
		}
		return &extensionSandbox03111{Cmd: h.Cmd, macos: h}, nil
	default:
		return nil, fmt.Errorf("sandbox-unavailable-for-platform-%s", runtime.GOOS)
	}
}
