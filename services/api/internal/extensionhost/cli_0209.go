package extensionhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const maxCLIOutput0209 = int64(2 << 20)

type CLIResult0209 struct {
	ExtensionID string `json:"extensionId"`
	Version     string `json:"version"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId,omitempty"`
	ExitCode    int    `json:"exitCode"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	DurationMs  int64  `json:"durationMs"`
	Protocol    string `json:"protocol"`
}

type boundedBuffer0209 struct {
	mu        sync.Mutex
	b         bytes.Buffer
	max       int64
	truncated bool
}

func (b *boundedBuffer0209) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.max - int64(b.b.Len())
	if remaining <= 0 {
		b.truncated = true
		return n, nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.b.Write(p[:remaining])
		b.truncated = true
		return n, nil
	}
	_, _ = b.b.Write(p)
	return n, nil
}
func (b *boundedBuffer0209) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.b.String()
	if b.truncated {
		s += "\n[output truncated by NeverLauncher]"
	}
	return s
}

func cliTarget0209(manifest model.ExtensionManifest) (model.ExtensionTarget, error) {
	for _, t := range manifest.Targets {
		if strings.EqualFold(t.Kind, "cli") {
			return t, nil
		}
	}
	return model.ExtensionTarget{}, errors.New("extension does not declare a cli target")
}

// RunCLI0209 starts the immutable cli target as a short-lived isolated process.
// The process authenticates to the same loopback Extension Host Protocol as a
// backend extension and therefore receives capabilities only through the
// deny-by-default broker. It never receives the Backend DB/auth/storage secrets.
func (s *Supervisor) RunCLI0209(ctx context.Context, install model.ExtensionInstall, argv []string) (CLIResult0209, error) {
	if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled || install.CurrentVersion == "" {
		return CLIResult0209{}, errors.New("extension must be enabled before cli invocation")
	}
	if len(argv) == 0 || len(argv) > 128 {
		return CLIResult0209{}, errors.New("cli invocation requires 1..128 arguments")
	}
	total := 0
	for _, arg := range argv {
		total += len(arg)
		if len(arg) > 16<<10 || strings.ContainsRune(arg, '\x00') {
			return CLIResult0209{}, errors.New("invalid cli argument")
		}
	}
	if total > 128<<10 {
		return CLIResult0209{}, errors.New("cli arguments exceed 128 KiB")
	}
	ver, err := s.repo.GetExtensionVersion(ctx, install.ExtensionID, install.CurrentVersion)
	if err != nil {
		return CLIResult0209{}, err
	}
	target, err := cliTarget0209(ver.Manifest)
	if err != nil {
		return CLIResult0209{}, err
	}
	security := s.securityValue0207()
	if security == nil {
		return CLIResult0209{}, errors.New("extension capability security unavailable")
	}
	projectID := ""
	if install.Scope == "project" {
		projectID = install.ScopeID
	}
	allowed, err := security.Allowed(ctx, install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, "cli:contribute", projectID)
	if err != nil {
		return CLIResult0209{}, fmt.Errorf("load cli capability policy: %w", err)
	}
	if !allowed {
		return CLIResult0209{}, errors.New("cli:contribute is not granted")
	}
	payloadRoot, err := extensionlifecycle.CurrentPayloadDir(s.cfg.ExtensionRoot, install.Scope, install.ScopeID, install.ExtensionID)
	if err != nil {
		return CLIResult0209{}, err
	}
	entrypoint, err := safeEntrypoint(payloadRoot, target.Entrypoint)
	if err != nil {
		return CLIResult0209{}, err
	}
	token, err := randomHex(32)
	if err != nil {
		return CLIResult0209{}, err
	}
	callbackToken, err := randomHex(32)
	if err != nil {
		return CLIResult0209{}, err
	}
	instance, err := randomHex(16)
	if err != nil {
		return CLIResult0209{}, err
	}
	effective, err := security.Effective(ctx, install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, projectID)
	if err != nil {
		return CLIResult0209{}, err
	}
	permissions := map[string]struct{}{}
	for _, p := range effective {
		permissions[p] = struct{}{}
	}
	st := &processState{key: Key{install.ExtensionID, install.Scope, install.ScopeID}.normalized(), install: install, manifest: ver.Manifest, permissions: permissions, token: token, callbackToken: callbackToken, instanceID: instance, entrypoint: target.Entrypoint, state: "starting", helloCh: make(chan struct{}), doneCh: make(chan struct{}), logs: ringLog{maxBytes: s.cfg.MaxLogBytes, maxEntries: s.cfg.MaxLogEntries}}
	s.mu.RLock()
	baseURL := s.baseURL
	s.mu.RUnlock()
	if baseURL == "" {
		return CLIResult0209{}, errors.New("extension host protocol server is not started")
	}
	if err := s.registerTransient0209(st); err != nil {
		return CLIResult0209{}, err
	}
	defer s.removeProcessToken(st)
	cmd := exec.Command(entrypoint, argv...)
	cmd.Dir = payloadRoot
	cmd.Env = sanitizedEnvironment(map[string]string{
		"NEVERLAUNCHER_EXTENSION_HOST_URL": baseURL, "NEVERLAUNCHER_EXTENSION_HOST_TOKEN": token, "NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN": callbackToken, "NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL": ProtocolVersion, "NEVERLAUNCHER_EXTENSION_API_VERSION": extensioncontract.ExtensionAPIVersion, "NEVERLAUNCHER_EXTENSION_INSTANCE_ID": instance,
		"NEVERLAUNCHER_EXTENSION_ID": install.ExtensionID, "NEVERLAUNCHER_EXTENSION_VERSION": install.CurrentVersion, "NEVERLAUNCHER_EXTENSION_SCOPE": install.Scope, "NEVERLAUNCHER_EXTENSION_SCOPE_ID": install.ScopeID, "NEVERLAUNCHER_EXTENSION_TARGET": "cli",
	})
	configureProcess(cmd)
	stdout := &boundedBuffer0209{max: maxCLIOutput0209}
	stderr := &boundedBuffer0209{max: maxCLIOutput0209}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	started := time.Now().UTC()
	if err := cmd.Start(); err != nil {
		return CLIResult0209{}, fmt.Errorf("start cli extension: %w", err)
	}
	st.mu.Lock()
	st.cmd = cmd
	st.startedAt = started
	st.processCount = 1
	stopRequested := st.expectedStop
	st.mu.Unlock()
	if stopRequested {
		_ = killProcessTree(cmd.Process)
	}
	waitCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		close(st.doneCh)
		waitCh <- err
	}()
	startup := time.NewTimer(s.cfg.StartupTimeout)
	defer startup.Stop()
	select {
	case <-st.helloCh:
	case waitErr := <-waitCh:
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		result := CLIResult0209{ExtensionID: install.ExtensionID, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String(), DurationMs: time.Since(started).Milliseconds(), Protocol: ProtocolVersion}
		if waitErr != nil {
			return result, fmt.Errorf("cli extension exited before authenticated hello: %w", waitErr)
		}
		return result, errors.New("cli extension exited before authenticated hello")
	case <-startup.C:
		_ = killProcessTree(cmd.Process)
		return CLIResult0209{}, fmt.Errorf("cli extension hello timeout after %s", s.cfg.StartupTimeout)
	case <-ctx.Done():
		_ = killProcessTree(cmd.Process)
		return CLIResult0209{}, ctx.Err()
	case <-s.ctx.Done():
		_ = killProcessTree(cmd.Process)
		return CLIResult0209{}, errors.New("extension host is shutting down")
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case waitErr := <-waitCh:
			code := 0
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
			}
			result := CLIResult0209{ExtensionID: install.ExtensionID, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String(), DurationMs: time.Since(started).Milliseconds(), Protocol: ProtocolVersion}
			if waitErr != nil || code != 0 {
				return result, fmt.Errorf("cli extension exited with code %d", code)
			}
			return result, nil
		case <-ticker.C:
			if cmd.Process != nil {
				if rss, count, e := processTreeUsage(cmd.Process.Pid); e == nil {
					if s.cfg.MaxMemoryBytes > 0 && rss > s.cfg.MaxMemoryBytes {
						_ = killProcessTree(cmd.Process)
						return CLIResult0209{}, fmt.Errorf("cli extension memory limit exceeded: %d > %d", rss, s.cfg.MaxMemoryBytes)
					}
					if s.cfg.MaxProcesses > 0 && count > s.cfg.MaxProcesses {
						_ = killProcessTree(cmd.Process)
						return CLIResult0209{}, fmt.Errorf("cli extension process limit exceeded: %d > %d", count, s.cfg.MaxProcesses)
					}
				}
			}
		case <-ctx.Done():
			_ = terminateProcessTree(cmd.Process)
			select {
			case <-waitCh:
			case <-time.After(s.cfg.StopTimeout):
				_ = killProcessTree(cmd.Process)
			}
			return CLIResult0209{}, ctx.Err()
		case <-s.ctx.Done():
			_ = terminateProcessTree(cmd.Process)
			select {
			case <-waitCh:
			case <-time.After(s.cfg.StopTimeout):
				_ = killProcessTree(cmd.Process)
			}
			return CLIResult0209{}, errors.New("extension host is shutting down")
		}
	}
}
