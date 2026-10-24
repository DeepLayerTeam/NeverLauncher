package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The host never sends a signal based on a historical PID alone. A request
// identifies the running session and child, and is consumed by its supervisor.
type hostStopRequest0282 struct {
	SessionID   string `json:"sessionId"`
	ProcessPID  int    `json:"processPid"`
	RequestedAt string `json:"requestedAt"`
}

func hostOwnIdentity0282() string { return hostOwnProcessIdentity0282(os.Getpid()) }
func hostOwnProcessIdentity0282(pid int) string {
	identity, err := hostProcessIdentity0282(pid)
	if err != nil {
		return ""
	}
	return identity
}
func hostIdentityMatches0282(pid int, identity string) bool {
	if pid <= 0 || identity == "" {
		return false
	}
	current, err := hostProcessIdentity0282(pid)
	return err == nil && current == identity
}
func hostIdentityForPID0282(pid int, runtimePath string) string {
	state, err := readServerBridgeHostRuntime01910(runtimePath)
	if err != nil || state.SupervisorPID != pid {
		return ""
	}
	return state.SupervisorIdentity
}

func hostTakeStopRequest0282(path, session string, pid int) bool {
	var request hostStopRequest0282
	if err := readJSONFile01910(path, &request); err != nil {
		return false
	}
	if request.SessionID != session || (pid > 0 && request.ProcessPID != pid) {
		return false
	}
	// Best effort removal: the request is session scoped, so a leftover cannot
	// stop a future, distinct supervisor session.
	_ = os.Remove(path)
	return true
}

// Poll rather than blocking in Wait so Minecraft can receive its supported
// console 'stop' command. SIGTERM and SIGKILL are *last resort* stages only.
func hostWaitForChild0282(pid int, stdin io.WriteCloser, wait <-chan error, requestPath, session string, timeoutSeconds int) (error, bool, string) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	childIdentity := hostOwnProcessIdentity0282(pid)
	var graceful <-chan time.Time
	var terminate <-chan time.Time
	stopping := false
	method := ""
	for {
		select {
		case err := <-wait:
			return err, stopping, method
		case <-graceful:
			graceful = nil
			if childIdentity != "" && hostIdentityMatches0282(pid, childIdentity) {
				_ = hostTerminateProcess01910(pid)
				method = "terminate"
				terminate = time.After(2 * time.Second)
			}
		case <-terminate:
			terminate = nil
			if childIdentity != "" && hostIdentityMatches0282(pid, childIdentity) {
				_ = hostKillProcess01910(pid)
				method = "kill"
			}
		case <-ticker.C:
			if stopping || !hostTakeStopRequest0282(requestPath, session, pid) {
				continue
			}
			stopping = true
			method = "console-stop"
			_, _ = io.WriteString(stdin, "stop\n")
			_ = stdin.Close()
			graceful = time.After(time.Duration(timeoutSeconds) * time.Second)
		}
	}
}

func hostRestartDelay0282(baseMillis int, attempt int) time.Duration {
	if baseMillis <= 0 {
		return 0
	}
	if attempt < 1 {
		attempt = 1
	}
	multiplier := 1
	for i := 1; i < attempt && multiplier < 32; i++ {
		multiplier *= 2
	}
	delay := time.Duration(baseMillis) * time.Millisecond * time.Duration(multiplier)
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}
func hostDefaultInt0282(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
func hostWaitBackoff0282(duration time.Duration, requestPath, session string) bool {
	deadline := time.Now().Add(duration)
	for {
		if hostTakeStopRequest0282(requestPath, session, 0) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		sleep := time.Until(deadline)
		if sleep > 75*time.Millisecond {
			sleep = 75 * time.Millisecond
		}
		time.Sleep(sleep)
	}
}

var hostEnvKeyPattern0282 = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var hostBaseEnvAllowlist0282 = []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ", "TMPDIR", "TMP", "TEMP", "SystemRoot", "WINDIR"}

func validateHostEnvKey0282(key string) error {
	if !hostEnvKeyPattern0282.MatchString(key) {
		return fmt.Errorf("invalid environment variable name %q", key)
	}
	return nil
}
func hostAllowlisted0282(allowlist []string, name string) bool {
	for _, key := range allowlist {
		if key == name {
			return true
		}
	}
	return false
}
func hostUniqueSorted0282(values []string) []string {
	keys := map[string]bool{}
	for _, value := range values {
		keys[value] = true
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
func hostChildEnvironment0282(config serverBridgeHostConfig01910) []string {
	// Zero inheritance for old configs: no implicit credentials/tokens/JVM injections.
	allow := config.EnvAllowlist
	if len(allow) == 0 {
		allow = hostBaseEnvAllowlist0282
	}
	env := map[string]string{}
	for _, key := range allow {
		if value, ok := os.LookupEnv(key); ok {
			env[key] = value
		}
	}
	for key, value := range config.Environment {
		env[key] = value
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+env[key])
	}
	return result
}
func hostRedactedConfig0282(config serverBridgeHostConfig01910) serverBridgeHostConfig01910 {
	if len(config.Environment) == 0 {
		return config
	}
	masked := make(map[string]string, len(config.Environment))
	for key := range config.Environment {
		masked[key] = "[REDACTED]"
	}
	config.Environment = masked
	return config
}
func hostResolveDirectory0282(root, directory string) (string, error) {
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	path := directory
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("working directory is not a directory")
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootResolved, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("working directory escapes server root")
	}
	return filepath.Clean(path), nil
}

// Rolling writers protect stdout, stderr and combined streams independently.
// Every append and rename is serialized; rotated log files remain mode 0600.
type hostRollingWriter0282 struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	max     int64
	backups int
	size    int64
}

func newHostRollingWriter0282(path string, max int64, backups int) (*hostRollingWriter0282, error) {
	if max == 0 {
		max = 20 * 1024 * 1024
	}

	if max < 1024 || backups < 0 || backups > 32 {
		return nil, errors.New("invalid rolling log limits")
	}
	writer := &hostRollingWriter0282{path: path, max: max, backups: backups}
	err := writer.open()
	return writer, err
}
func (w *hostRollingWriter0282) open() error {
	if info, err := os.Lstat(w.path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to write to non-regular log %s", w.path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file, w.size = f, info.Size()
	return nil
}
func (w *hostRollingWriter0282) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	if w.backups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.backups))
		for i := w.backups - 1; i >= 1; i-- {
			old, next := fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1)
			if err := os.Rename(old, next); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := os.Rename(w.path, w.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if err := os.Remove(w.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return w.open()
}
func (w *hostRollingWriter0282) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, errors.New("log closed")
	}
	written := 0
	for len(p) > 0 {
		if w.size >= w.max {
			if err := w.rotate(); err != nil {
				return written, err
			}
		}
		n := len(p)
		if int64(n) > w.max-w.size {
			n = int(w.max - w.size)
		}
		count, err := w.file.Write(p[:n])
		written += count
		w.size += int64(count)
		p = p[count:]
		if err != nil {
			return written, err
		}
		if count != n {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
func (w *hostRollingWriter0282) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
