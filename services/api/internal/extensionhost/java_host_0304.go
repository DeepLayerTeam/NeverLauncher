package extensionhost

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const javaRPCVersion0304 = "1.0"
const javaHostMain0304 = "ru.neverlauncher.sdk.host.JavaExtensionHost"

var javaExtensionClass0304 = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]{1,200}$`)

// validateJavaJar0304 rejects malformed/non-host JARs before executing any JVM code.
// Package integrity and publisher trust are still enforced by the existing installer.
func validateJavaJar0304(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() > 128<<20 || st.Size() < 64 {
		return errors.New("Java entrypoint must be a regular JAR of at most 128 MiB")
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open Java JAR: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > 4096 {
		return errors.New("Java JAR has too many entries")
	}
	var descriptor *zip.File
	classes := map[string]bool{}
	seen := map[string]bool{}
	var total uint64
	for _, f := range zr.File {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(f.Name)))
		if f.Name == "" || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "\\") || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("invalid Java JAR archive entry path")
		}
		if seen[f.Name] {
			return errors.New("duplicate Java JAR entry")
		}
		seen[f.Name] = true
		if f.UncompressedSize64 > 32<<20 {
			return errors.New("oversized Java JAR entry")
		}
		total += f.UncompressedSize64
		if total > 384<<20 {
			return errors.New("oversized Java JAR uncompressed contents")
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return errors.New("Java JAR contains a symlink")
		}
		if f.Name == "META-INF/MANIFEST.MF" {
			if descriptor != nil {
				return errors.New("duplicate JAR manifest")
			}
			descriptor = f
		}
		if strings.HasSuffix(f.Name, ".class") {
			classes[f.Name] = true
		}
	}
	if descriptor == nil || descriptor.UncompressedSize64 > 65536 {
		return errors.New("Java JAR manifest missing or oversized")
	}
	r, err := descriptor.Open()
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	_ = r.Close()
	if err != nil {
		return err
	}
	attributes := map[string]string{}
	var current string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if current == "" {
				return errors.New("invalid JAR manifest continuation")
			}
			attributes[current] += strings.TrimPrefix(line, " ")
			continue
		}
		kv := strings.SplitN(line, ": ", 2)
		if len(kv) != 2 {
			return errors.New("invalid JAR manifest attribute")
		}
		current = strings.ToLower(kv[0])
		if _, exists := attributes[current]; exists {
			return errors.New("duplicate JAR manifest attribute")
		}
		attributes[current] = kv[1]
	}
	if attributes["main-class"] != javaHostMain0304 {
		return fmt.Errorf("JAR Main-Class must be %s", javaHostMain0304)
	}
	class := attributes["neverlauncher-extension-class"]
	if !javaExtensionClass0304.MatchString(class) || strings.Contains(class, "..") {
		return errors.New("invalid NeverLauncher-Extension-Class")
	}
	if _, ok := attributes["class-path"]; ok {
		return errors.New("external Java JAR Class-Path is not supported")
	}
	if !classes[strings.ReplaceAll(class, ".", "/")+".class"] {
		return errors.New("extension implementation class missing from JAR")
	}
	if !classes["ru/neverlauncher/sdk/host/JavaExtensionHost.class"] {
		return errors.New("Java Extension Host implementation class missing from JAR")
	}
	return nil
}

// javaCommand0304 resolves a trusted Java executable; never accepts Java command arguments from a package.
func (s *Supervisor) javaCommand0304(jar string, argv []string) (*exec.Cmd, error) {
	java := strings.TrimSpace(s.cfg.JavaExecutable)
	if java != "" {
		if !filepath.IsAbs(java) {
			return nil, errors.New("configured Java executable must be absolute")
		}
		info, err := os.Lstat(java)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("configured Java executable must be regular, not symlink")
		}
	} else {
		var err error
		java, err = exec.LookPath("java")
		if err != nil {
			return nil, fmt.Errorf("Java 17+ runtime missing: %w", err)
		}
	}
	heapMiB := s.cfg.MaxMemoryBytes / (1 << 20) * 65 / 100
	if heapMiB < 32 {
		heapMiB = 32
	}
	if heapMiB > 4096 {
		heapMiB = 4096
	}
	args := []string{"-XX:+ExitOnOutOfMemoryError", "-Djava.awt.headless=true", "-Dfile.encoding=UTF-8", fmt.Sprintf("-Xmx%dm", heapMiB), "-jar", jar}
	args = append(args, argv...)
	return exec.Command(java, args...), nil
}

type javaRPCRequest0304 struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
	DeadlineMs      int64           `json:"deadlineMs"`
}
type javaRPCResponse0304 struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	OK              bool            `json:"ok"`
	Result          json.RawMessage `json:"result"`
}

// CallJavaRPC0304 performs an authenticated, deadline-bound Go -> JVM request.
// It is intentionally usable only for a running Java target registered by this supervisor.
func (s *Supervisor) CallJavaRPC0304(ctx context.Context, key Key, method string, params json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "health", "command.invoke", "event.deliver", "hook.deliver":
	default:
		return nil, errors.New("unsupported Java RPC method")
	}
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if len(params) > 64<<10 || !json.Valid(params) || params[0] != '{' {
		return nil, errors.New("Java RPC params must be a bounded JSON object")
	}
	key = key.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return nil, ErrHostNotRunning
	}
	st.mu.Lock()
	running := st.state == "running" && st.javaHost
	endpoint, token := st.callbackURL, st.callbackToken
	st.mu.Unlock()
	if !running || endpoint == "" {
		return nil, ErrHostNotRunning
	}
	return s.callJavaProcess0304(ctx, endpoint, token, method, params)
}
func (s *Supervisor) callJavaProcess0304(ctx context.Context, endpoint, token, method string, params json.RawMessage) (json.RawMessage, error) {
	budget := s.cfg.CapabilityTimeout
	if budget > 1800*time.Millisecond {
		budget = 1800 * time.Millisecond
	}
	if budget <= 0 {
		budget = 1800 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	id, err := randomHex(12)
	if err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(javaRPCRequest0304{ProtocolVersion: javaRPCVersion0304, RequestID: id, Method: method, Params: params, DeadlineMs: int64(budget.Milliseconds())})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/rpc", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.callbackClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Java RPC %s failed: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(body) > 65536 {
		return nil, errors.New("Java RPC response exceeds 64 KiB")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Java RPC %s returned HTTP %d", method, resp.StatusCode)
	}
	var answer javaRPCResponse0304
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&answer); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing Java RPC response data")
	}
	if !answer.OK || answer.ProtocolVersion != javaRPCVersion0304 || answer.RequestID != id || !json.Valid(answer.Result) {
		return nil, errors.New("Java RPC protocol or request identity mismatch")
	}
	return answer.Result, nil
}

// probeJava0304 runs independently of the supervisor's heartbeat/resource monitor.
// A noncooperative callback can keep sending heartbeats but will not keep an unresponsive JVM alive.
func (s *Supervisor) probeJava0304(st *processState) {
	defer func() { st.mu.Lock(); st.rpcBusy = false; st.mu.Unlock() }()
	st.mu.Lock()
	endpoint, token := st.callbackURL, st.callbackToken
	st.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.CapabilityTimeout)
	defer cancel()
	payload, err := s.callJavaProcess0304(ctx, endpoint, token, "health", json.RawMessage(`{}`))
	if err == nil {
		var result struct {
			State      string `json:"state"`
			Responsive bool   `json:"responsive"`
		}
		if e := json.Unmarshal(payload, &result); e != nil || !result.Responsive || result.State != "RUNNING" {
			err = errors.New("Java host is not in RUNNING state")
		}
	}
	st.mu.Lock()
	if st.state != "running" {
		st.mu.Unlock()
		return
	}
	if err == nil {
		st.rpcFailures = 0
		st.mu.Unlock()
		return
	}
	st.rpcFailures++
	failures := st.rpcFailures
	st.mu.Unlock()
	s.addLog(st, "host", "warn", fmt.Sprintf("Java RPC liveness probe failed (%d/3): %v", failures, err), nil)
	if failures >= 3 {
		s.failProcess(st, "Java RPC unresponsive after 3 probes", false)
	}
}

// Package-level check to keep the Java JAR verifier independent of OS process setup.
func sameHostJar0304(path string) bool { return strings.EqualFold(filepath.Ext(path), ".jar") }
