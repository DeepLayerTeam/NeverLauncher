package extensionhost

import (
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
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionjava"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const javaRPCVersion0304 = "1.0"

// All JAR validation is shared with the lifecycle preflight (0.30.5).
// Never downgrade checks when an operator starts a JAR outside the installer.
func validateJavaJar0304(path string) error {
	_, err := extensionjava.Inspect(path)
	return err
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
	case "health", "command.invoke", "event.deliver", "hook.deliver", "auth.health", "auth.password", "auth.resolve", "auth.session.verify", "auth.session.revoke", "content.health", "content.source.resolve", "content.texture.resolve", "content.delivery.resolve", "content.metadata.enrich", "content.package.prepare", "ui.action.invoke", "ui.settings.get", "ui.settings.put", "state.migrate":
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
	if strings.HasPrefix(method, "auth.") {
		// Authentication connectors are only allowed for explicitly consented,
		// global installations. Project extensions cannot authenticate accounts.
		if key.Scope != "global" || st.manifest.ID != key.ExtensionID {
			return nil, errors.New("Java authentication provider scope denied")
		}
		declared := false
		for _, permission := range st.manifest.Permissions {
			if permission == "auth:provider" {
				declared = true
				break
			}
		}
		if !declared {
			return nil, errors.New("Java authentication capability not declared")
		}
		allowed, err := s.permissionAllowed0207(ctx, st, "auth:provider", "")
		if err != nil || !allowed {
			return nil, errors.New("Java authentication capability revoked or unavailable")
		}
	}
	if strings.HasPrefix(method, "content.") {
		// Content callbacks cannot mint signed releases or bypass the Go broker.
		// A global extension must be granted release:read for the explicit project;
		// a project extension is confined to its installation project.
		var payload struct {
			ProjectID string `json:"projectId"`
		}
		if err := json.Unmarshal(params, &payload); err != nil {
			return nil, errors.New("invalid content project")
		}
		if method != "content.health" {
			id, err := s.scopedProject(st, payload.ProjectID)
			if err != nil {
				return nil, errors.New("content project scope denied")
			}
			permission := "release:read"
			if method == "content.package.prepare" {
				permission = "release:prepare"
			}
			granted, err := s.permissionAllowed0207(ctx, st, permission, id)
			if err != nil || !granted {
				return nil, errors.New("content permission denied or unavailable")
			}
		}
	}
	// UI callbacks are only exposed to signed Admin/Desktop contributions.
	// Never accept arbitrary Java method/handler names from an iframe.
	if strings.HasPrefix(method, "ui.") {
		if err := s.checkJavaUI0489(ctx, st, method, params); err != nil {
			return nil, err
		}
	}
	// A previously authorized supervisor command must not race an emergency
	// disable, revoked publisher or replaced installation. The HTTP broker
	// already checks live trust, but direct Go -> JVM RPC bypasses that broker.
	if err := s.enforceLiveTrust04210(ctx, st); err != nil {
		s.denyRevokedHost04210(st, err)
		return nil, fmt.Errorf("Java RPC denied by current extension trust: %w", err)
	}
	// The process can be stopped/replaced while the durable check is running.
	st.mu.Lock()
	stillRunning := st.state == "running" && st.javaHost && st.callbackURL == endpoint && st.callbackToken == token
	st.mu.Unlock()
	if !stillRunning {
		return nil, ErrHostNotRunning
	}
	result, err := s.callJavaProcess0304(ctx, endpoint, token, method, params)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(method, "auth.") {
		allowed, checkErr := s.permissionAllowed0207(ctx, st, "auth:provider", "")
		if checkErr != nil || !allowed {
			return nil, errors.New("Java authentication permission revoked during operation")
		}
	}
	if strings.HasPrefix(method, "content.") && method != "content.health" {
		var payload struct {
			ProjectID string `json:"projectId"`
		}
		if err := json.Unmarshal(params, &payload); err != nil {
			return nil, errors.New("invalid content scope")
		}
		id, err := s.scopedProject(st, payload.ProjectID)
		if err != nil {
			return nil, err
		}
		permission := "release:read"
		if method == "content.package.prepare" {
			permission = "release:prepare"
		}
		granted, err := s.permissionAllowed0207(ctx, st, permission, id)
		if err != nil || !granted {
			return nil, errors.New("content permission revoked during RPC")
		}
	}
	if strings.HasPrefix(method, "ui.") {
		if err := s.checkJavaUI0489(ctx, st, method, params); err != nil {
			return nil, fmt.Errorf("Java UI authorization revoked during RPC: %w", err)
		}
	}
	if method == "state.migrate" {
		if err := s.enforceLiveTrust04210(ctx, st); err != nil {
			return nil, fmt.Errorf("Java state migration trust revoked: %w", err)
		}
	}
	return result, nil
}
func (s *Supervisor) callJavaProcess0304(ctx context.Context, endpoint, token, method string, params json.RawMessage) (json.RawMessage, error) {
	budget := s.cfg.CapabilityTimeout
	if method == "state.migrate" {
		// State migrations are bounded separately from ordinary interactive RPC;
		// the global HTTP callback timeout is 10 seconds by default.
		budget = 8 * time.Second
	} else {
		if budget > 1800*time.Millisecond {
			budget = 1800 * time.Millisecond
		}
		if budget <= 0 {
			budget = 1800 * time.Millisecond
		}
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

// MigrateExtensionState04810 invokes the new, already authenticated JVM's
// registered migration graph. The update manager owns durable checkpoints,
// restarts and compensation; this method never bypasses live trust or grants.
func (s *Supervisor) MigrateExtensionState04810(ctx context.Context, install model.ExtensionInstall, fromVersion string) error {
	if fromVersion == "" || fromVersion == install.CurrentVersion {
		return nil
	}
	// Non-Java extensions have no Java callback. Their state is preserved
	// unchanged by the same durable checkpoint/rollback path.
	version, err := s.repo.GetExtensionVersion(ctx, install.ExtensionID, install.CurrentVersion)
	if err != nil {
		return err
	}
	target, err := backendTarget(version.Manifest)
	if errors.Is(err, ErrNoBackendTarget) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = target
	key := Key{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID}.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return ErrHostNotRunning
	}
	st.mu.Lock()
	java := st.javaHost
	sameVersion := st.install.CurrentVersion == install.CurrentVersion && st.install.Generation == install.Generation && st.install.CurrentPackageIdentity == install.CurrentPackageIdentity
	st.mu.Unlock()
	if !sameVersion {
		return errors.New("extension generation changed during state migration")
	}
	if !java {
		return nil
	}
	params, err := json.Marshal(map[string]string{"fromVersion": fromVersion, "toVersion": install.CurrentVersion})
	if err != nil {
		return err
	}
	body, err := s.CallJavaRPC0304(ctx, key, "state.migrate", params)
	if err != nil {
		return fmt.Errorf("state migration callback failed: %w", err)
	}
	var answer struct {
		FromVersion string `json:"fromVersion"`
		ToVersion   string `json:"toVersion"`
		Applied     bool   `json:"applied"`
	}
	if err = json.Unmarshal(body, &answer); err != nil {
		return err
	}
	if answer.FromVersion != fromVersion || answer.ToVersion != install.CurrentVersion {
		return errors.New("invalid migration acknowledgement")
	}
	return nil
}
