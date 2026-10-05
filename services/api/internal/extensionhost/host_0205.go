package extensionhost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/eventbus"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

const ProtocolVersion = "1.0"

var ErrNoBackendTarget = errors.New("extension does not declare a backend target")
var ErrHostNotRunning = errors.New("extension host process is not running")

type Config struct {
	ExtensionRoot        string
	Listen               string
	StartupTimeout       time.Duration
	HeartbeatTimeout     time.Duration
	StopTimeout          time.Duration
	CapabilityTimeout    time.Duration
	MaxMemoryBytes       int64
	MaxProcesses         int
	MaxLogBytes          int64
	MaxLogEntries        int
	MaxProtocolBody      int64
	MaxStorageReadBytes  int64
	MaxHTTPRequestBytes  int64
	MaxHTTPResponseBytes int64
	HTTPTimeout          time.Duration
	CrashLimit           int
	CrashWindow          time.Duration
	RestartBackoff       time.Duration
}

func (c Config) normalized() Config {
	if strings.TrimSpace(c.ExtensionRoot) == "" {
		c.ExtensionRoot = "./data/extensions"
	}
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = "127.0.0.1:0"
	}
	if c.StartupTimeout <= 0 {
		c.StartupTimeout = 10 * time.Second
	}
	if c.HeartbeatTimeout <= 0 {
		c.HeartbeatTimeout = 30 * time.Second
	}
	if c.StopTimeout <= 0 {
		c.StopTimeout = 5 * time.Second
	}
	if c.CapabilityTimeout <= 0 {
		c.CapabilityTimeout = 3 * time.Second
	}
	if c.MaxMemoryBytes <= 0 {
		c.MaxMemoryBytes = 512 << 20
	}
	if c.MaxProcesses <= 0 {
		c.MaxProcesses = 8
	}
	if c.MaxLogBytes <= 0 {
		c.MaxLogBytes = 4 << 20
	}
	if c.MaxLogEntries <= 0 {
		c.MaxLogEntries = 1000
	}
	if c.MaxProtocolBody <= 0 {
		c.MaxProtocolBody = 1 << 20
	}
	if c.MaxStorageReadBytes <= 0 {
		c.MaxStorageReadBytes = 1 << 20
	}
	if c.MaxHTTPRequestBytes <= 0 {
		c.MaxHTTPRequestBytes = 256 << 10
	}
	if c.MaxHTTPResponseBytes <= 0 {
		c.MaxHTTPResponseBytes = 1 << 20
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 10 * time.Second
	}
	if c.CrashLimit <= 0 {
		c.CrashLimit = 5
	}
	if c.CrashWindow <= 0 {
		c.CrashWindow = 10 * time.Minute
	}
	if c.RestartBackoff <= 0 {
		c.RestartBackoff = time.Second
	}
	c.ExtensionRoot = filepath.Clean(c.ExtensionRoot)
	return c
}

type Key struct{ ExtensionID, Scope, ScopeID string }

func (k Key) normalized() Key {
	k.ExtensionID = strings.ToLower(strings.TrimSpace(k.ExtensionID))
	k.Scope = strings.ToLower(strings.TrimSpace(k.Scope))
	k.ScopeID = strings.TrimSpace(k.ScopeID)
	if k.Scope == "" {
		k.Scope = "global"
	}
	if k.Scope == "global" {
		k.ScopeID = ""
	}
	return k
}
func (k Key) String() string {
	k = k.normalized()
	return k.Scope + "\x00" + k.ScopeID + "\x00" + k.ExtensionID
}

type LogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Stream    string         `json:"stream"`
	Level     string         `json:"level,omitempty"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type Status struct {
	ExtensionID       string     `json:"extensionId"`
	Scope             string     `json:"scope"`
	ScopeID           string     `json:"scopeId,omitempty"`
	Version           string     `json:"version,omitempty"`
	Generation        int64      `json:"generation"`
	InstanceID        string     `json:"instanceId,omitempty"`
	PID               int        `json:"pid,omitempty"`
	State             string     `json:"state"`
	Healthy           bool       `json:"healthy"`
	StartedAt         *time.Time `json:"startedAt,omitempty"`
	HelloAt           *time.Time `json:"helloAt,omitempty"`
	LastHeartbeatAt   *time.Time `json:"lastHeartbeatAt,omitempty"`
	ExitedAt          *time.Time `json:"exitedAt,omitempty"`
	ExitCode          *int       `json:"exitCode,omitempty"`
	Restarts          int        `json:"restarts"`
	LastError         string     `json:"lastError,omitempty"`
	MemoryBytes       int64      `json:"memoryBytes,omitempty"`
	ProcessCount      int        `json:"processCount,omitempty"`
	ResourceIsolation string     `json:"resourceIsolation"`
	Permissions       []string   `json:"permissions,omitempty"`
	Entrypoint        string     `json:"entrypoint,omitempty"`
}

type ringLog struct {
	entries    []LogEntry
	bytes      int64
	maxBytes   int64
	maxEntries int
}

func (r *ringLog) add(e LogEntry) {
	if len(e.Message) > 64<<10 {
		e.Message = e.Message[:64<<10] + "…"
	}
	size := int64(len(e.Message) + len(e.Stream) + len(e.Level) + 64)
	r.entries = append(r.entries, e)
	r.bytes += size
	for len(r.entries) > r.maxEntries || r.bytes > r.maxBytes {
		if len(r.entries) == 0 {
			break
		}
		old := r.entries[0]
		r.bytes -= int64(len(old.Message) + len(old.Stream) + len(old.Level) + 64)
		r.entries = r.entries[1:]
	}
}
func (r *ringLog) list(limit int) []LogEntry {
	if limit <= 0 || limit > r.maxEntries {
		limit = r.maxEntries
	}
	start := len(r.entries) - limit
	if start < 0 {
		start = 0
	}
	return append([]LogEntry(nil), r.entries[start:]...)
}

type processState struct {
	mu                                                        sync.Mutex
	key                                                       Key
	install                                                   model.ExtensionInstall
	manifest                                                  model.ExtensionManifest
	permissions                                               map[string]struct{}
	token, callbackToken, callbackURL, instanceID, entrypoint string
	cmd                                                       *exec.Cmd
	state                                                     string
	startedAt, helloAt, heartbeatAt, exitedAt                 time.Time
	exitCode                                                  *int
	lastError                                                 string
	memoryBytes                                               int64
	processCount                                              int
	expectedStop                                              bool
	restarts                                                  int
	helloCh                                                   chan struct{}
	helloOnce                                                 sync.Once
	doneCh                                                    chan struct{}
	logs                                                      ringLog
}

type Supervisor struct {
	cfg            Config
	repo           repository.Repository
	storage        storage.Storage
	mu             sync.RWMutex
	processes      map[string]*processState
	tokens         map[string]*processState
	crashes        map[string][]time.Time
	restarts       map[string]int
	listener       net.Listener
	server         *http.Server
	baseURL        string
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	eventBus       *eventbus.Bus
	security       *extensionsecurity.Manager
	callbackClient *http.Client
}

func New(cfg Config, repo repository.Repository, store storage.Storage) *Supervisor {
	cfg = cfg.normalized()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, MaxIdleConns: 16, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	security, _ := extensionsecurity.New(repo, nil)
	return &Supervisor{cfg: cfg, repo: repo, storage: store, processes: map[string]*processState{}, tokens: map[string]*processState{}, crashes: map[string][]time.Time{}, restarts: map[string]int{}, security: security, callbackClient: client}
}

func (s *Supervisor) SetSecurity(security *extensionsecurity.Manager) {
	s.mu.Lock()
	s.security = security
	s.mu.Unlock()
}
func (s *Supervisor) securityValue0207() *extensionsecurity.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.security
}

func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen extension host protocol: %w", err)
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcp.IP == nil || !tcp.IP.IsLoopback() {
		_ = ln.Close()
		return errors.New("extension host protocol must listen on loopback only")
	}
	s.listener = ln
	s.baseURL = "http://" + ln.Addr().String()
	s.ctx, s.cancel = context.WithCancel(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/hello", s.handleHello)
	mux.HandleFunc("POST /v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /v1/log", s.handleLog)
	mux.HandleFunc("POST /v1/capabilities/{capability}", s.handleCapability)
	mux.HandleFunc("GET /v1/events/subscriptions", s.handleEventSubscriptions)
	mux.HandleFunc("POST /v1/events/subscriptions", s.handleEventSubscribe)
	mux.HandleFunc("DELETE /v1/events/subscriptions/{subscriptionId}", s.handleEventUnsubscribe)
	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("extension host protocol server failed: %v", err)
		}
	}()
	go s.monitorLoop()
	return nil
}

func (s *Supervisor) Close(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	statuses := s.List()
	for _, st := range statuses {
		_ = s.Stop(context.Background(), Key{st.ExtensionID, st.Scope, st.ScopeID})
	}
	var err error
	if s.server != nil {
		err = s.server.Shutdown(ctx)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func backendTarget(manifest model.ExtensionManifest) (model.ExtensionTarget, error) {
	for _, t := range manifest.Targets {
		if t.Kind == "backend" {
			return t, nil
		}
	}
	return model.ExtensionTarget{}, ErrNoBackendTarget
}

func safeEntrypoint(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", errors.New("invalid backend extension entrypoint")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("backend extension entrypoint escapes payload")
	}
	full := filepath.Join(root, clean)
	rootAbs, _ := filepath.Abs(root)
	fullAbs, _ := filepath.Abs(full)
	if fullAbs == rootAbs || !strings.HasPrefix(fullAbs, rootAbs+string(os.PathSeparator)) {
		return "", errors.New("backend extension entrypoint escapes payload")
	}
	info, err := os.Lstat(fullAbs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("backend extension entrypoint must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("backend extension entrypoint is not executable")
	}
	return fullAbs, nil
}

var safeEnvKeys = map[string]struct{}{"PATH": {}, "HOME": {}, "USERPROFILE": {}, "SYSTEMROOT": {}, "WINDIR": {}, "TMP": {}, "TEMP": {}, "TMPDIR": {}, "LANG": {}, "LC_ALL": {}, "TZ": {}}

func sanitizedEnvironment(extra map[string]string) []string {
	env := make([]string, 0, len(safeEnvKeys)+len(extra))
	for _, raw := range os.Environ() {
		p := strings.IndexByte(raw, '=')
		if p <= 0 {
			continue
		}
		key := strings.ToUpper(raw[:p])
		if _, ok := safeEnvKeys[key]; ok {
			env = append(env, raw)
		}
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+extra[k])
	}
	return env
}

func (s *Supervisor) StartInstallation(ctx context.Context, install model.ExtensionInstall) error {
	if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled {
		return errors.New("extension must be persistently enabled before host start")
	}
	key := Key{install.ExtensionID, install.Scope, install.ScopeID}.normalized()
	k := key.String()
	manifestVersion, err := s.repo.GetExtensionVersion(ctx, install.ExtensionID, install.CurrentVersion)
	if err != nil {
		return err
	}
	target, err := backendTarget(manifestVersion.Manifest)
	if err != nil {
		return err
	}
	payloadRoot, err := extensionlifecycle.CurrentPayloadDir(s.cfg.ExtensionRoot, key.Scope, key.ScopeID, key.ExtensionID)
	if err != nil {
		return err
	}
	entrypoint, err := safeEntrypoint(payloadRoot, target.Entrypoint)
	if err != nil {
		return err
	}
	token, err := randomHex(32)
	if err != nil {
		return err
	}
	callbackToken, err := randomHex(32)
	if err != nil {
		return err
	}
	instance, err := randomHex(16)
	if err != nil {
		return err
	}
	security := s.securityValue0207()
	if security == nil {
		return errors.New("extension capability security is unavailable")
	}
	projectID := ""
	if key.Scope == "project" {
		projectID = key.ScopeID
	}
	effective, err := security.Effective(ctx, install.ExtensionID, install.CurrentVersion, key.Scope, key.ScopeID, projectID)
	if err != nil {
		return fmt.Errorf("load extension capability policy: %w", err)
	}
	permissions := map[string]struct{}{}
	for _, p := range effective {
		permissions[p] = struct{}{}
	}
	st := &processState{key: key, install: install, manifest: manifestVersion.Manifest, permissions: permissions, token: token, callbackToken: callbackToken, instanceID: instance, entrypoint: target.Entrypoint, state: "starting", helloCh: make(chan struct{}), doneCh: make(chan struct{}), logs: ringLog{maxBytes: s.cfg.MaxLogBytes, maxEntries: s.cfg.MaxLogEntries}}
	s.mu.Lock()
	if existing := s.processes[k]; existing != nil {
		existing.mu.Lock()
		active := existing.state == "starting" || existing.state == "running" || existing.state == "stopping"
		existing.mu.Unlock()
		if active {
			s.mu.Unlock()
			return fmt.Errorf("extension host already active for %s", key.ExtensionID)
		}
	}
	st.restarts = s.restarts[k]
	s.processes[k] = st
	s.tokens[token] = st
	baseURL := s.baseURL
	s.mu.Unlock()
	if baseURL == "" {
		s.removeProcessToken(st)
		return errors.New("extension host protocol server is not started")
	}
	cmd := exec.Command(entrypoint)
	cmd.Dir = payloadRoot
	cmd.Env = sanitizedEnvironment(map[string]string{
		"NEVERLAUNCHER_EXTENSION_HOST_URL": baseURL, "NEVERLAUNCHER_EXTENSION_HOST_TOKEN": token, "NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN": callbackToken, "NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL": ProtocolVersion, "NEVERLAUNCHER_EXTENSION_INSTANCE_ID": instance,
		"NEVERLAUNCHER_EXTENSION_ID": install.ExtensionID, "NEVERLAUNCHER_EXTENSION_VERSION": install.CurrentVersion, "NEVERLAUNCHER_EXTENSION_SCOPE": install.Scope, "NEVERLAUNCHER_EXTENSION_SCOPE_ID": install.ScopeID,
	})
	configureProcess(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.removeProcessToken(st)
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.removeProcessToken(st)
		return err
	}
	if err := cmd.Start(); err != nil {
		s.removeProcessToken(st)
		return fmt.Errorf("start backend extension: %w", err)
	}
	st.mu.Lock()
	st.cmd = cmd
	st.startedAt = time.Now().UTC()
	st.processCount = 1
	st.mu.Unlock()
	s.addLog(st, "host", "info", fmt.Sprintf("process started pid=%d", cmd.Process.Pid), nil)
	s.wg.Add(3)
	go s.captureStream(st, "stdout", stdout)
	go s.captureStream(st, "stderr", stderr)
	go s.waitProcess(st)
	timer := time.NewTimer(s.cfg.StartupTimeout)
	defer timer.Stop()
	select {
	case <-st.helloCh:
		if err := s.reconcileManifestSubscriptions0206(ctx, st); err != nil {
			s.failProcess(st, "event subscription reconcile failed: "+err.Error(), true)
			return err
		}
		return nil
	case <-st.doneCh:
		st.mu.Lock()
		msg := st.lastError
		st.mu.Unlock()
		if msg == "" {
			msg = "extension process exited before authenticated hello"
		}
		return errors.New(msg)
	case <-timer.C:
		s.failProcess(st, "startup hello timeout", true)
		return fmt.Errorf("extension host startup timeout after %s", s.cfg.StartupTimeout)
	case <-ctx.Done():
		s.failProcess(st, "startup cancelled", true)
		return ctx.Err()
	}
}

func (s *Supervisor) removeProcessToken(st *processState) {
	s.mu.Lock()
	if st.token != "" {
		delete(s.tokens, st.token)
	}
	s.mu.Unlock()
}
func (s *Supervisor) captureStream(st *processState, stream string, r io.Reader) {
	defer s.wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		s.addLog(st, stream, "", sc.Text(), nil)
	}
	if err := sc.Err(); err != nil {
		s.addLog(st, "host", "warn", stream+" log stream: "+err.Error(), nil)
	}
}
func (s *Supervisor) addLog(st *processState, stream, level, message string, fields map[string]any) {
	st.mu.Lock()
	st.logs.add(LogEntry{Timestamp: time.Now().UTC(), Stream: stream, Level: level, Message: message, Fields: fields})
	st.mu.Unlock()
}

func (s *Supervisor) waitProcess(st *processState) {
	defer s.wg.Done()
	err := st.cmd.Wait()
	now := time.Now().UTC()
	code := -1
	if st.cmd.ProcessState != nil {
		code = st.cmd.ProcessState.ExitCode()
	}
	st.mu.Lock()
	expected := st.expectedStop
	st.exitedAt = now
	st.exitCode = &code
	if expected {
		st.state = "stopped"
	} else {
		st.state = "crashed"
		if err != nil {
			st.lastError = err.Error()
		} else {
			st.lastError = fmt.Sprintf("unexpected exit code %d", code)
		}
	}
	close(st.doneCh)
	st.mu.Unlock()
	s.removeProcessToken(st)
	s.addLog(st, "host", map[bool]string{true: "info", false: "error"}[expected], fmt.Sprintf("process exited code=%d expected=%t", code, expected), nil)
	if !expected {
		s.registerCrashAndRestart(st)
	}
}

func (s *Supervisor) registerCrashAndRestart(st *processState) {
	k := st.key.String()
	now := time.Now().UTC()
	s.mu.Lock()
	history := s.crashes[k]
	cut := now.Add(-s.cfg.CrashWindow)
	n := history[:0]
	for _, t := range history {
		if t.After(cut) {
			n = append(n, t)
		}
	}
	n = append(n, now)
	s.crashes[k] = n
	if len(n) > s.cfg.CrashLimit {
		s.restarts[k] = len(n) - 1
		s.mu.Unlock()
		st.mu.Lock()
		st.state = "crashloop"
		st.lastError = fmt.Sprintf("crash loop: %d crashes within %s", len(n), s.cfg.CrashWindow)
		st.mu.Unlock()
		return
	}
	s.restarts[k]++
	attempt := s.restarts[k]
	s.mu.Unlock()
	delay := s.cfg.RestartBackoff * time.Duration(1<<minInt(attempt-1, 5))
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	go func() {
		select {
		case <-time.After(delay):
		case <-s.ctx.Done():
			return
		}
		fresh, err := s.repo.GetExtensionInstallState(context.Background(), st.key.ExtensionID, st.key.Scope, st.key.ScopeID)
		if err != nil || fresh.CurrentState != model.ExtensionInstallStateEnabled || !fresh.Enabled {
			return
		}
		if err := s.StartInstallation(context.Background(), fresh); err != nil && !errors.Is(err, ErrNoBackendTarget) {
			log.Printf("extension host restart failed %s: %v", st.key.ExtensionID, err)
		}
	}()
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Supervisor) failProcess(st *processState, reason string, expected bool) {
	st.mu.Lock()
	st.lastError = reason
	st.expectedStop = expected
	cmd := st.cmd
	st.mu.Unlock()
	s.addLog(st, "host", "error", reason, nil)
	if cmd != nil && cmd.Process != nil {
		_ = killProcessTree(cmd.Process)
	}
}

func (s *Supervisor) Stop(ctx context.Context, key Key) error {
	key = key.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return nil
	}
	st.mu.Lock()
	if st.state == "stopped" || st.state == "crashed" || st.state == "crashloop" || st.state == "failed" {
		st.mu.Unlock()
		return nil
	}
	st.expectedStop = true
	st.state = "stopping"
	cmd := st.cmd
	done := st.doneCh
	st.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = terminateProcessTree(cmd.Process)
	timer := time.NewTimer(s.cfg.StopTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		_ = killProcessTree(cmd.Process)
		select {
		case <-done:
			return nil
		case <-time.After(2 * time.Second):
			return errors.New("extension process did not exit after kill")
		}
	case <-ctx.Done():
		_ = killProcessTree(cmd.Process)
		return ctx.Err()
	}
}

func (s *Supervisor) Restart(ctx context.Context, key Key) error {
	key = key.normalized()
	s.mu.Lock()
	delete(s.crashes, key.String())
	s.restarts[key.String()] = 0
	s.mu.Unlock()
	_ = s.Stop(ctx, key)
	install, err := s.repo.GetExtensionInstallState(ctx, key.ExtensionID, key.Scope, key.ScopeID)
	if err != nil {
		return err
	}
	return s.StartInstallation(ctx, install)
}

func (s *Supervisor) Reconcile(ctx context.Context) []error {
	installs, err := s.repo.ListExtensionInstallStates(ctx, "", "")
	if err != nil {
		return []error{err}
	}
	var errs []error
	for _, item := range installs {
		if item.CurrentState != model.ExtensionInstallStateEnabled || !item.Enabled {
			continue
		}
		if err := s.StartInstallation(ctx, item); err != nil && !errors.Is(err, ErrNoBackendTarget) {
			errs = append(errs, fmt.Errorf("%s/%s/%s: %w", item.Scope, item.ScopeID, item.ExtensionID, err))
		}
	}
	return errs
}

func (s *Supervisor) Get(key Key) (Status, error) {
	key = key.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return Status{}, repository.ErrNotFound
	}
	return s.statusOf(st), nil
}
func (s *Supervisor) List() []Status {
	s.mu.RLock()
	items := make([]*processState, 0, len(s.processes))
	for _, st := range s.processes {
		items = append(items, st)
	}
	s.mu.RUnlock()
	out := make([]Status, 0, len(items))
	for _, st := range items {
		out = append(out, s.statusOf(st))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope == out[j].Scope && out[i].ScopeID == out[j].ScopeID {
			return out[i].ExtensionID < out[j].ExtensionID
		}
		if out[i].Scope == out[j].Scope {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}
func (s *Supervisor) Logs(key Key, limit int) ([]LogEntry, error) {
	key = key.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return nil, repository.ErrNotFound
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.logs.list(limit), nil
}
func (s *Supervisor) statusOf(st *processState) Status {
	st.mu.Lock()
	defer st.mu.Unlock()
	status := Status{ExtensionID: st.key.ExtensionID, Scope: st.key.Scope, ScopeID: st.key.ScopeID, Version: st.install.CurrentVersion, Generation: st.install.Generation, InstanceID: st.instanceID, State: st.state, Restarts: st.restarts, LastError: st.lastError, MemoryBytes: st.memoryBytes, ProcessCount: st.processCount, ResourceIsolation: resourceIsolationMode(), Entrypoint: st.entrypoint}
	if st.cmd != nil && st.cmd.Process != nil {
		status.PID = st.cmd.Process.Pid
	}
	if !st.startedAt.IsZero() {
		x := st.startedAt
		status.StartedAt = &x
	}
	if !st.helloAt.IsZero() {
		x := st.helloAt
		status.HelloAt = &x
	}
	if !st.heartbeatAt.IsZero() {
		x := st.heartbeatAt
		status.LastHeartbeatAt = &x
	}
	if !st.exitedAt.IsZero() {
		x := st.exitedAt
		status.ExitedAt = &x
	}
	status.ExitCode = st.exitCode
	status.Healthy = st.state == "running" && !st.heartbeatAt.IsZero() && time.Since(st.heartbeatAt) <= s.cfg.HeartbeatTimeout
	for p := range st.permissions {
		status.Permissions = append(status.Permissions, p)
	}
	sort.Strings(status.Permissions)
	return status
}

func (s *Supervisor) monitorLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.monitorOnce(now)
		}
	}
}
func (s *Supervisor) monitorOnce(now time.Time) {
	s.mu.RLock()
	items := make([]*processState, 0, len(s.processes))
	for _, st := range s.processes {
		items = append(items, st)
	}
	s.mu.RUnlock()
	for _, st := range items {
		st.mu.Lock()
		state := st.state
		pid := 0
		if st.cmd != nil && st.cmd.Process != nil {
			pid = st.cmd.Process.Pid
		}
		hb := st.heartbeatAt
		hello := st.helloAt
		st.mu.Unlock()
		if state != "running" && state != "starting" {
			continue
		}
		if !hello.IsZero() && now.Sub(hb) > s.cfg.HeartbeatTimeout {
			s.failProcess(st, "heartbeat timeout", false)
			continue
		}
		if pid > 0 {
			rss, count, err := processTreeUsage(pid)
			if err == nil {
				st.mu.Lock()
				st.memoryBytes = rss
				st.processCount = count
				st.mu.Unlock()
				if s.cfg.MaxMemoryBytes > 0 && rss > s.cfg.MaxMemoryBytes {
					s.failProcess(st, fmt.Sprintf("memory limit exceeded: %d > %d", rss, s.cfg.MaxMemoryBytes), false)
					continue
				}
				if s.cfg.MaxProcesses > 0 && count > s.cfg.MaxProcesses {
					s.failProcess(st, fmt.Sprintf("process limit exceeded: %d > %d", count, s.cfg.MaxProcesses), false)
				}
			}
		}
	}
}

func loopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func (s *Supervisor) authenticate(w http.ResponseWriter, r *http.Request) (*processState, bool) {
	if !loopbackRequest(r) {
		http.Error(w, "loopback required", http.StatusForbidden)
		return nil, false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "bearer token required", http.StatusUnauthorized)
		return nil, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	s.mu.RLock()
	st := s.tokens[token]
	s.mu.RUnlock()
	if st == nil || subtle.ConstantTimeCompare([]byte(token), []byte(st.token)) != 1 {
		http.Error(w, "invalid host token", http.StatusUnauthorized)
		return nil, false
	}
	return st, true
}
func decodeJSONBody(w http.ResponseWriter, r *http.Request, max int64, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}
func jsonResponse(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type helloRequest struct {
	ProtocolVersion string `json:"protocolVersion"`
	ExtensionID     string `json:"extensionId"`
	InstanceID      string `json:"instanceId"`
	PID             int    `json:"pid"`
	CallbackURL     string `json:"callbackUrl,omitempty"`
}

func (s *Supervisor) handleHello(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req helloRequest
	if err := decodeJSONBody(w, r, s.cfg.MaxProtocolBody, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if req.ProtocolVersion != ProtocolVersion || strings.ToLower(strings.TrimSpace(req.ExtensionID)) != st.key.ExtensionID || req.InstanceID != st.instanceID {
		http.Error(w, "host identity/protocol mismatch", 409)
		return
	}
	callbackURL, err := validateCallbackURL0206(req.CallbackURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	st.mu.Lock()
	expectedPID := 0
	if st.cmd != nil && st.cmd.Process != nil {
		expectedPID = st.cmd.Process.Pid
	}
	if req.PID != 0 && expectedPID != 0 && req.PID != expectedPID {
		st.mu.Unlock()
		http.Error(w, "pid mismatch", 409)
		return
	}
	now := time.Now().UTC()
	st.helloAt = now
	st.heartbeatAt = now
	st.callbackURL = callbackURL
	st.state = "running"
	st.helloOnce.Do(func() { close(st.helloCh) })
	st.mu.Unlock()
	jsonResponse(w, 200, map[string]any{"protocolVersion": ProtocolVersion, "instanceId": st.instanceID, "heartbeatTimeoutSeconds": int(s.cfg.HeartbeatTimeout.Seconds()), "capabilities": s.allowedCapabilities(st), "events": eventbus.KnownEventTypes(), "eventProtocolVersion": eventbus.ProtocolVersion})
}
func (s *Supervisor) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	st.mu.Lock()
	if st.state != "running" {
		st.mu.Unlock()
		http.Error(w, "host is not running", 409)
		return
	}
	st.heartbeatAt = time.Now().UTC()
	st.mu.Unlock()
	jsonResponse(w, 200, map[string]any{"ok": true})
}

type logRequest struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

func (s *Supervisor) handleLog(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req logRequest
	if err := decodeJSONBody(w, r, s.cfg.MaxProtocolBody, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	req.Level = strings.ToLower(strings.TrimSpace(req.Level))
	if req.Level == "" {
		req.Level = "info"
	}
	if len(req.Message) > 64<<10 {
		http.Error(w, "log message too large", 413)
		return
	}
	s.addLog(st, "protocol", req.Level, req.Message, req.Fields)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Supervisor) permissionAllowed0207(ctx context.Context, st *processState, permission, projectID string) (bool, error) {
	security := s.securityValue0207()
	if security == nil {
		return false, errors.New("extension capability security unavailable")
	}
	if st.key.Scope == "project" {
		if projectID == "" {
			projectID = st.key.ScopeID
		}
		if projectID != st.key.ScopeID {
			return false, nil
		}
	}
	return security.Allowed(ctx, st.key.ExtensionID, st.install.CurrentVersion, st.key.Scope, st.key.ScopeID, permission, projectID)
}
func (s *Supervisor) allowedCapabilities(st *processState) []string {
	caps := []string{"extension.self", "host.health"}
	checks := []struct{ permission, capability string }{
		{"project:read", "project.get"}, {"release:read", "release.list"}, {"storage:read", "storage.read"},
		{"telemetry:write", "telemetry.emit"}, {"http:outbound", "http.fetch"}, {"secrets:read", "secret.get"},
	}
	projectID := ""
	if st.key.Scope == "project" {
		projectID = st.key.ScopeID
	}
	for _, item := range checks {
		if ok, err := s.permissionAllowed0207(context.Background(), st, item.permission, projectID); err == nil && ok {
			caps = append(caps, item.capability)
		}
	}
	sort.Strings(caps)
	return caps
}
func (s *Supervisor) requirePermission(st *processState, p string) bool {
	projectID := ""
	if st.key.Scope == "project" {
		projectID = st.key.ScopeID
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.CapabilityTimeout)
	defer cancel()
	ok, err := s.permissionAllowed0207(ctx, st, p, projectID)
	return err == nil && ok
}

type capabilityRequest struct {
	ProjectID  string            `json:"projectId,omitempty"`
	Version    string            `json:"version,omitempty"`
	Path       string            `json:"path,omitempty"`
	Name       string            `json:"name,omitempty"`
	Method     string            `json:"method,omitempty"`
	URL        string            `json:"url,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyBase64 string            `json:"bodyBase64,omitempty"`
	ProfileID  string            `json:"profileId,omitempty"`
	Event      string            `json:"event,omitempty"`
	Status     string            `json:"status,omitempty"`
}

func (s *Supervisor) scopedProject(st *processState, projectID string) (string, error) {
	projectID = strings.TrimSpace(projectID)
	if st.key.Scope == "project" {
		if projectID == "" {
			projectID = st.key.ScopeID
		}
		if projectID != st.key.ScopeID {
			return "", errors.New("project-scoped extension cannot access another project")
		}
	}
	if projectID == "" {
		return "", errors.New("projectId is required")
	}
	return projectID, nil
}

type capabilityResult0205 struct {
	value  any
	status int
	err    error
}

func (s *Supervisor) executeCapability(ctx context.Context, st *processState, capName string, req capabilityRequest) capabilityResult0205 {
	switch capName {
	case "host.health":
		return capabilityResult0205{value: map[string]any{"status": s.statusOf(st)}, status: http.StatusOK}
	case "extension.self":
		return capabilityResult0205{value: map[string]any{"extensionId": st.key.ExtensionID, "version": st.install.CurrentVersion, "scope": st.key.Scope, "scopeId": st.key.ScopeID, "generation": st.install.Generation, "manifest": st.manifest}, status: http.StatusOK}
	case "project.get":
		id, err := s.scopedProject(st, req.ProjectID)
		if err != nil {
			return capabilityResult0205{status: http.StatusForbidden, err: err}
		}
		allowed, authErr := s.permissionAllowed0207(ctx, st, "project:read", id)
		if authErr != nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("capability policy unavailable")}
		}
		if !allowed {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("permission project:read not granted")}
		}
		item, err := s.repo.GetProject(id)
		if err != nil {
			return capabilityResult0205{status: http.StatusNotFound, err: err}
		}
		return capabilityResult0205{value: map[string]any{"project": item}, status: http.StatusOK}
	case "release.list":
		id, err := s.scopedProject(st, req.ProjectID)
		if err != nil {
			return capabilityResult0205{status: http.StatusForbidden, err: err}
		}
		allowed, authErr := s.permissionAllowed0207(ctx, st, "release:read", id)
		if authErr != nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("capability policy unavailable")}
		}
		if !allowed {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("permission release:read not granted")}
		}
		items, err := s.repo.ListVersions(id)
		if err != nil {
			return capabilityResult0205{status: http.StatusInternalServerError, err: err}
		}
		return capabilityResult0205{value: map[string]any{"items": items}, status: http.StatusOK}
	case "storage.read":
		id, err := s.scopedProject(st, req.ProjectID)
		if err != nil {
			return capabilityResult0205{status: http.StatusForbidden, err: err}
		}
		allowed, authErr := s.permissionAllowed0207(ctx, st, "storage:read", id)
		if authErr != nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("capability policy unavailable")}
		}
		if !allowed {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("permission storage:read not granted")}
		}
		if strings.TrimSpace(req.Version) == "" || strings.TrimSpace(req.Path) == "" {
			return capabilityResult0205{status: http.StatusBadRequest, err: errors.New("version and path are required")}
		}
		reader, size, err := s.storage.Open(id, req.Version, req.Path)
		if err != nil {
			return capabilityResult0205{status: http.StatusNotFound, err: err}
		}
		defer reader.Close()
		if size > s.cfg.MaxStorageReadBytes {
			return capabilityResult0205{status: http.StatusRequestEntityTooLarge, err: errors.New("storage object exceeds capability read limit")}
		}
		data, err := io.ReadAll(io.LimitReader(reader, s.cfg.MaxStorageReadBytes+1))
		if err != nil {
			return capabilityResult0205{status: http.StatusInternalServerError, err: err}
		}
		if int64(len(data)) > s.cfg.MaxStorageReadBytes {
			return capabilityResult0205{status: http.StatusRequestEntityTooLarge, err: errors.New("storage object exceeds capability read limit")}
		}
		return capabilityResult0205{value: map[string]any{"size": len(data), "contentBase64": base64.StdEncoding.EncodeToString(data)}, status: http.StatusOK}
	case "secret.get":
		security := s.securityValue0207()
		if security == nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("secrets broker unavailable")}
		}
		secretScope, secretScopeID := st.key.Scope, st.key.ScopeID
		projectID := strings.TrimSpace(req.ProjectID)
		if st.key.Scope == "project" {
			projectID = st.key.ScopeID
		} else if projectID != "" {
			secretScope, secretScopeID = "project", projectID
		}
		allowed, authErr := s.permissionAllowed0207(ctx, st, "secrets:read", projectID)
		if authErr != nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("capability policy unavailable")}
		}
		if !allowed {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("permission secrets:read not granted")}
		}
		if strings.TrimSpace(req.Name) == "" {
			return capabilityResult0205{status: http.StatusBadRequest, err: errors.New("secret name is required")}
		}
		plain, err := security.GetSecret(ctx, st.key.ExtensionID, secretScope, secretScopeID, req.Name)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return capabilityResult0205{status: http.StatusNotFound, err: errors.New("secret not found")}
			}
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: err}
		}
		encoded := base64.StdEncoding.EncodeToString(plain)
		clear(plain)
		return capabilityResult0205{value: map[string]any{"name": req.Name, "valueBase64": encoded}, status: http.StatusOK}
	case "telemetry.emit":
		id, err := s.scopedProject(st, req.ProjectID)
		if err != nil {
			return capabilityResult0205{status: http.StatusForbidden, err: err}
		}
		allowed, authErr := s.permissionAllowed0207(ctx, st, "telemetry:write", id)
		if authErr != nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("capability policy unavailable")}
		}
		if !allowed {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("permission telemetry:write not granted")}
		}
		eventName := strings.TrimSpace(req.Event)
		if eventName == "" || len(eventName) > 128 {
			return capabilityResult0205{status: http.StatusBadRequest, err: errors.New("telemetry event is required and must be <=128 chars")}
		}
		s.repo.AddTelemetryEvent(model.TelemetryEvent{ProjectID: id, ProfileID: strings.TrimSpace(req.ProfileID), LauncherVersion: "extension:" + st.key.ExtensionID + "@" + st.install.CurrentVersion, ProfileVersion: st.install.CurrentVersion, Event: eventName, Status: strings.TrimSpace(req.Status), CreatedAt: time.Now().UTC()})
		return capabilityResult0205{value: map[string]any{"accepted": true}, status: http.StatusAccepted}
	case "http.fetch":
		allowed, authErr := s.permissionAllowed0207(ctx, st, "http:outbound", "")
		if authErr != nil {
			return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("capability policy unavailable")}
		}
		if !allowed {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("permission http:outbound not granted")}
		}
		value, status, err := s.secureHTTPFetch0207(ctx, req.Method, req.URL, req.Headers, req.BodyBase64)
		return capabilityResult0205{value: value, status: status, err: err}
	default:
		return capabilityResult0205{status: http.StatusNotFound, err: errors.New("unknown or unavailable capability")}
	}
}

func (s *Supervisor) auditCapability0207(st *processState, capability string, allowed bool, detail string) {
	action := "extension:capability:allowed"
	if !allowed {
		action = "extension:capability:denied"
	}
	target := st.key.ExtensionID + "@" + st.install.CurrentVersion + ":" + capability + ":" + st.key.Scope
	if st.key.ScopeID != "" {
		target += ":" + st.key.ScopeID
	}
	if detail != "" {
		target += ":" + detail
	}
	s.repo.AddAuditEvent(model.AuditEvent{Actor: "extension:" + st.key.ExtensionID, Action: action, Target: target, UserAgent: "NeverExtensions Host/" + ProtocolVersion, CreatedAt: time.Now().UTC()})
}

func (s *Supervisor) handleCapability(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	capName := strings.ToLower(strings.TrimSpace(r.PathValue("capability")))
	var req capabilityRequest
	if r.ContentLength != 0 {
		if err := decodeJSONBody(w, r, s.cfg.MaxProtocolBody, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	resultCh := make(chan capabilityResult0205, 1)
	go func() { resultCh <- s.executeCapability(r.Context(), st, capName, req) }()
	timer := time.NewTimer(s.cfg.CapabilityTimeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		privileged := capName != "host.health" && capName != "extension.self"
		if result.err != nil {
			if privileged {
				s.auditCapability0207(st, capName, false, strconv.Itoa(result.status))
			}
			http.Error(w, result.err.Error(), result.status)
			return
		}
		if privileged {
			s.auditCapability0207(st, capName, true, strconv.Itoa(result.status))
		}
		jsonResponse(w, result.status, result.value)
	case <-timer.C:
		if capName != "host.health" && capName != "extension.self" {
			s.auditCapability0207(st, capName, false, "timeout")
		}
		http.Error(w, "capability broker timeout", http.StatusGatewayTimeout)
	case <-r.Context().Done():
		return
	}
}

func parseManifestHook0206(raw string) (string, string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	mode := model.ExtensionEventModeAsync
	if strings.HasPrefix(raw, "sync:") {
		mode = model.ExtensionEventModeSync
		raw = strings.TrimPrefix(raw, "sync:")
	}
	if strings.HasPrefix(raw, "async:") {
		mode = model.ExtensionEventModeAsync
		raw = strings.TrimPrefix(raw, "async:")
	}
	return strings.TrimSpace(raw), mode
}
func (s *Supervisor) reconcileManifestSubscriptions0206(ctx context.Context, st *processState) error {
	bus := s.eventBusValue0206()
	if bus == nil || len(st.manifest.Hooks) == 0 {
		return nil
	}
	st.mu.Lock()
	callbackReady := st.callbackURL != ""
	st.mu.Unlock()
	if !callbackReady {
		return errors.New("manifest hooks require callbackUrl in authenticated hello")
	}
	for _, raw := range st.manifest.Hooks {
		eventType, mode := parseManifestHook0206(raw)
		if err := s.validateEventPermission0206(st, eventType, mode); err != nil {
			return fmt.Errorf("manifest hook %q: %w", raw, err)
		}
		if _, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: st.key.ExtensionID, Scope: st.key.Scope, ScopeID: st.key.ScopeID, EventType: eventType, Mode: mode, Enabled: true}); err != nil {
			return fmt.Errorf("manifest hook %q: %w", raw, err)
		}
	}
	return nil
}

func (s *Supervisor) SetEventBus(bus *eventbus.Bus) { s.mu.Lock(); s.eventBus = bus; s.mu.Unlock() }

func validateCallbackURL0206(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("callbackUrl must be a plain http loopback origin")
	}
	host := u.Hostname()
	port := u.Port()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || port == "" {
		return "", errors.New("callbackUrl must use an explicit loopback IP and port")
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func (s *Supervisor) eventBusValue0206() *eventbus.Bus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.eventBus
}
func (s *Supervisor) validateEventPermission0206(st *processState, eventType, mode string) error {
	spec, ok := eventbus.Spec(eventType)
	if !ok {
		return fmt.Errorf("unsupported event type %q", eventType)
	}
	if !s.requirePermission(st, "events:subscribe") {
		return errors.New("permission events:subscribe required")
	}
	if spec.CategoryPermission != "" && !s.requirePermission(st, spec.CategoryPermission) {
		return fmt.Errorf("permission %s required", spec.CategoryPermission)
	}
	if mode == model.ExtensionEventModeSync {
		if !spec.SyncAllowed {
			return fmt.Errorf("event %s is async-only", eventType)
		}
		if !s.requirePermission(st, "events:sync") {
			return errors.New("permission events:sync required")
		}
	}
	return nil
}

type eventSubscriptionRequest0206 struct {
	EventType string `json:"eventType"`
	Mode      string `json:"mode"`
}

func (s *Supervisor) handleEventSubscriptions(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bus := s.eventBusValue0206()
	if bus == nil {
		http.Error(w, "event bus unavailable", 503)
		return
	}
	items, err := bus.Subscriptions(r.Context(), st.key.ExtensionID, st.key.Scope, st.key.ScopeID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
func (s *Supervisor) handleEventSubscribe(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bus := s.eventBusValue0206()
	if bus == nil {
		http.Error(w, "event bus unavailable", 503)
		return
	}
	var req eventSubscriptionRequest0206
	if err := decodeJSONBody(w, r, s.cfg.MaxProtocolBody, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	req.EventType = strings.ToLower(strings.TrimSpace(req.EventType))
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		req.Mode = model.ExtensionEventModeAsync
	}
	if err := s.validateEventPermission0206(st, req.EventType, req.Mode); err != nil {
		s.auditCapability0207(st, "events.subscribe:"+req.EventType+":"+req.Mode, false, "403")
		http.Error(w, err.Error(), 403)
		return
	}
	st.mu.Lock()
	callbackReady := st.callbackURL != ""
	st.mu.Unlock()
	if !callbackReady {
		http.Error(w, "callbackUrl must be registered before subscribing", http.StatusConflict)
		return
	}
	item, err := bus.Subscribe(r.Context(), model.ExtensionEventSubscription{ExtensionID: st.key.ExtensionID, Scope: st.key.Scope, ScopeID: st.key.ScopeID, EventType: req.EventType, Mode: req.Mode, Enabled: true})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.auditCapability0207(st, "events.subscribe:"+req.EventType+":"+req.Mode, true, "201")
	jsonResponse(w, http.StatusCreated, item)
}
func (s *Supervisor) handleEventUnsubscribe(w http.ResponseWriter, r *http.Request) {
	st, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bus := s.eventBusValue0206()
	if bus == nil {
		http.Error(w, "event bus unavailable", 503)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("subscriptionId")), 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid subscription id", 400)
		return
	}
	if err := bus.Unsubscribe(r.Context(), id, st.key.ExtensionID, st.key.Scope, st.key.ScopeID); err != nil {
		s.auditCapability0207(st, "events.unsubscribe", false, strconv.FormatInt(id, 10))
		if errors.Is(err, repository.ErrNotFound) {
			http.Error(w, "subscription not found", 404)
		} else {
			http.Error(w, err.Error(), 500)
		}
		return
	}
	s.auditCapability0207(st, "events.unsubscribe", true, strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Supervisor) processForSubscription0206(sub model.ExtensionEventSubscription) (*processState, error) {
	key := Key{ExtensionID: sub.ExtensionID, Scope: sub.Scope, ScopeID: sub.ScopeID}.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return nil, ErrHostNotRunning
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.state != "running" || st.callbackURL == "" {
		return nil, ErrHostNotRunning
	}
	return st, nil
}
func (s *Supervisor) callbackRequest0206(ctx context.Context, sub model.ExtensionEventSubscription, event model.ExtensionEvent, path string) (*http.Response, error) {
	st, err := s.processForSubscription0206(sub)
	if err != nil {
		return nil, err
	}
	if err := s.validateEventPermission0206(st, event.Type, sub.Mode); err != nil {
		s.auditCapability0207(st, "events.deliver:"+event.Type+":"+sub.Mode, false, "permission-revoked")
		return nil, fmt.Errorf("event capability revoked: %w", err)
	}
	st.mu.Lock()
	base := st.callbackURL
	token := st.callbackToken
	st.mu.Unlock()
	body, err := json.Marshal(map[string]any{"protocolVersion": eventbus.ProtocolVersion, "subscription": sub, "event": event})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NeverLauncher-Event-ID", event.ID)
	req.Header.Set("Idempotency-Key", event.IdempotencyKey)
	return s.callbackClient.Do(req)
}
func (s *Supervisor) DeliverExtensionEvent(ctx context.Context, sub model.ExtensionEventSubscription, event model.ExtensionEvent) error {
	resp, err := s.callbackRequest0206(ctx, sub, event, "/v1/events")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("extension event callback returned HTTP %d", resp.StatusCode)
	}
	return nil
}
func (s *Supervisor) DeliverExtensionHook(ctx context.Context, sub model.ExtensionEventSubscription, event model.ExtensionEvent) (model.ExtensionHookResult, error) {
	resp, err := s.callbackRequest0206(ctx, sub, event, "/v1/hooks")
	if err != nil {
		return model.ExtensionHookResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return model.ExtensionHookResult{}, fmt.Errorf("extension hook callback returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return model.ExtensionHookResult{}, fmt.Errorf("read hook response: %w", err)
	}
	if len(body) > 64<<10 {
		return model.ExtensionHookResult{}, errors.New("extension hook response exceeds 64 KiB")
	}
	var result model.ExtensionHookResult
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return model.ExtensionHookResult{}, fmt.Errorf("decode hook response: %w", err)
	}
	if dec.More() {
		return model.ExtensionHookResult{}, errors.New("extension hook response contains trailing JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return model.ExtensionHookResult{}, errors.New("extension hook response contains trailing data")
	}
	return result, nil
}

func (s *Supervisor) ProtocolURL() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.baseURL }
func (s *Supervisor) ResourceIsolation() string { return resourceIsolationMode() }
func (s *Supervisor) Limits() map[string]any {
	return map[string]any{"startupTimeoutSeconds": s.cfg.StartupTimeout.Seconds(), "heartbeatTimeoutSeconds": s.cfg.HeartbeatTimeout.Seconds(), "stopTimeoutSeconds": s.cfg.StopTimeout.Seconds(), "maxMemoryBytes": s.cfg.MaxMemoryBytes, "maxProcesses": s.cfg.MaxProcesses, "maxLogBytes": s.cfg.MaxLogBytes, "maxLogEntries": s.cfg.MaxLogEntries, "maxStorageReadBytes": s.cfg.MaxStorageReadBytes, "maxHttpRequestBytes": s.cfg.MaxHTTPRequestBytes, "maxHttpResponseBytes": s.cfg.MaxHTTPResponseBytes, "httpTimeoutSeconds": s.cfg.HTTPTimeout.Seconds(), "crashLimit": s.cfg.CrashLimit, "crashWindowSeconds": s.cfg.CrashWindow.Seconds()}
}
func ParseLimit(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}
