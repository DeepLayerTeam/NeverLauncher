package main

// RemoteControl v1 is a deliberately narrow host-level interface. It never
// accepts a command line, Java argument array or arbitrary file path from a
// remote caller. Its operations dispatch through the 0.28.2 Host Supervisor.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitflic.ru/skif4er/launcher/cli/internal/remotetls"
)

const remoteAudience0284 = "launcher/host-remote/v1"
const remoteMaxTTL0284 = 15 * time.Minute

var remoteScopes0284 = map[string]bool{
	"host.status": true, "host.start": true, "host.stop": true, "host.restart": true,
}
var remoteIdempotency0284 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type remoteIdentity0284 struct {
	Version int    `json:"version"`
	NodeID  string `json:"nodeId"`
	Key     []byte `json:"key"`
}
type remoteClaims0284 struct {
	Audience string   `json:"aud"`
	NodeID   string   `json:"nodeId"`
	ID       string   `json:"jti"`
	Subject  string   `json:"sub"`
	Issued   int64    `json:"iat"`
	Expires  int64    `json:"exp"`
	Scopes   []string `json:"scopes"`
	Sources  []string `json:"sources"`
}
type remoteRevoke0284 struct {
	Entries map[string]int64 `json:"entries"`
}
type remoteCommand0284 struct {
	Action string `json:"action"`
}
type remoteReceipt0284 struct {
	SchemaVersion string          `json:"schemaVersion"`
	KeyHash       string          `json:"keyHash"`
	Digest        string          `json:"digest"`
	Subject       string          `json:"subject"`
	Action        string          `json:"action"`
	State         string          `json:"state"` // indeterminate before external operation, succeeded after confirmation
	CreatedAt     string          `json:"createdAt"`
	FinishedAt    string          `json:"finishedAt,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         string          `json:"error,omitempty"`
}
type remoteAudit0284 struct {
	At      string `json:"at"`
	Event   string `json:"event"`
	IP      string `json:"ip"`
	TokenID string `json:"tokenId,omitempty"`
	Subject string `json:"subject,omitempty"`
	Action  string `json:"action,omitempty"`
	KeyHash string `json:"keyHash,omitempty"`
	Outcome string `json:"outcome"`
}
type remoteLease0284 struct {
	PID      int    `json:"pid"`
	Identity string `json:"identity"`
	NodeID   string `json:"nodeId"`
}

type remoteAgent0284 struct {
	root     string
	dir      string
	identity remoteIdentity0284
	sources  []*net.IPNet
	mu       sync.Mutex
	now      func() time.Time
	execute  func(string) (json.RawMessage, error)
}

func remoteDir0284(root string) string { return filepath.Join(hostPaths01910(root)["dir"], "remote") }
func remoteRandom0284(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// A single active remote agent may own one server root. This prevents two
// listeners on different TCP ports from independently executing the same
// durable idempotency key. A stale lock is recoverable only after the precise
// OS process identity has disappeared.
func remoteAcquireLease0284(dir, nodeID string) (func(), error) {
	// A permanent inode is locked by the kernel for the listener lifetime.
	// Without this, two challengers can both rename the same stale JSON lock
	// and start listeners on different ports (split brain).
	unlockFence, err := remoteKernelFence04112(dir)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			unlockFence()
		}
	}()
	path := filepath.Join(dir, "agent.lock")
	own := remoteLease0284{PID: os.Getpid(), Identity: hostOwnIdentity0282(), NodeID: nodeID}
	if own.Identity == "" {
		return nil, errors.New("OS process identity required for RemoteControl lease")
	}
	data, err := json.Marshal(own)
	if err != nil {
		return nil, err
	}
	for attempts := 0; attempts < 3; attempts++ {
		f, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if openErr == nil {
			_, writeErr := f.Write(data)
			if writeErr == nil {
				writeErr = f.Sync()
			}
			closeErr := f.Close()
			if writeErr != nil {
				_ = os.Remove(path)
				return nil, writeErr
			}
			if closeErr != nil {
				_ = os.Remove(path)
				return nil, closeErr
			}
			if err = remoteSyncDir0284(dir); err != nil {
				return nil, err
			}
			owned = true
			return func() {
				defer unlockFence()
				var actual remoteLease0284
				if readJSONFile01910(path, &actual) == nil && actual == own {
					_ = os.Remove(path)
				}
			}, nil
		}
		if !errors.Is(openErr, os.ErrExist) {
			return nil, openErr
		}
		if err = remoteCheckFile0284(path); err != nil {
			return nil, err
		}
		var existing remoteLease0284
		if err = readJSONFile01910(path, &existing); err != nil {
			return nil, err
		}
		if existing.Identity != "" && hostIdentityMatches0282(existing.PID, existing.Identity) {
			return nil, fmt.Errorf("remote agent already holds server root pid=%d", existing.PID)
		}
		if existing.Identity == "" && updaterProcessAlive0156(existing.PID) {
			return nil, errors.New("unverified remote agent lock belongs to a live PID")
		}
		// A stale lock can only be discarded by an operator holding filesystem
		// write permission for the private directory. Refuse blind SIGKILL/reclaim.
		stale := path + ".stale-" + fmt.Sprint(os.Getpid())
		if err = os.Rename(path, stale); err != nil {
			return nil, err
		}
		_ = os.Remove(stale)
	}
	return nil, errors.New("remote agent lock contention")
}

func remoteSecureDir0284(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("remote state directory must be a private real directory: %s", dir)
	}
	return nil
}
func remoteCheckFile0284(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("remote secret/state must be a private regular file: %s", path)
	}
	return nil
}
func remoteSyncDir0284(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
func remoteSave0284(path string, v any) error {
	if _, err := os.Lstat(path); err == nil {
		if err = remoteCheckFile0284(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicWriteJSON01910(path, v, 0600); err != nil {
		return err
	}
	return remoteSyncDir0284(filepath.Dir(path))
}
func remoteInit0284(root string) (remoteIdentity0284, error) {
	dir := remoteDir0284(root)
	if err := remoteSecureDir0284(dir); err != nil {
		return remoteIdentity0284{}, err
	}
	path := filepath.Join(dir, "identity.json")
	if _, err := os.Lstat(path); err == nil {
		return remoteIdentity0284{}, errors.New("remote identity already exists; use rotate-key to invalidate tokens")
	} else if !errors.Is(err, os.ErrNotExist) {
		return remoteIdentity0284{}, err
	}
	id, err := remoteRandom0284(16)
	if err != nil {
		return remoteIdentity0284{}, err
	}
	key, err := remoteRandom0284(32)
	if err != nil {
		return remoteIdentity0284{}, err
	}
	identity := remoteIdentity0284{Version: 1, NodeID: hex.EncodeToString(id), Key: key}
	// O_EXCL ensures concurrent operators cannot replace each other's secrets.
	data, err := json.Marshal(identity)
	if err != nil {
		return remoteIdentity0284{}, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return remoteIdentity0284{}, err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return remoteIdentity0284{}, writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return remoteIdentity0284{}, closeErr
	}
	if err = remoteSyncDir0284(dir); err != nil {
		return remoteIdentity0284{}, err
	}
	return identity, nil
}
func remoteLoad0284(root string) (remoteIdentity0284, error) {
	dir := remoteDir0284(root)
	if err := remoteSecureDir0284(dir); err != nil {
		return remoteIdentity0284{}, err
	}
	path := filepath.Join(dir, "identity.json")
	if err := remoteCheckFile0284(path); err != nil {
		return remoteIdentity0284{}, err
	}
	var i remoteIdentity0284
	if err := readJSONFile01910(path, &i); err != nil {
		return i, err
	}
	if i.Version != 1 || len(i.Key) != 32 || len(i.NodeID) != 32 {
		return i, errors.New("invalid remote node identity")
	}
	return i, nil
}
func remoteParseSources0284(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, errors.New("source CIDR allowlist required")
	}
	networks := make([]*net.IPNet, 0, len(values))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			s := strings.TrimSpace(part)
			if s == "" {
				return nil, errors.New("empty source CIDR")
			}
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("invalid source CIDR %q", s)
			}
			networks = append(networks, n)
		}
	}
	return networks, nil
}
func remoteAllowIP0284(networks []*net.IPNet, remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
func remoteTokenSign0284(id remoteIdentity0284, claims remoteClaims0284) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, id.Key)
	_, _ = mac.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func remoteTokenDecode0284(id remoteIdentity0284, token string, now time.Time) (remoteClaims0284, error) {
	var c remoteClaims0284
	if len(token) > 4096 {
		return c, errors.New("invalid token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, id.Key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return c, errors.New("invalid token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, errors.New("invalid token")
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, errors.New("invalid token")
	}
	ts := now.Unix()
	if c.Audience != remoteAudience0284 || c.NodeID != id.NodeID || c.Subject == "" || c.ID == "" || c.Issued > ts+10 || c.Expires <= ts || c.Expires-c.Issued > int64(remoteMaxTTL0284.Seconds()) || c.Issued <= 0 || len(c.Scopes) == 0 || len(c.Sources) == 0 {
		return c, errors.New("expired, mismatched or invalid token")
	}
	for _, scope := range c.Scopes {
		if !remoteScopes0284[scope] {
			return c, errors.New("unknown token scope")
		}
	}
	if _, err = remoteParseSources0284(c.Sources); err != nil {
		return c, err
	}
	return c, nil
}
func remoteIssue0284(id remoteIdentity0284, subject string, scopes, sources []string, ttl time.Duration, now time.Time) (string, error) {
	if subject == "" || len(subject) > 128 || strings.ContainsAny(subject, "\n\r\t") {
		return "", errors.New("invalid token subject")
	}
	if ttl < time.Second || ttl > remoteMaxTTL0284 || len(scopes) == 0 {
		return "", errors.New("token must have scopes and TTL between 1 second and 15 minutes")
	}
	for _, s := range scopes {
		if !remoteScopes0284[s] {
			return "", fmt.Errorf("unknown host-level scope %q", s)
		}
	}
	if _, err := remoteParseSources0284(sources); err != nil {
		return "", err
	}
	b, err := remoteRandom0284(16)
	if err != nil {
		return "", err
	}
	return remoteTokenSign0284(id, remoteClaims0284{Audience: remoteAudience0284, NodeID: id.NodeID, ID: hex.EncodeToString(b), Subject: subject, Issued: now.Unix(), Expires: now.Unix() + int64(ttl.Seconds()), Scopes: scopes, Sources: sources})
}
func remoteRevoked0284(dir, jti string, now time.Time) (bool, error) {
	path := filepath.Join(dir, "revoked.json")
	var state remoteRevoke0284
	if err := readJSONFile01910(path, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return state.Entries[jti] > now.Unix(), nil
}
func remoteRevokeToken0284(dir string, c remoteClaims0284, now time.Time) error {
	path := filepath.Join(dir, "revoked.json")
	state := remoteRevoke0284{Entries: map[string]int64{}}
	if err := readJSONFile01910(path, &state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state.Entries == nil {
		state.Entries = map[string]int64{}
	}
	for k, v := range state.Entries {
		if v <= now.Unix() {
			delete(state.Entries, k)
		}
	}
	state.Entries[c.ID] = c.Expires
	return remoteSave0284(path, state)
}
func remoteAuditLog0284(dir string, event remoteAudit0284) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.jsonl")
	if _, err = os.Lstat(path); err == nil {
		if err = remoteCheckFile0284(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
func remoteReceiptFile0284(dir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, "commands", hex.EncodeToString(sum[:])+".json")
}
func remoteReadReceipt0284(path string) (remoteReceipt0284, error) {
	if err := remoteCheckFile0284(path); err != nil {
		return remoteReceipt0284{}, err
	}
	var r remoteReceipt0284
	err := readJSONFile01910(path, &r)
	return r, err
}
func remotePersistReceipt0284(path string, r remoteReceipt0284) error { return remoteSave0284(path, r) }

// A different idempotency key must never bypass an interrupted/uncertain
// host action. The directory is private and guarded by the singleton agent;
// malformed or unreadable receipts fail closed instead of being ignored.
func remoteUnresolvedCommand04112(dir string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "commands"))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || len(entry.Name()) != 69 {
			return false, fmt.Errorf("unexpected command journal entry: %s", entry.Name())
		}
		path := filepath.Join(dir, "commands", entry.Name())
		receipt, err := remoteReadReceipt0284(path)
		if err != nil {
			return false, fmt.Errorf("read command journal: %w", err)
		}
		if receipt.KeyHash != strings.TrimSuffix(entry.Name(), ".json") || receipt.Digest == "" || receipt.Subject == "" ||
			(receipt.Action != "start" && receipt.Action != "stop" && receipt.Action != "restart") ||
			(receipt.State != "succeeded" && receipt.State != "indeterminate") {
			return false, errors.New("invalid command journal entry; manual recovery required")
		}
		if receipt.State == "indeterminate" {
			return true, nil
		}
	}
	return false, nil
}
func remoteHostStatus0284(root string) json.RawMessage {
	paths := hostPaths01910(root)
	result := map[string]any{"schemaVersion": "1.0", "configured": false, "observedStatus": "not-started"}
	if _, err := readServerBridgeHostConfig01910(paths["config"]); err == nil {
		result["configured"] = true
	}
	if state, err := readServerBridgeHostRuntime01910(paths["runtime"]); err == nil {
		supervisor := hostIdentityMatches0282(state.SupervisorPID, state.SupervisorIdentity)
		process := hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity)
		status := state.Status
		if state.ProcessPID > 0 && !process {
			status = "stale-runtime"
		} else if process && !supervisor {
			status = "orphaned-process"
		}
		result["observedStatus"] = status
		result["supervisorAlive"] = supervisor
		result["processAlive"] = process
		if process {
			// Only live OS observations, bound to the managed process identity.
			if metrics := hostProcessTelemetry0419(state.ProcessPID, state.ProcessIdentity); metrics != nil {
				result["telemetry"] = metrics
			}
		}
		result["sessionId"] = state.SessionID
		result["restartCount"] = state.RestartCount
		result["crashCount"] = state.CrashCount
	}
	b, _ := json.Marshal(result)
	return b
}
func remoteObservedEffect0413(action string, before, after map[string]any) bool {
	status, _ := after["observedStatus"].(string)
	process, _ := after["processAlive"].(bool)
	supervisor, _ := after["supervisorAlive"].(bool)
	session, _ := after["sessionId"].(string)
	oldSession, _ := before["sessionId"].(string)
	switch action {
	case "start":
		return process && supervisor && status == "running"
	case "stop":
		return !process && !supervisor && (status == "stopped" || status == "not-started")
	case "restart":
		return process && supervisor && status == "running" && session != "" && session != oldSession
	default:
		return false
	}
}
func remoteObservedState0413(root string) map[string]any {
	var s map[string]any
	if err := json.Unmarshal(remoteHostStatus0284(root), &s); err != nil {
		return map[string]any{}
	}
	return s
}
func remoteHostExecute0284(root, dir, action string) (json.RawMessage, error) {
	before := remoteObservedState0413(root)
	output := filepath.Join(dir, ".result-"+action+"-"+fmt.Sprint(time.Now().UnixNano())+".json")
	defer os.Remove(output)
	args := []string{"--server-root", root, "--output", output}
	var err error
	switch action {
	case "start":
		err = startServerBridgeHost01910(args)
	case "stop":
		err = stopServerBridgeHost01910(args)
	case "restart":
		err = restartServerBridgeHost01910(args)
	default:
		return nil, errors.New("unsupported remote operation")
	}
	if err != nil {
		return nil, err
	}
	// Do not confuse the CLI returning with actual JVM/process completion.
	// The OS process identity is checked by remoteHostStatus0284 on each poll.
	deadline := time.Now().Add(45 * time.Second)
	for {
		observed := remoteObservedState0413(root)
		if remoteObservedEffect0413(action, before, observed) {
			return remoteHostStatus0284(root), nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("host %s returned but OS process postcondition remains unverified", action)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
func remoteNewAgent0284(root string, identity remoteIdentity0284, sourceCIDRs []string) (*remoteAgent0284, error) {
	sources, err := remoteParseSources0284(sourceCIDRs)
	if err != nil {
		return nil, err
	}
	dir := remoteDir0284(root)
	if err = remoteSecureDir0284(dir); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Join(dir, "commands"), 0700); err != nil {
		return nil, err
	}
	if err = remoteSecureDir0284(filepath.Join(dir, "commands")); err != nil {
		return nil, err
	}
	a := &remoteAgent0284{root: root, dir: dir, identity: identity, sources: sources, now: time.Now}
	a.execute = func(action string) (json.RawMessage, error) { return remoteHostExecute0284(root, dir, action) }
	return a, nil
}
func remoteScopeContains0284(claims remoteClaims0284, scope string) bool {
	for _, v := range claims.Scopes {
		if v == scope {
			return true
		}
	}
	return false
}
func (a *remoteAgent0284) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	write := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	event := remoteAudit0284{At: a.now().UTC().Format(time.RFC3339Nano), Event: "remote-request", IP: ip, Outcome: "denied"}
	if r.TLS == nil || !remoteAllowIP0284(a.sources, r.RemoteAddr) {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusForbidden, map[string]string{"error": "TLS and approved source required"})
		return
	}
	tokenField := r.Header.Get("Authorization")
	if !strings.HasPrefix(tokenField, "Bearer ") {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
		return
	}
	token := strings.TrimPrefix(tokenField, "Bearer ")
	// Reload the key from protected storage on every request. Rotating a
	// key invalidates existing credentials without restarting the listener.
	identity, loadErr := remoteLoad0284(a.root)
	if loadErr != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "node identity unavailable"})
		return
	}
	claims, err := remoteTokenDecode0284(identity, token, a.now())
	if err != nil {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
		return
	}
	event.TokenID = claims.ID
	event.Subject = claims.Subject
	cidrs, err := remoteParseSources0284(claims.Sources)
	if err != nil || !remoteAllowIP0284(cidrs, r.RemoteAddr) {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusForbidden, map[string]string{"error": "token source restriction"})
		return
	}
	a.mu.Lock()
	revoked, err := remoteRevoked0284(a.dir, claims.ID, a.now())
	a.mu.Unlock()
	if err != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "revocation store unavailable"})
		return
	}
	if revoked {
		write(http.StatusUnauthorized, map[string]string{"error": "revoked token"})
		return
	}
	scope := ""
	action := ""
	if r.Method == http.MethodGet && r.URL.Path == "/v1/host/status" {
		scope = "host.status"
	}
	// Receipt inspection is strictly read-only: never dispatch an action to
	// recover a dropped ACK. Scope and original token subject are rechecked.
	receiptKey := ""
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/host/receipts/") {
		receiptKey = strings.TrimPrefix(r.URL.Path, "/v1/host/receipts/")
		if !remoteIdempotency0284.MatchString(receiptKey) {
			write(http.StatusBadRequest, map[string]string{"error": "invalid receipt key"})
			return
		}
		scope = "host.status"
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/host/commands" {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var command remoteCommand0284
		if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
			write(http.StatusBadRequest, map[string]string{"error": "invalid command body"})
			return
		}
		action = command.Action
		if action == "start" || action == "stop" || action == "restart" {
			scope = "host." + action
		}
	}
	if scope == "" {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusNotFound, map[string]string{"error": "unsupported operation"})
		return
	}
	event.Action = scope
	if !remoteScopeContains0284(claims, scope) {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusForbidden, map[string]string{"error": "insufficient scope"})
		return
	}
	if receiptKey != "" {
		a.mu.Lock()
		defer a.mu.Unlock()
		path := remoteReceiptFile0284(a.dir, receiptKey)
		receipt, readErr := remoteReadReceipt0284(path)
		if errors.Is(readErr, os.ErrNotExist) {
			write(http.StatusNotFound, map[string]string{"error": "receipt not found"})
			return
		}
		if readErr != nil || receipt.KeyHash != strings.TrimSuffix(filepath.Base(path), ".json") || receipt.Subject != claims.Subject ||
			!remoteScopeContains0284(claims, "host."+receipt.Action) {
			write(http.StatusForbidden, map[string]string{"error": "receipt unavailable or not authorized"})
			return
		}
		event.Outcome = "receipt-read"
		if remoteAuditLog0284(a.dir, event) != nil {
			write(http.StatusServiceUnavailable, map[string]string{"error": "audit unavailable"})
			return
		}
		write(http.StatusOK, receipt)
		return
	}
	if action == "" {
		event.Outcome = "read"
		if err = remoteAuditLog0284(a.dir, event); err != nil {
			write(http.StatusServiceUnavailable, map[string]string{"error": "audit unavailable"})
			return
		}
		write(http.StatusOK, map[string]any{"nodeId": identity.NodeID, "status": json.RawMessage(remoteHostStatus0284(a.root))})
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !remoteIdempotency0284.MatchString(key) {
		_ = remoteAuditLog0284(a.dir, event)
		write(http.StatusBadRequest, map[string]string{"error": "Idempotency-Key must be 16-128 safe characters"})
		return
	}
	digestBytes := sha256.Sum256([]byte(action + "\x00" + claims.Subject + "\x00" + identity.NodeID))
	digest := hex.EncodeToString(digestBytes[:])
	path := remoteReceiptFile0284(a.dir, key)
	a.mu.Lock()
	defer a.mu.Unlock()
	// Token expiry/revocation may change while another command is running.
	if a.now().Unix() >= claims.Expires {
		write(http.StatusUnauthorized, map[string]string{"error": "token expired"})
		return
	}
	revoked, err = remoteRevoked0284(a.dir, claims.ID, a.now())
	if err != nil || revoked {
		write(http.StatusUnauthorized, map[string]string{"error": "token revoked/unavailable"})
		return
	}
	if old, readErr := remoteReadReceipt0284(path); readErr == nil {
		if old.KeyHash != strings.TrimSuffix(filepath.Base(path), ".json") || old.Digest != digest || old.Subject != claims.Subject || old.Action != action {
			write(http.StatusConflict, map[string]string{"error": "idempotency key already bound to a different operation"})
			return
		}
		event.Outcome = "replayed-" + old.State
		_ = remoteAuditLog0284(a.dir, event)
		code := http.StatusOK
		if old.State != "succeeded" {
			code = http.StatusConflict
		}
		write(code, old)
		return
	} else if !errors.Is(readErr, os.ErrNotExist) {
		write(http.StatusServiceUnavailable, map[string]string{"error": "command journal unavailable"})
		return
	}
	// Check all previous receipts, not only the current idempotency key.
	// If a crash happened after an irreversible effect, newer keys cannot
	// silently issue a second dangerous action.
	unknown, guardErr := remoteUnresolvedCommand04112(a.dir)
	if guardErr != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "command journal integrity unavailable"})
		return
	}
	if unknown {
		write(http.StatusConflict, map[string]string{"error": "previous host command indeterminate; operator reconciliation required"})
		return
	}
	event.Outcome = "accepted"
	if err = remoteAuditLog0284(a.dir, event); err != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "audit unavailable"})
		return
	}
	receipt := remoteReceipt0284{SchemaVersion: "1.0", KeyHash: strings.TrimSuffix(filepath.Base(path), ".json"), Digest: digest, Subject: claims.Subject, Action: action, State: "indeterminate", CreatedAt: a.now().UTC().Format(time.RFC3339Nano)}
	if err = remotePersistReceipt0284(path, receipt); err != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "cannot persist command intent"})
		return
	}
	result, runErr := a.execute(action)
	receipt.FinishedAt = a.now().UTC().Format(time.RFC3339Nano)
	if runErr == nil {
		receipt.State = "succeeded"
		receipt.Result = result
	} else {
		receipt.Error = runErr.Error() /* cannot prove external action was not applied */
	}
	if err = remotePersistReceipt0284(path, receipt); err != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "result persistence failed; command outcome indeterminate"})
		return
	}
	event.Outcome = receipt.State
	if err = remoteAuditLog0284(a.dir, event); err != nil {
		write(http.StatusServiceUnavailable, map[string]string{"error": "audit write failed; inspect persisted receipt"})
		return
	}
	code := http.StatusOK
	if receipt.State != "succeeded" {
		code = http.StatusConflict
	}
	write(code, receipt)
}
func remoteHandle0284(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nl server-bridge host remote init|tls-init|issue|revoke|rotate-key|inspect|serve|call")
	}
	if args[0] == "call" {
		return remoteCall0284(args) // A remote client has no local server root.
	}
	if args[0] == "tls-init" {
		// The output directory must be new; ca.key is retained only for offline
		// issuance and must never be left in a publicly served game directory.
		days, err := strconv.Atoi(flagValue(args, "--days", "90"))
		if err != nil {
			return fmt.Errorf("--days: %w", err)
		}
		bundle, err := remotetls.Generate(flagValue(args, "--output-dir", ""), multiFlagValues01910(args, "--host"), days)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), bundle)
	}
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	switch args[0] {
	case "inspect":
		// Local operator-only inspection of a durable command journal. No
		// automatic retry or success assertion is made from PID/process state.
		if _, err := remoteLoad0284(root); err != nil {
			return err
		}
		key := flagValue(args, "--idempotency-key", "")
		if !remoteIdempotency0284.MatchString(key) {
			return errors.New("--idempotency-key must be 16-128 safe characters")
		}
		path := remoteReceiptFile0284(remoteDir0284(root), key)
		receipt, err := remoteReadReceipt0284(path)
		if err != nil {
			return err
		}
		if receipt.KeyHash != strings.TrimSuffix(filepath.Base(path), ".json") {
			return errors.New("corrupt command journal binding")
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{
			"receipt": receipt, "observedHostStatus": json.RawMessage(remoteHostStatus0284(root)),
			"inspectionTime":         time.Now().UTC().Format(time.RFC3339Nano),
			"verifiedExternalEffect": false,
			"operatorAction":         "compare game/application state and audit before issuing another idempotency key",
		})
	case "init":
		id, err := remoteInit0284(root)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]string{"nodeId": id.NodeID, "status": "initialized"})
	case "rotate-key":
		id, err := remoteLoad0284(root)
		if err != nil {
			return err
		}
		key, err := remoteRandom0284(32)
		if err != nil {
			return err
		}
		id.Key = key
		if err = remoteAuditLog0284(remoteDir0284(root), remoteAudit0284{At: time.Now().UTC().Format(time.RFC3339Nano), Event: "local-rotate-key", IP: "local", Outcome: "accepted"}); err != nil {
			return err
		}
		if err = remoteSave0284(filepath.Join(remoteDir0284(root), "identity.json"), id); err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]string{"nodeId": id.NodeID, "status": "key-rotated", "effect": "all old service tokens invalidated on next request"})
	case "issue":
		id, err := remoteLoad0284(root)
		if err != nil {
			return err
		}
		output := flagValue(args, "--token-file", "")
		if output == "" {
			return errors.New("--token-file required; tokens are never printed")
		}
		ttl, err := positiveIntFlag01910(args, "--ttl-seconds", 300)
		if err != nil {
			return err
		}
		token, err := remoteIssue0284(id, flagValue(args, "--subject", ""), multiFlagValues01910(args, "--scope"), multiFlagValues01910(args, "--source"), time.Duration(ttl)*time.Second, time.Now())
		if err != nil {
			return err
		}
		c, err := remoteTokenDecode0284(id, token, time.Now())
		if err != nil {
			return err
		}
		if err = remoteAuditLog0284(remoteDir0284(root), remoteAudit0284{At: time.Now().UTC().Format(time.RFC3339Nano), Event: "local-issue-token", IP: "local", TokenID: c.ID, Subject: c.Subject, Outcome: "accepted"}); err != nil {
			return err
		}
		f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.WriteString(token + "\n")
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			_ = os.Remove(output)
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]string{"status": "issued", "tokenFile": output, "nodeId": id.NodeID})
	case "revoke":
		id, err := remoteLoad0284(root)
		if err != nil {
			return err
		}
		token, err := remoteReadTokenFile0284(flagValue(args, "--token-file", ""))
		if err != nil {
			return err
		}
		c, err := remoteTokenDecode0284(id, token, time.Now())
		if err != nil {
			return err
		}
		if err = remoteAuditLog0284(remoteDir0284(root), remoteAudit0284{At: time.Now().UTC().Format(time.RFC3339Nano), Event: "local-revoke-token", IP: "local", TokenID: c.ID, Subject: c.Subject, Outcome: "accepted"}); err != nil {
			return err
		}
		if err = remoteRevokeToken0284(remoteDir0284(root), c, time.Now()); err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]string{"status": "revoked", "tokenId": c.ID})
	case "serve":
		id, err := remoteLoad0284(root)
		if err != nil {
			return err
		}
		listen := flagValue(args, "--listen", "127.0.0.1:9443")
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return err
		}
		if net.ParseIP(host) == nil {
			return errors.New("--listen must use a numeric bind IP")
		}
		sources := multiFlagValues01910(args, "--allow-source")
		if len(sources) == 0 {
			sources = []string{"127.0.0.0/8", "::1/128"}
		}
		agent, err := remoteNewAgent0284(root, id, sources)
		if err != nil {
			return err
		}
		certFile, keyFile := flagValue(args, "--tls-cert", ""), flagValue(args, "--tls-key", "")
		if certFile == "" || keyFile == "" {
			return errors.New("TLS certificate and private key are mandatory")
		}
		if err := remoteCheckFile0284(keyFile); err != nil {
			return fmt.Errorf("TLS private key: %w", err)
		}
		release, err := remoteAcquireLease0284(remoteDir0284(root), id.NodeID)
		if err != nil {
			return err
		}
		defer release()
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
		if ca := flagValue(args, "--client-ca", ""); ca != "" {
			pem, err := os.ReadFile(ca)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return errors.New("invalid client CA")
			}
			config.ClientCAs = pool
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
		server := &http.Server{Addr: listen, Handler: agent, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
		listener, err := tls.Listen("tcp", listen, config)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return remoteServeManaged0428(ctx, server, listener)
	default:
		return fmt.Errorf("unknown remote subcommand: %s", args[0])
	}
}
func remoteReadTokenFile0284(path string) (string, error) {
	if path == "" {
		return "", errors.New("--token-file required")
	}
	if err := remoteCheckFile0284(path); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
func remoteCall0284(args []string) error {
	url := strings.TrimRight(flagValue(args, "--url", ""), "/")
	if !strings.HasPrefix(url, "https://") || strings.Contains(url, "@") || strings.ContainsAny(url, "?#") {
		return errors.New("remote URL must be an https:// origin without credentials/query/fragment")
	}
	token, err := remoteReadTokenFile0284(flagValue(args, "--token-file", ""))
	if err != nil {
		return err
	}
	certs := x509.NewCertPool()
	ca := flagValue(args, "--ca-file", "")
	if ca == "" {
		return errors.New("--ca-file required; insecure TLS is unsupported")
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	if !certs.AppendCertsFromPEM(pem) {
		return errors.New("invalid CA file")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: certs}
	if cert, key := flagValue(args, "--client-cert", ""), flagValue(args, "--client-key", ""); cert != "" || key != "" {
		if cert == "" || key == "" {
			return errors.New("client certificate and key must both be supplied")
		}
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	client := &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	action := flagValue(args, "--action", "status")
	var method, path string
	var body io.Reader
	if action == "status" {
		method = http.MethodGet
		path = "/v1/host/status"
	} else if action == "start" || action == "stop" || action == "restart" {
		method = http.MethodPost
		path = "/v1/host/commands"
		encoded, _ := json.Marshal(remoteCommand0284{Action: action})
		body = bytes.NewReader(encoded)
		if !remoteIdempotency0284.MatchString(flagValue(args, "--idempotency-key", "")) {
			return errors.New("mutations require --idempotency-key (16-128 safe characters)")
		}
	} else {
		return errors.New("unsupported remote action")
	}
	request, err := http.NewRequest(method, url+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	if method == http.MethodPost {
		request.Header.Set("Idempotency-Key", flagValue(args, "--idempotency-key", ""))
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		return fmt.Errorf("remote returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(content)))
	}
	if !json.Valid(content) {
		return errors.New("remote response is not JSON")
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), json.RawMessage(content))
}

// remoteServeManaged0428 stops accepting new connections on SIGTERM while
// allowing the durable command journal to finish and fsync receipts. A forced
// timeout is returned as an error: an in-flight command may be indeterminate
// and must be reconciled, never retried with a new idempotency key.
func remoteServeManaged0428(ctx context.Context, server *http.Server, listener net.Listener) error {
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		<-finished
		return fmt.Errorf("remote HTTPS shutdown incomplete; inspect durable command receipts before retrying: %w", err)
	}
	if err := <-finished; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
