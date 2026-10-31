package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Operator workflows work against actual installed artifacts, the process supervisor,
// and a freshly signed ServerBridge heartbeat observed by Backend. A successful copy
// or enrollment response is deliberately NOT an indication of a healthy deployment.
type bridgeVerification02812 struct {
	SchemaVersion   string `json:"schemaVersion"`
	Status          string `json:"status"`
	LocalVerified   bool   `json:"localVerified"`
	RuntimeVerified bool   `json:"runtimeVerified"`
	ServerID        string `json:"serverId"`
	Platform        string `json:"platform"`
	Version         string `json:"version"`
	ArtifactSHA256  string `json:"artifactSha256"`
	KeyFingerprint  string `json:"keyFingerprint"`
	ObservedAt      string `json:"observedAt,omitempty"`
	RuntimeID       string `json:"runtimeId,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

var bridgeTxID02812 = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{12}$`)

func bridgeEndpointSecure02812(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return errors.New("Backend URL must be a plain HTTPS origin, without userinfo/query/fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("Backend URL must not include an API path")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("Backend credentials require HTTPS outside local loopback")
}

func bridgeInsideRoot02812(root, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("not an absolute managed path: %s", path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("managed path outside server root: %s", path)
	}
	// Do not follow a symlink into another tenant's tree.
	current := root
	for _, segment := range strings.Split(rel, string(os.PathSeparator)) {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed path traverses symlink: %s", current)
		}
	}
	return nil
}

func verifyBridgeLocal02812(root string) (bridgeVerification02812, bridgeProvisionState0199, bridgeEnrollmentRequest0199, error) {
	result := bridgeVerification02812{SchemaVersion: "1.0", Status: "unhealthy"}
	path := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	state, err := readBridgeProvisionState0199(path)
	if err != nil {
		return result, state, bridgeEnrollmentRequest0199{}, fmt.Errorf("managed bridge missing: %w", err)
	}
	result.Platform, result.Version, result.ArtifactSHA256 = state.Platform, state.Version, state.ArtifactSHA256
	if !bridgeSupportedPlatform0199(state.Platform) || state.Version == "" || len(state.ArtifactSHA256) != 64 {
		return result, state, bridgeEnrollmentRequest0199{}, errors.New("invalid managed installation state")
	}
	for _, path := range []string{state.ArtifactPath, state.ConfigPath, state.IdentityPath, state.EnrollmentRequestPath} {
		if err := bridgeInsideRoot02812(root, path); err != nil {
			return result, state, bridgeEnrollmentRequest0199{}, err
		}
	}
	detection, err := detectServerBridgePlatform0199(root, state.Platform)
	if err != nil || detection.Platform != state.Platform || filepath.Clean(state.ConfigPath) != filepath.Clean(detection.ConfigPath) || filepath.Dir(state.ArtifactPath) != detection.InstallDir {
		return result, state, bridgeEnrollmentRequest0199{}, errors.New("platform or managed installation location changed")
	}
	hash, _, err := hashFile(state.ArtifactPath)
	if err != nil || !strings.EqualFold(hash, state.ArtifactSHA256) {
		return result, state, bridgeEnrollmentRequest0199{}, errors.New("installed artifact missing or SHA-256 mismatch")
	}
	if err := verifyBridgeArtifactShape0199(state.ArtifactPath, state.Platform); err != nil {
		return result, state, bridgeEnrollmentRequest0199{}, err
	}
	values, err := readBridgeConfigValues0199(state.ConfigPath)
	if err != nil {
		return result, state, bridgeEnrollmentRequest0199{}, err
	}
	identity, err := loadNodeIdentityPublic0199(state.IdentityPath)
	if err != nil {
		return result, state, bridgeEnrollmentRequest0199{}, err
	}
	reqRaw, err := os.ReadFile(state.EnrollmentRequestPath)
	if err != nil {
		return result, state, bridgeEnrollmentRequest0199{}, err
	}
	var req bridgeEnrollmentRequest0199
	if json.Unmarshal(reqRaw, &req) != nil || req.ID == "" || req.Kind != state.Platform || req.KeyAlgorithm != "ed25519" || req.KeyFingerprint != identity.Fingerprint || req.PublicKey != identity.PublicKey || !strings.EqualFold(req.ArtifactSHA256, hash) {
		return result, state, req, errors.New("enrollment request differs from installed artifact or local node identity")
	}
	if values["server.id"] != req.ID || values["profile.projectId"] != req.ProjectID || values["profile.profileId"] != req.ProfileID || strings.TrimRight(values["backend.url"], "/") != strings.TrimRight(req.BackendURL, "/") {
		return result, state, req, errors.New("runtime config and enrollment request disagree")
	}
	result.ServerID, result.KeyFingerprint, result.LocalVerified = req.ID, req.KeyFingerprint, true
	result.Status = "installed-unverified-runtime"
	return result, state, req, nil
}

func verifyBridgeRuntime02812(local bridgeVerification02812, req bridgeEnrollmentRequest0199, payload map[string]any, now time.Time) (bridgeVerification02812, error) {
	node := findBackendBridgeNode0199(payload, req.ID)
	if node == nil {
		return local, errors.New("Backend has no enrolled node")
	}
	field := func(key string) string { s, _ := node[key].(string); return strings.TrimSpace(s) }
	if field("kind") != req.Kind || field("projectId") != req.ProjectID || field("keyFingerprint") != req.KeyFingerprint {
		return local, errors.New("Backend node identity/platform/project mismatch")
	}
	if field("pluginVersion") != local.Version || !strings.EqualFold(field("pluginSha256"), local.ArtifactSHA256) {
		return local, errors.New("runtime plugin version/digest differs from installed artifact")
	}
	when, err := time.Parse(time.RFC3339Nano, field("lastHeartbeatAt"))
	if err != nil || when.After(now.Add(30*time.Second)) || now.Sub(when) > 90*time.Second {
		return local, errors.New("no fresh attested ServerBridge heartbeat")
	}
	version, _ := node["protocolVersion"].(float64)
	if version < 3 || field("runtimeId") == "" {
		return local, errors.New("signed v3 runtime identity not observed")
	}
	if field("status") == "disabled" || field("status") == "revoked" {
		return local, errors.New("Backend node disabled or revoked")
	}
	if s := field("integrityStatus"); s != "" && s != "verified" && s != "valid" {
		return local, fmt.Errorf("Backend integrity status: %s", s)
	}
	local.RuntimeVerified, local.Status = true, "healthy"
	local.ObservedAt, local.RuntimeID = when.UTC().Format(time.RFC3339Nano), field("runtimeId")
	return local, nil
}

func verifyServerBridge02812(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	result, _, req, err := verifyBridgeLocal02812(root)
	if err != nil {
		return err
	}
	if flagBool(args, "--offline", false) {
		return writeOrPrintJSON(flagValue(args, "--output", ""), result)
	}
	backend := strings.TrimRight(firstNonEmpty0199(flagValue(args, "--backend", ""), req.BackendURL), "/")
	if err := bridgeEndpointSecure02812(backend); err != nil {
		return err
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("runtime verify needs --token or LAUNCHER_TOKEN (or use --offline)")
	}
	payload, err := httpJSONWithAuth("GET", backend+"/api/v1/server-bridge/servers", nil, token)
	if err != nil {
		return err
	}
	result, err = verifyBridgeRuntime02812(result, req, payload, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("ServerBridge runtime not certified healthy: %w", err)
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), result)
}

// Atomic lock for competing operator CLIs. An abandoned lock is not blindly
// stolen: a human must reconcile the partially executed action first.
func bridgeOperatorLock02812(root string) (func(), error) {
	lockPath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "operator.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("provisioning operation already in progress or needs reconciliation: %s", lockPath)
	}
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "startedAt": time.Now().UTC().Format(time.RFC3339Nano)})
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(lockPath)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(lockPath)
		return nil, err
	}
	f.Close()
	return func() { _ = os.Remove(lockPath) }, nil
}

// The game's stop acknowledgement can precede the supervisor releasing its
// session lock. Never race that lock when starting a replacement process.
func bridgeWaitHostExit02812(root string) error {
	path := hostPaths01910(root)["lock"]
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		lock, err := readServerBridgeHostLock01910(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cannot verify old host lock: %w", err)
		}
		if !hostIdentityMatches0282(lock.PID, lock.Identity) {
			return errors.New("stale Host lock requires explicit reconciliation")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("old Host Supervisor did not release its session lock")
}

func bridgeRollout02812(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	if flagBool(args, "--dry-run", false) {
		return errors.New("rollout has side effects; use install/upgrade --dry-run for preflight")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("rollout needs an authenticated --token or LAUNCHER_TOKEN")
	}
	existingPath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	old, oldErr := readBridgeProvisionState0199(existingPath)
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return fmt.Errorf("cannot read current install: %w", oldErr)
	}
	managed := oldErr == nil
	host := hostPaths01910(root)
	if _, err := readServerBridgeHostConfig01910(host["config"]); err != nil {
		return fmt.Errorf("rollout requires configured Host Supervisor: %w", err)
	}
	wasRunning := false
	if runtimeState, err := readServerBridgeHostRuntime01910(host["runtime"]); err == nil {
		if hostIdentityMatches0282(runtimeState.ProcessPID, runtimeState.ProcessIdentity) {
			lock, err := readServerBridgeHostLock01910(host["lock"])
			if err != nil || lock.SessionID != runtimeState.SessionID || !hostIdentityMatches0282(lock.PID, lock.Identity) {
				return errors.New("orphaned or unverified game process: refusing rollout")
			}
			wasRunning = true
		} else if runtimeState.ProcessPID > 0 && (runtimeState.ProcessIdentity == "" && updaterProcessAlive0156(runtimeState.ProcessPID)) {
			return errors.New("unverified legacy game process: refusing rollout")
		}
	}
	if managed {
		if _, _, _, err := verifyBridgeLocal02812(root); err != nil {
			return fmt.Errorf("existing managed installation failed preflight: %w", err)
		}
	}
	// Before modifying a live server, inspect all release metadata and arguments.
	detection, err := detectServerBridgePlatform0199(root, flagValue(args, "--platform", ""))
	if err != nil {
		return err
	}
	bridgeVersion := strings.TrimSpace(flagValue(args, "--bridge-version", version))
	if _, err := resolveBridgeArtifact0199(args, detection.Platform, bridgeVersion); err != nil {
		return err
	}
	backend := strings.TrimRight(firstNonEmpty0199(flagValue(args, "--backend", ""), os.Getenv("LAUNCHER_BACKEND_URL")), "/")
	if backend == "" && managed {
		raw, _ := os.ReadFile(old.EnrollmentRequestPath)
		var req bridgeEnrollmentRequest0199
		_ = json.Unmarshal(raw, &req)
		backend = strings.TrimRight(req.BackendURL, "/")
	}
	if err := bridgeEndpointSecure02812(backend); err != nil {
		return err
	}
	timeout := 120 * time.Second
	if raw := flagValue(args, "--health-timeout-seconds", ""); raw != "" {
		var seconds int
		if _, err := fmt.Sscanf(raw, "%d", &seconds); err != nil || seconds < 5 || seconds > 600 || fmt.Sprint(seconds) != raw {
			return errors.New("--health-timeout-seconds must be 5..600")
		}
		timeout = time.Duration(seconds) * time.Second
	}
	if wasRunning {
		if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
			return fmt.Errorf("game did not stop cleanly; no files changed: %w", err)
		}
		if err := bridgeWaitHostExit02812(root); err != nil {
			return err
		}
	}
	// Every failed phase restores the previous managed artifact/config. Enrollment
	// itself is not reversible on Backend; the operator receives an explicit warning.
	installationDone := false
	rollback := func(problem error) error {
		if !installationDone {
			if wasRunning {
				_ = startServerBridgeHost01910([]string{"--server-root", root})
			}
			return problem
		}
		if state, e := readServerBridgeHostRuntime01910(host["runtime"]); e == nil && hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
			if e := stopServerBridgeHost01910([]string{"--server-root", root}); e != nil {
				return fmt.Errorf("rollout error: %v; rollback BLOCKED: cannot stop new process: %w", problem, e)
			}
		}
		if e := bridgeWaitHostExit02812(root); e != nil {
			return fmt.Errorf("rollout failed: %v; rollback BLOCKED pending supervisor exit: %w", problem, e)
		}
		state, e := readBridgeProvisionState0199(existingPath)
		if e != nil {
			return fmt.Errorf("rollout error: %v; rollback BLOCKED: %w", problem, e)
		}
		if e := rollbackServerBridge0199([]string{"--server-root", root, "--transaction", state.TransactionID}); e != nil {
			return fmt.Errorf("rollout error: %v; rollback failed: %w", problem, e)
		}
		if wasRunning {
			if e := startServerBridgeHost01910([]string{"--server-root", root}); e != nil {
				return fmt.Errorf("rollout error: %v; old files restored but previous server failed restart: %w", problem, e)
			}
		}
		return fmt.Errorf("rollout failed; previous local artifact/config restored (Backend enrollment may need reconciliation): %w", problem)
	}
	op := "install"
	if managed {
		op = "upgrade"
	}
	installArgs := append([]string{op, "--server-root", root, "--backend", backend}, args...)
	if err := provisionServerBridge0199(installArgs, managed); err != nil {
		return rollback(err)
	}
	installationDone = true
	if err := enrollServerBridge0199([]string{"enroll", "--server-root", root, "--backend", backend, "--token", token}); err != nil {
		return rollback(fmt.Errorf("enrollment failed: %w", err))
	}
	activationStart := time.Now().UTC()
	if err := startServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		return rollback(fmt.Errorf("start failed: %w", err))
	}
	deadline := time.Now().Add(timeout)
	var failure error
	for time.Now().Before(deadline) {
		local, _, req, err := verifyBridgeLocal02812(root)
		if err == nil {
			var payload map[string]any
			payload, err = httpJSONWithAuth("GET", backend+"/api/v1/server-bridge/servers", nil, token)
			if err == nil {
				var verified bridgeVerification02812
				verified, err = verifyBridgeRuntime02812(local, req, payload, time.Now().UTC())
				if err == nil {
					observed, _ := time.Parse(time.RFC3339Nano, verified.ObservedAt)
					if observed.Before(activationStart) {
						err = errors.New("heartbeat predates this rollout activation")
					}
				}
			}
		}
		if err == nil {
			state, stateErr := readServerBridgeHostRuntime01910(host["runtime"])
			if stateErr != nil || state.Status != "running" || !hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) || !hostIdentityMatches0282(state.SupervisorPID, state.SupervisorIdentity) {
				err = errors.New("Host Supervisor and JVM not confirmed alive")
			}
		}
		if err == nil {
			return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "status": "healthy", "operation": op, "serverId": local.ServerID, "version": local.Version, "transactionId": func() string { state, _ := readBridgeProvisionState0199(existingPath); return state.TransactionID }()})
		}
		failure = err
		time.Sleep(2 * time.Second)
	}
	return rollback(fmt.Errorf("runtime health did not converge: %w", failure))
}

func bridgeSafeTransaction02812(root string, tx *bridgeProvisionTransaction0199) error {
	if !bridgeTxID02812.MatchString(tx.ID) {
		return errors.New("invalid transaction id")
	}
	if tx.Operation != "install" && tx.Operation != "upgrade" {
		return errors.New("unsupported transaction operation")
	}
	allowedBackup := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "backups", tx.ID)
	if len(tx.Changes) == 0 || len(tx.Changes) > 32 {
		return errors.New("unexpected transaction change count")
	}
	// A transaction file lives on disk and must never be allowed to select
	// arbitrary files under the Minecraft root (worlds, plugins, playerdata).
	state, err := readBridgeProvisionState0199(filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json"))
	if err != nil || state.TransactionID != tx.ID || state.Platform != tx.Platform {
		return errors.New("transaction does not match active managed installation")
	}
	detection := bridgeDetectionForPlatform0199(root, tx.Platform, "verified", nil)
	allowed := map[string]bool{
		filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json"):            true,
		filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "enrollment-request.json"): true,
		detection.ConfigPath: true,
		state.IdentityPath:   true,
	}
	if !strings.HasPrefix(state.IdentityPath, filepath.Dir(detection.ConfigPath)+string(os.PathSeparator)) {
		return errors.New("node identity not stored under managed config directory")
	}
	if detection.Sidecar {
		allowed[filepath.Join(detection.InstallDir, "run-server-bridge.sh")] = true
		allowed[filepath.Join(detection.InstallDir, "run-server-bridge.cmd")] = true
	}
	seen := map[string]bool{}
	for _, change := range tx.Changes {
		if !allowed[change.Path] {
			name := filepath.Base(change.Path)
			if filepath.Dir(change.Path) != detection.InstallDir || !strings.HasPrefix(strings.ToLower(name), "launcher-") || !strings.Contains(strings.ToLower(name), "-bridge-") || !strings.HasSuffix(strings.ToLower(name), ".jar") {
				return fmt.Errorf("transaction target not owned by ServerBridge: %s", change.Path)
			}
		}
		if err := bridgeInsideRoot02812(root, change.Path); err != nil {
			return err
		}
		if seen[change.Path] {
			return errors.New("duplicate transaction target")
		}
		seen[change.Path] = true
		if change.Existed {
			if change.BackupPath == "" || filepath.Dir(change.BackupPath) != allowedBackup {
				return errors.New("transaction backup outside managed backup directory")
			}
			if err := bridgeInsideRoot02812(root, change.BackupPath); err != nil {
				return err
			}
			// Backups use the short sha256 of the exact destination name.
			sum := sha256.Sum256([]byte(filepath.Clean(change.Path)))
			expected := hex.EncodeToString(sum[:8]) + "-" + filepath.Base(change.Path)
			if filepath.Base(change.BackupPath) != expected {
				return errors.New("transaction backup name mismatch")
			}
		} else if change.BackupPath != "" {
			return errors.New("nonexistent target has unexpected backup")
		}
	}
	return nil
}
