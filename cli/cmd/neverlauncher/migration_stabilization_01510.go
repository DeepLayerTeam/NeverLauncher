package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const releaseTrustStateSchema01510 = "2.1"

type releaseTrustStateLock01510 struct {
	SchemaVersion string `json:"schemaVersion"`
	PID           int    `json:"pid"`
	CreatedAt     string `json:"createdAt"`
}

type componentStateMigrationReport01510 struct {
	SchemaVersion string `json:"schemaVersion"`
	ToolVersion   string `json:"toolVersion"`
	Root          string `json:"root"`
	Source        string `json:"source,omitempty"`
	Destination   string `json:"destination"`
	Version       string `json:"version,omitempty"`
	Migrated      bool   `json:"migrated"`
	Status        string `json:"status"`
}

func migrationStabilizationRequired01510(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 10)))
}

func resolveReleaseTrustStatePath01510(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE"))
	}
	return path
}

func withReleaseTrustStateLock01510(path string, fn func() error) error {
	path = resolveReleaseTrustStatePath01510(path)
	if path == "" {
		return errors.New("0.15.10 Release Verification требует persistent trust state для serialized verification")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}
	lockPath := abs + ".lock"
	payload := releaseTrustStateLock01510{SchemaVersion: "1.0", PID: os.Getpid(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(payload)
	for attempt := 0; attempt < 2; attempt++ {
		f, openErr := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr == nil {
			if _, err := f.Write(append(raw, '\n')); err != nil {
				_ = f.Close()
				_ = os.Remove(lockPath)
				return err
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				_ = os.Remove(lockPath)
				return err
			}
			if err := f.Close(); err != nil {
				_ = os.Remove(lockPath)
				return err
			}
			syncDirBestEffort0156(filepath.Dir(lockPath))
			defer func() {
				_ = os.Remove(lockPath)
				syncDirBestEffort0156(filepath.Dir(lockPath))
			}()
			return fn()
		}
		if !errors.Is(openErr, os.ErrExist) {
			return fmt.Errorf("release trust-state lock: %w", openErr)
		}
		existingRaw, readErr := os.ReadFile(lockPath)
		if readErr != nil {
			return fmt.Errorf("release trust-state lock unreadable: %w", readErr)
		}
		var existing releaseTrustStateLock01510
		if err := json.Unmarshal(existingRaw, &existing); err != nil || existing.PID <= 0 {
			return errors.New("release trust-state lock повреждён; удалите lock только после проверки отсутствия активного verifier")
		}
		if updaterProcessAlive0156(existing.PID) {
			return fmt.Errorf("release trust state занят verifier process pid=%d", existing.PID)
		}
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale release trust-state lock: %w", err)
		}
	}
	return errors.New("не удалось получить release trust-state lock")
}

func validateComponentUpdateState01510(state componentUpdateState0157) error {
	if state.SchemaVersion != "1.0" {
		return fmt.Errorf("component state schemaVersion=%q unsupported", state.SchemaVersion)
	}
	if _, _, _, ok := parseCoreVersion(state.Version); !ok {
		return fmt.Errorf("component state version invalid: %q", state.Version)
	}
	if strings.TrimSpace(state.Platform) == "" || strings.TrimSpace(state.Architecture) == "" {
		return errors.New("component state target is incomplete")
	}
	if len(state.Components) != 3 {
		return fmt.Errorf("component state requires exactly three components, got %d", len(state.Components))
	}
	seen := map[string]bool{}
	for _, item := range state.Components {
		if item.Component != "desktop" && item.Component != "guard" && item.Component != "runtime" {
			return fmt.Errorf("component state contains unknown component %q", item.Component)
		}
		if seen[item.Component] || !validSHA256Hex0157(item.SHA256) || item.Size <= 0 {
			return fmt.Errorf("component state metadata invalid for %s", item.Component)
		}
		if err := validateComponentRelativePath0157(item.TargetPath); err != nil {
			return err
		}
		seen[item.Component] = true
	}
	return nil
}

func readComponentUpdateStateOptional01510(path string) (componentUpdateState0157, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return componentUpdateState0157{}, false, nil
	}
	if err != nil {
		return componentUpdateState0157{}, false, err
	}
	var state componentUpdateState0157
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, false, fmt.Errorf("component update state %s: %w", path, err)
	}
	if err := validateComponentUpdateState01510(state); err != nil {
		return state, false, fmt.Errorf("component update state %s: %w", path, err)
	}
	return state, true, nil
}

func componentStateEquivalent01510(a, b componentUpdateState0157) bool {
	if a.Version != b.Version || a.Platform != b.Platform || a.Architecture != b.Architecture || len(a.Components) != len(b.Components) {
		return false
	}
	byComponent := map[string]componentUpdateArtifact0157{}
	for _, item := range a.Components {
		byComponent[item.Component] = item
	}
	for _, item := range b.Components {
		previous, ok := byComponent[item.Component]
		if !ok || previous.TargetPath != item.TargetPath || previous.Size != item.Size || !strings.EqualFold(previous.SHA256, item.SHA256) {
			return false
		}
	}
	return true
}

func compareComponentStateVersion01510(a, b string) (int, error) {
	av, okA := parseVersionTriple0158(a)
	bv, okB := parseVersionTriple0158(b)
	if !okA || !okB {
		return 0, errors.New("component state contains invalid semantic version")
	}
	return compareVersionTriple0158(av, bv), nil
}

func migrateComponentUpdateState01510(root string) (componentStateMigrationReport01510, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return componentStateMigrationReport01510{}, err
	}
	abs = filepath.Clean(abs)
	canonical := filepath.Join(abs, filepath.FromSlash(componentUpdateStateFile0157))
	legacy := filepath.Join(abs, filepath.FromSlash(updaterCoreDir0156), "component-update-state.json")
	report := componentStateMigrationReport01510{SchemaVersion: "1.0", ToolVersion: version, Root: abs, Destination: canonical, Status: "unchanged"}

	current, hasCurrent, err := readComponentUpdateStateOptional01510(canonical)
	if err != nil {
		return report, err
	}
	old, hasLegacy, err := readComponentUpdateStateOptional01510(legacy)
	if err != nil {
		return report, err
	}
	if !hasLegacy {
		if hasCurrent {
			report.Version = current.Version
		}
		return report, nil
	}

	selected := old
	report.Source = legacy
	if hasCurrent {
		cmp, err := compareComponentStateVersion01510(current.Version, old.Version)
		if err != nil {
			return report, err
		}
		switch {
		case cmp > 0:
			selected = current
		case cmp == 0 && !componentStateEquivalent01510(current, old):
			return report, errors.New("canonical and legacy component states disagree for the same version")
		case cmp == 0:
			selected = current
		}
	}
	if err := writeJSONFileAtomicMode(canonical, selected, 0o600); err != nil {
		return report, fmt.Errorf("persist canonical component state: %w", err)
	}
	if err := os.Remove(legacy); err != nil && !errors.Is(err, os.ErrNotExist) {
		return report, fmt.Errorf("remove legacy component state after canonical commit: %w", err)
	}
	syncDirBestEffort0156(filepath.Dir(canonical))
	syncDirBestEffort0156(filepath.Dir(legacy))
	report.Migrated = true
	report.Version = selected.Version
	report.Status = "migrated"
	return report, nil
}

func removeUpdaterTerminalPayload01510(txDir string) error {
	for _, name := range []string{"stage", "backup"} {
		if err := os.RemoveAll(filepath.Join(txDir, name)); err != nil {
			return err
		}
	}
	syncDirBestEffort0156(txDir)
	return nil
}

func removeSafeComponentTreePayload01510(u *transactionalUpdater0156, journal *componentTreeJournal0157) error {
	control, err := filepath.Abs(u.controlDir)
	if err != nil {
		return err
	}
	for _, candidate := range []string{journal.BackupPath, journal.FailedPath, journal.StagePath} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(control, abs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			continue // Never clean a path outside the updater control directory.
		}
		if err := os.RemoveAll(abs); err != nil {
			return err
		}
	}
	return nil
}

func (u *transactionalUpdater0156) stabilizeTerminalPayloads01510() (int, error) {
	cleaned := 0
	txRoot := filepath.Join(u.controlDir, "transactions")
	if entries, err := os.ReadDir(txRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			journal, err := u.readJournal(entry.Name())
			if err != nil {
				return cleaned, err
			}
			if journal.Phase == "committed" || journal.Phase == "rolled-back" {
				if err := removeUpdaterTerminalPayload01510(u.transactionDir(journal.ID)); err != nil {
					return cleaned, err
				}
				cleaned++
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return cleaned, err
	}

	treeRoot := filepath.Join(u.controlDir, "component-trees")
	if entries, err := os.ReadDir(treeRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			journal, err := readComponentTreeJournal0157(u, entry.Name())
			if err != nil {
				return cleaned, err
			}
			if journal.Phase == "committed" || journal.Phase == "rolled-back" {
				if err := removeSafeComponentTreePayload01510(u, journal); err != nil {
					return cleaned, err
				}
				cleaned++
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return cleaned, err
	}
	return cleaned, nil
}

func migrateUpdaterState01510(root string, force bool) (map[string]any, error) {
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		return nil, err
	}
	if err := updater.acquireLock(force); err != nil {
		return nil, err
	}
	defer updater.releaseLock()
	fileRecovered, err := updater.recoverIncompleteLocked()
	if err != nil {
		return nil, err
	}
	treeRecovered, err := updater.recoverComponentTreesLocked0157()
	if err != nil {
		return nil, err
	}
	stateReport, err := migrateComponentUpdateState01510(updater.root)
	if err != nil {
		return nil, err
	}
	cleaned, err := updater.stabilizeTerminalPayloads01510()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"schemaVersion": "1.0", "toolVersion": version, "mode": "migration-stabilization-0.15.10",
		"root": updater.root, "fileTransactionsRecovered": fileRecovered, "componentTreesRecovered": treeRecovered,
		"componentState": stateReport, "terminalPayloadsCleaned": cleaned, "status": "ok",
	}, nil
}

func runMigrationStabilizationSelfTest01510() (map[string]any, error) {
	root, err := os.MkdirTemp("", "neverlauncher-01510-selftest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)

	target, err := currentDeliveryTarget()
	if err != nil {
		return nil, err
	}
	components := []componentUpdateArtifact0157{
		{Component: "desktop", TargetPath: "neverlauncher-desktop", SHA256: strings.Repeat("1", 64), Size: 1, Executable: true},
		{Component: "guard", TargetPath: "neverguard", SHA256: strings.Repeat("2", 64), Size: 1, Executable: true},
		{Component: "runtime", TargetPath: "neverruntime", SHA256: strings.Repeat("3", 64), Size: 1, Executable: true},
	}
	legacyState := componentUpdateState0157{SchemaVersion: "1.0", ToolVersion: "0.15.9", Version: "0.15.9", Platform: target.Platform, Architecture: target.Architecture, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Components: components}
	legacyPath := filepath.Join(root, filepath.FromSlash(updaterCoreDir0156), "component-update-state.json")
	if err := writeJSONFileAtomicMode(legacyPath, legacyState, 0o600); err != nil {
		return nil, err
	}
	migration, err := migrateComponentUpdateState01510(root)
	if err != nil || !migration.Migrated {
		return nil, fmt.Errorf("component state migration failed: %v report=%+v", err, migration)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("legacy component state survived migration")
	}

	live := filepath.Join(root, "live")
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(live, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(source, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(live, "app.bin"), []byte("old"), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(source, "app.bin"), []byte("new"), 0o644); err != nil {
		return nil, err
	}
	updater, err := newTransactionalUpdater0156(live)
	if err != nil {
		return nil, err
	}
	spec, err := selfTestUpdaterSpec0156("app.bin", filepath.Join(source, "app.bin"))
	if err != nil {
		return nil, err
	}
	if _, err := updater.apply(updaterRequest0156{Root: live, Namespace: "01510-rollback", Files: []updaterFileSpec0156{spec}, Verify: func() error { return errors.New("intentional rollback") }}); err == nil {
		return nil, errors.New("stabilization rollback self-test unexpectedly committed")
	}
	txRoot := filepath.Join(updater.controlDir, "transactions")
	entries, err := os.ReadDir(txRoot)
	if err != nil || len(entries) == 0 {
		return nil, errors.New("stabilization self-test transaction journal missing")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, payload := range []string{"stage", "backup"} {
			if _, err := os.Stat(filepath.Join(txRoot, entry.Name(), payload)); !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("terminal transaction retained %s payload", payload)
			}
		}
	}

	trustStatePath := filepath.Join(root, "trust-state.json")
	oldTrustState := releaseTrustState0158{SchemaVersion: releaseSignatureSchema0158, TrustDomain: releaseTrustDomain0158, RootFingerprint: "sha256:" + strings.Repeat("a", 64), HighestTrustEpoch: 9, HighestRelease: "0.15.9", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := writeJSONFileAtomicMode(trustStatePath, oldTrustState, 0o600); err != nil {
		return nil, err
	}
	manifestHash := strings.Repeat("b", 64)
	ctx := releaseVerificationV2Context{Policy: releaseTrustPolicy0158{Epoch: 10}, Envelope: releaseSignatureEnvelopeV2{ReleaseVersion: "0.15.10", ReleaseManifestSHA256: manifestHash, KeyFingerprint: "sha256:" + strings.Repeat("c", 64)}, RootFingerprint: oldTrustState.RootFingerprint, StatePath: trustStatePath}
	if err := commitTrustState0158(ctx); err != nil {
		return nil, err
	}
	migratedTrust, err := loadTrustState0158(trustStatePath)
	if err != nil {
		return nil, err
	}
	if migratedTrust.SchemaVersion != releaseTrustStateSchema01510 || migratedTrust.HighestReleaseManifestSHA256 != manifestHash || migratedTrust.StateRevision == 0 {
		return nil, fmt.Errorf("trust state migration incomplete: %+v", migratedTrust)
	}
	if err := precheckTrustState0158(trustStatePath, oldTrustState.RootFingerprint, 10, "0.15.10", strings.Repeat("d", 64)); err == nil {
		return nil, errors.New("same-version release manifest equivocation was not rejected")
	}

	lockPath := filepath.Join(root, "lock-test-state.json")
	lockHeld := make(chan struct{})
	releaseLock := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- withReleaseTrustStateLock01510(lockPath, func() error {
			close(lockHeld)
			<-releaseLock
			return nil
		})
	}()
	<-lockHeld
	if err := withReleaseTrustStateLock01510(lockPath, func() error { return nil }); err == nil {
		close(releaseLock)
		<-errCh
		return nil, errors.New("concurrent trust-state verifier lock was not rejected")
	}
	close(releaseLock)
	if err := <-errCh; err != nil {
		return nil, err
	}

	return map[string]any{
		"schemaVersion": "1.0", "toolVersion": version, "mode": "migration-stabilization-0.15.10",
		"checks": []string{"legacy-component-state-migration", "terminal-payload-cleanup", "trust-state-2.0-to-2.1", "same-version-manifest-binding", "serialized-trust-state-verification"},
		"status": "ok",
	}, nil
}
