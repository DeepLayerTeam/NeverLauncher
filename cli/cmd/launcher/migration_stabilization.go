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
		path = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_TRUST_STATE_FILE"))
	}
	return path
}

func withReleaseTrustStateLock01510(path string, fn func() error) error {
	path = resolveReleaseTrustStatePath01510(path)
	if path == "" {
		return errors.New("Проверка выпуска 0.15.10 требует постоянного хранения состояния доверия для последовательной проверки")
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
			return fmt.Errorf("Блокировка состояния доверия релиза: %w", openErr)
		}
		existingRaw, readErr := os.ReadFile(lockPath)
		if readErr != nil {
			return fmt.Errorf("Не удалось прочитать блокировку состояния доверия релиза: %w", readErr)
		}
		var existing releaseTrustStateLock01510
		if err := json.Unmarshal(existingRaw, &existing); err != nil || existing.PID <= 0 {
			return errors.New("Блокировка состояния доверия выпуска повреждена; удалите её только после проверки отсутствия активного процесса проверки")
		}
		if updaterProcessAlive0156(existing.PID) {
			return fmt.Errorf("Состояние доверия выпуска занято процессом проверки, PID=%d", existing.PID)
		}
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("Удаление устаревшей блокировки состояния доверия релиза: %w", err)
		}
	}
	return errors.New("Не удалось получить блокировку состояния доверия выпуска")
}

func validateComponentUpdateState01510(state componentUpdateState0157) error {
	if state.SchemaVersion != "1.0" {
		return fmt.Errorf("Неподдерживаемая версия схемы состояния компонентов: schemaVersion=%q", state.SchemaVersion)
	}
	if _, _, _, ok := parseCoreVersion(state.Version); !ok {
		return fmt.Errorf("Некорректная версия состояния компонентов: %q", state.Version)
	}
	if strings.TrimSpace(state.Platform) == "" || strings.TrimSpace(state.Architecture) == "" {
		return errors.New("Не полностью задана целевая платформа состояния компонентов")
	}
	expected := 3
	if state.Platform == "windows" && componentCoordinationRequired02310(state.Version) {
		expected = 4
	}
	if len(state.Components) != expected {
		return fmt.Errorf("В состоянии компонентов ожидалось %d компонентов, получено %d", expected, len(state.Components))
	}
	if componentSecurityRequired02311(state.Version) && state.SecurityGeneration == 0 {
		return errors.New("В установленном наборе компонентов версии 0.23.11+ отсутствует securityGeneration")
	}
	if state.SecurityGeneration > 0 {
		if !validSHA256Hex0157(state.ManifestDigest) {
			return errors.New("Неверный формат контрольной суммы манифеста безопасности установленных компонентов")
		}
		if state.Platform == "macos" && (state.BundleName == "" || filepath.Base(state.BundleName) != state.BundleName || !strings.HasSuffix(strings.ToLower(state.BundleName), ".app")) {
			return errors.New("Идентификатор пакета безопасности компонентов macOS отсутствует либо небезопасен")
		}
	}

	seen := map[string]bool{}
	for _, item := range state.Components {
		if item.Component != "desktop" && item.Component != "guard" && item.Component != "runtime" && !(expected == 4 && item.Component == "sensor") {
			return fmt.Errorf("Состояние компонентов содержит неизвестный компонент %q", item.Component)
		}
		if seen[item.Component] || !validSHA256Hex0157(item.SHA256) || item.Size <= 0 {
			return fmt.Errorf("Неверные метаданные состояния компонента %s", item.Component)
		}
		if err := validateComponentRelativePath0157(item.TargetPath); err != nil {
			return err
		}
		seen[item.Component] = true
	}
	if componentSecurityRequired02311(state.Version) {
		if len(state.SupportFiles) != 1 || state.SupportFiles[0].Component != "updater" || !validSHA256Hex0157(state.SupportFiles[0].SHA256) {
			return errors.New("В состоянии безопасности установленных компонентов отсутствует вспомогательная программа обновления")
		}
		if err := validateComponentRelativePath0157(state.SupportFiles[0].TargetPath); err != nil {
			return err
		}
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
		return state, false, fmt.Errorf("Состояние обновления компонента %s: %w", path, err)
	}
	if err := validateComponentUpdateState01510(state); err != nil {
		return state, false, fmt.Errorf("Состояние обновления компонента %s: %w", path, err)
	}
	return state, true, nil
}

func componentStateEquivalent01510(a, b componentUpdateState0157) bool {
	if a.SecurityGeneration != b.SecurityGeneration || a.ManifestDigest != b.ManifestDigest || a.BundleName != b.BundleName || len(a.SupportFiles) != len(b.SupportFiles) {
		return false
	}
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
	for i := range a.SupportFiles {
		x, y := a.SupportFiles[i], b.SupportFiles[i]
		if x.Component != y.Component || x.TargetPath != y.TargetPath || x.Size != y.Size || !strings.EqualFold(x.SHA256, y.SHA256) {
			return false
		}
	}
	return true
}

func compareComponentStateVersion01510(a, b string) (int, error) {
	av, okA := parseVersionTriple0158(a)
	bv, okB := parseVersionTriple0158(b)
	if !okA || !okB {
		return 0, errors.New("В состоянии компонента указана неверная семантическая версия")
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
		// Локальные миграции совместимости не должны отменять минимальные требования безопасности
		// только из-за более высокого SemVer в устаревших метаданных.
		if current.SecurityGeneration > old.SecurityGeneration {
			selected = current
		} else if old.SecurityGeneration > current.SecurityGeneration {
			selected = old
		} else {
			cmp, err := compareComponentStateVersion01510(current.Version, old.Version)
			if err != nil {
				return report, err
			}
			switch {
			case cmp > 0:
				selected = current
			case cmp == 0 && !componentStateEquivalent01510(current, old):
				return report, errors.New("Для одной версии основное и устаревшее состояния компонентов не совпадают")
			case cmp == 0:
				selected = current
			}
		}
	}
	if err := writeJSONFileAtomicMode(canonical, selected, 0o600); err != nil {
		return report, fmt.Errorf("Сохранение основного состояния компонентов: %w", err)
	}
	if err := os.Remove(legacy); err != nil && !errors.Is(err, os.ErrNotExist) {
		return report, fmt.Errorf("Удаление устаревшего состояния компонентов после фиксации основного: %w", err)
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
			continue // Никогда не удаляйте путь за пределами управляющего каталога обновлятора.
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
	root, err := os.MkdirTemp("", "launcher-01510-selftest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)

	target, err := currentDeliveryTarget()
	if err != nil {
		return nil, err
	}
	components := []componentUpdateArtifact0157{
		{Component: "desktop", TargetPath: "launcher-desktop", SHA256: strings.Repeat("1", 64), Size: 1, Executable: true},
		{Component: "guard", TargetPath: "guard", SHA256: strings.Repeat("2", 64), Size: 1, Executable: true},
		{Component: "runtime", TargetPath: "runtime", SHA256: strings.Repeat("3", 64), Size: 1, Executable: true},
	}
	legacyState := componentUpdateState0157{SchemaVersion: "1.0", ToolVersion: "0.15.9", Version: "0.15.9", Platform: target.Platform, Architecture: target.Architecture, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Components: components}
	legacyPath := filepath.Join(root, filepath.FromSlash(updaterCoreDir0156), "component-update-state.json")
	if err := writeJSONFileAtomicMode(legacyPath, legacyState, 0o600); err != nil {
		return nil, err
	}
	migration, err := migrateComponentUpdateState01510(root)
	if err != nil || !migration.Migrated {
		return nil, fmt.Errorf("Ошибка миграции состояния компонентов: %v; отчёт=%+v", err, migration)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("После миграции осталось устаревшее состояние компонентов")
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
	if _, err := updater.apply(updaterRequest0156{Root: live, Namespace: "01510-rollback", Files: []updaterFileSpec0156{spec}, Verify: func() error { return errors.New("Преднамеренная ошибка для проверки отката") }}); err == nil {
		return nil, errors.New("Проверка отката при стабилизации неожиданно зафиксировала транзакцию")
	}
	txRoot := filepath.Join(updater.controlDir, "transactions")
	entries, err := os.ReadDir(txRoot)
	if err != nil || len(entries) == 0 {
		return nil, errors.New("Отсутствует журнал транзакции самопроверки стабилизации")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, payload := range []string{"stage", "backup"} {
			if _, err := os.Stat(filepath.Join(txRoot, entry.Name(), payload)); !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("После завершённой транзакции остались данные %s", payload)
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
		return nil, fmt.Errorf("Миграция состояния доверия не завершена: %+v", migratedTrust)
	}
	if err := precheckTrustState0158(trustStatePath, oldTrustState.RootFingerprint, 10, "0.15.10", strings.Repeat("d", 64)); err == nil {
		return nil, errors.New("Противоречивые манифесты релиза одной версии не были отклонены")
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
		return nil, errors.New("Конфликтующая блокировка параллельной проверки доверия не была отклонена")
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
