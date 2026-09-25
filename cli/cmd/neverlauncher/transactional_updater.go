package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const updaterCoreSchema0156 = "1.0"
const updaterCoreDir0156 = ".neverlauncher/updater"

type updaterFileSpec0156 struct {
	Path       string
	Source     string
	Data       []byte
	Size       int64
	SHA256     string
	Executable bool
}

type updaterRequest0156 struct {
	Root        string
	Namespace   string
	FromVersion string
	ToVersion   string
	Files       []updaterFileSpec0156
	Remove      []string
	Verify      func() error
}

type updaterTouchedPath0156 struct {
	Path         string `json:"path"`
	HadOriginal  bool   `json:"hadOriginal"`
	OriginalMode uint32 `json:"originalMode,omitempty"`
}

type updaterJournal0156 struct {
	SchemaVersion string                   `json:"schemaVersion"`
	EngineVersion string                   `json:"engineVersion"`
	ID            string                   `json:"id"`
	Namespace     string                   `json:"namespace"`
	Root          string                   `json:"root"`
	FromVersion   string                   `json:"fromVersion,omitempty"`
	ToVersion     string                   `json:"toVersion,omitempty"`
	Phase         string                   `json:"phase"`
	CreatedAt     string                   `json:"createdAt"`
	UpdatedAt     string                   `json:"updatedAt"`
	Files         []updaterJournalFile0156 `json:"files"`
	Remove        []string                 `json:"remove,omitempty"`
	Touched       []updaterTouchedPath0156 `json:"touched"`
	Applied       []string                 `json:"applied,omitempty"`
	Error         string                   `json:"error,omitempty"`
}

type updaterJournalFile0156 struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable,omitempty"`
}

type updaterLock0156 struct {
	SchemaVersion string `json:"schemaVersion"`
	PID           int    `json:"pid"`
	CreatedAt     string `json:"createdAt"`
}

type transactionalUpdater0156 struct {
	root       string
	controlDir string
	lockPath   string
	lockHeld   bool
}

func newTransactionalUpdater0156(root string) (*transactionalUpdater0156, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("updater root пуст")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("создание updater root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve updater root: %w", err)
	}
	abs, err = filepath.Abs(realRoot)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	return &transactionalUpdater0156{
		root:       abs,
		controlDir: filepath.Join(abs, filepath.FromSlash(updaterCoreDir0156)),
		lockPath:   filepath.Join(abs, filepath.FromSlash(updaterCoreDir0156), "lock.json"),
	}, nil
}

func (u *transactionalUpdater0156) apply(req updaterRequest0156) (map[string]any, error) {
	if strings.TrimSpace(req.Root) != "" {
		reqRoot, err := filepath.Abs(req.Root)
		if err != nil {
			return nil, err
		}
		if resolved, resolveErr := filepath.EvalSymlinks(reqRoot); resolveErr == nil {
			reqRoot = resolved
		}
		reqRoot, err = filepath.Abs(reqRoot)
		if err != nil {
			return nil, err
		}
		if filepath.Clean(reqRoot) != u.root {
			return nil, fmt.Errorf("updater request root mismatch: request=%s engine=%s", filepath.Clean(reqRoot), u.root)
		}
	}
	if err := u.acquireLock(false); err != nil {
		return nil, err
	}
	defer u.releaseLock()

	recovered, err := u.recoverIncompleteLocked()
	if err != nil {
		return nil, fmt.Errorf("automatic updater recovery: %w", err)
	}
	journal, err := u.prepareLocked(req)
	if err != nil {
		// prepare never mutates live bytes, but it may already have created a durable
		// staging journal. Terminalize it so the next run does not inherit noise.
		_, _ = u.recoverIncompleteLocked()
		return nil, err
	}
	if err := u.commitLocked(journal, req.Verify); err != nil {
		rollbackErr := u.rollbackLocked(journal, err)
		if rollbackErr != nil {
			return nil, fmt.Errorf("transaction %s failed: %v; rollback failed: %w", journal.ID, err, rollbackErr)
		}
		return nil, fmt.Errorf("transaction %s rolled back: %w", journal.ID, err)
	}
	return map[string]any{
		"schemaVersion": updaterCoreSchema0156,
		"toolVersion":   version,
		"engine":        "unified-transactional-updater",
		"transactionId": journal.ID,
		"namespace":     journal.Namespace,
		"fromVersion":   journal.FromVersion,
		"toVersion":     journal.ToVersion,
		"root":          u.root,
		"appliedFiles":  len(journal.Files),
		"removedFiles":  len(journal.Remove),
		"recovered":     recovered,
		"status":        "committed",
	}, nil
}

func (u *transactionalUpdater0156) acquireLock(force bool) error {
	if err := os.MkdirAll(u.controlDir, 0o755); err != nil {
		return err
	}
	payload := updaterLock0156{SchemaVersion: updaterCoreSchema0156, PID: os.Getpid(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(payload)
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(u.lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if _, err := f.Write(append(raw, '\n')); err != nil {
				_ = f.Close()
				_ = os.Remove(u.lockPath)
				return err
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				_ = os.Remove(u.lockPath)
				return err
			}
			if err := f.Close(); err != nil {
				_ = os.Remove(u.lockPath)
				return err
			}
			u.lockHeld = true
			syncDirBestEffort0156(u.controlDir)
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("updater lock: %w", err)
		}
		lockRaw, readErr := os.ReadFile(u.lockPath)
		if readErr != nil {
			return fmt.Errorf("updater lock уже существует и не читается: %w", readErr)
		}
		var existing updaterLock0156
		if json.Unmarshal(lockRaw, &existing) == nil && existing.PID > 0 && updaterProcessAlive0156(existing.PID) && !force {
			return fmt.Errorf("updater занят процессом pid=%d", existing.PID)
		}
		if !force && existing.PID <= 0 {
			return errors.New("updater lock повреждён; используйте update recover --force")
		}
		if err := os.Remove(u.lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("удаление stale updater lock: %w", err)
		}
	}
	return errors.New("не удалось получить updater lock")
}

func (u *transactionalUpdater0156) releaseLock() {
	if !u.lockHeld {
		return
	}
	_ = os.Remove(u.lockPath)
	u.lockHeld = false
	syncDirBestEffort0156(u.controlDir)
}

func (u *transactionalUpdater0156) prepareLocked(req updaterRequest0156) (*updaterJournal0156, error) {
	if !u.lockHeld {
		return nil, errors.New("updater lock не удерживается")
	}
	if strings.TrimSpace(req.Namespace) == "" {
		req.Namespace = "default"
	}
	files, remove, err := normalizeUpdaterRequest0156(req.Files, req.Remove)
	if err != nil {
		return nil, err
	}
	id, err := newUpdaterTransactionID0156()
	if err != nil {
		return nil, err
	}
	txDir := u.transactionDir(id)
	stageDir := filepath.Join(txDir, "stage")
	backupDir := filepath.Join(txDir, "backup")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return nil, err
	}

	journal := &updaterJournal0156{
		SchemaVersion: updaterCoreSchema0156,
		EngineVersion: version,
		ID:            id,
		Namespace:     req.Namespace,
		Root:          u.root,
		FromVersion:   req.FromVersion,
		ToVersion:     req.ToVersion,
		Phase:         "staging",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Remove:        remove,
		Applied:       []string{},
	}
	for _, spec := range files {
		journal.Files = append(journal.Files, updaterJournalFile0156{Path: spec.Path, Size: spec.Size, SHA256: strings.ToLower(spec.SHA256), Executable: spec.Executable})
	}
	if err := u.writeJournal(journal); err != nil {
		return nil, err
	}

	// Stage verified bytes before touching the live tree.
	for _, spec := range files {
		stagePath := filepath.Join(stageDir, filepath.FromSlash(spec.Path))
		if err := os.MkdirAll(filepath.Dir(stagePath), 0o755); err != nil {
			return nil, err
		}
		mode := os.FileMode(0o644)
		if spec.Executable {
			mode = 0o755
		}
		if len(spec.Data) > 0 || (spec.Data != nil && spec.Size == 0) {
			if err := writeUpdaterBytes0156(stagePath, spec.Data, mode); err != nil {
				return nil, fmt.Errorf("stage %s: %w", spec.Path, err)
			}
		} else {
			if err := copyUpdaterSource0156(spec.Source, stagePath, mode); err != nil {
				return nil, fmt.Errorf("stage %s: %w", spec.Path, err)
			}
		}
		if err := verifyUpdaterFile0156(stagePath, spec.Size, spec.SHA256); err != nil {
			return nil, fmt.Errorf("stage verify %s: %w", spec.Path, err)
		}
	}

	// Capture all live paths before any replacement/removal. This is the rollback boundary.
	touchedPaths := make([]string, 0, len(files)+len(remove))
	for _, spec := range files {
		touchedPaths = append(touchedPaths, spec.Path)
	}
	touchedPaths = append(touchedPaths, remove...)
	sort.Strings(touchedPaths)
	for _, rel := range touchedPaths {
		dst, err := u.safeLivePath(rel)
		if err != nil {
			return nil, err
		}
		touched := updaterTouchedPath0156{Path: rel}
		info, statErr := os.Lstat(dst)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("updater target должен быть regular file: %s", rel)
			}
			touched.HadOriginal = true
			touched.OriginalMode = uint32(info.Mode().Perm())
			backup := filepath.Join(backupDir, filepath.FromSlash(rel))
			if err := copyUpdaterSource0156(dst, backup, info.Mode().Perm()); err != nil {
				return nil, fmt.Errorf("backup %s: %w", rel, err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect target %s: %w", rel, statErr)
		}
		journal.Touched = append(journal.Touched, touched)
	}
	journal.Phase = "prepared"
	if err := u.writeJournal(journal); err != nil {
		return nil, err
	}
	return journal, nil
}

func (u *transactionalUpdater0156) commitLocked(journal *updaterJournal0156, verify func() error) error {
	if journal.Phase != "prepared" {
		return fmt.Errorf("transaction %s phase=%s, ожидался prepared", journal.ID, journal.Phase)
	}
	journal.Phase = "committing"
	if err := u.writeJournal(journal); err != nil {
		return err
	}
	stageDir := filepath.Join(u.transactionDir(journal.ID), "stage")

	for _, file := range journal.Files {
		dst, err := u.safeLivePath(file.Path)
		if err != nil {
			return err
		}
		stage := filepath.Join(stageDir, filepath.FromSlash(file.Path))
		if err := verifyUpdaterFile0156(stage, file.Size, file.SHA256); err != nil {
			return fmt.Errorf("pre-switch verify %s: %w", file.Path, err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp := dst + ".nl0156-" + journal.ID
		mode := os.FileMode(0o644)
		if file.Executable {
			mode = 0o755
		}
		if err := copyUpdaterSource0156(stage, tmp, mode); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("prepare live replacement %s: %w", file.Path, err)
		}
		if err := verifyUpdaterFile0156(tmp, file.Size, file.SHA256); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replacement verify %s: %w", file.Path, err)
		}
		if err := replaceFileAtomicPortable(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("atomic switch %s: %w", file.Path, err)
		}
		syncDirBestEffort0156(filepath.Dir(dst))
		journal.Applied = append(journal.Applied, file.Path)
		if err := u.writeJournal(journal); err != nil {
			return err
		}
	}

	for _, rel := range journal.Remove {
		dst, err := u.safeLivePath(rel)
		if err != nil {
			return err
		}
		info, err := os.Lstat(dst)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("updater remove target должен быть regular file: %s", rel)
		}
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("remove obsolete %s: %w", rel, err)
		}
		syncDirBestEffort0156(filepath.Dir(dst))
		journal.Applied = append(journal.Applied, rel)
		if err := u.writeJournal(journal); err != nil {
			return err
		}
	}

	journal.Phase = "verifying"
	if err := u.writeJournal(journal); err != nil {
		return err
	}
	if verify != nil {
		if err := verify(); err != nil {
			return fmt.Errorf("post-apply verification: %w", err)
		}
	}
	for _, file := range journal.Files {
		dst, err := u.safeLivePath(file.Path)
		if err != nil {
			return err
		}
		if err := verifyUpdaterFile0156(dst, file.Size, file.SHA256); err != nil {
			return fmt.Errorf("final verify %s: %w", file.Path, err)
		}
	}
	for _, rel := range journal.Remove {
		dst, err := u.safeLivePath(rel)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(dst); err == nil {
			return fmt.Errorf("final verify obsolete path still exists: %s", rel)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	journal.Phase = "committed"
	journal.Error = ""
	if err := u.writeJournal(journal); err != nil {
		return err
	}
	// Rollback bytes are unnecessary after a durable committed journal. Keep the journal for audit/status.
	_ = os.RemoveAll(filepath.Join(u.transactionDir(journal.ID), "stage"))
	_ = os.RemoveAll(filepath.Join(u.transactionDir(journal.ID), "backup"))
	syncDirBestEffort0156(u.transactionDir(journal.ID))
	return nil
}

func (u *transactionalUpdater0156) rollbackLocked(journal *updaterJournal0156, cause error) error {
	journal.Phase = "rolling-back"
	if cause != nil {
		journal.Error = cause.Error()
	}
	// Journal persistence failure must never prevent restoration of already-switched bytes.
	// We retry with the terminal state after live-tree recovery is complete.
	_ = u.writeJournal(journal)
	backupDir := filepath.Join(u.transactionDir(journal.ID), "backup")
	for i := len(journal.Touched) - 1; i >= 0; i-- {
		touched := journal.Touched[i]
		dst, err := u.safeLivePath(touched.Path)
		if err != nil {
			return err
		}
		if !touched.HadOriginal {
			if info, statErr := os.Lstat(dst); statErr == nil {
				if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
					return fmt.Errorf("rollback refuses non-regular target: %s", touched.Path)
				}
				if err := os.Remove(dst); err != nil {
					return err
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
			syncDirBestEffort0156(filepath.Dir(dst))
			continue
		}
		backup := filepath.Join(backupDir, filepath.FromSlash(touched.Path))
		mode := os.FileMode(touched.OriginalMode)
		if mode == 0 {
			mode = 0o644
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp := dst + ".nl0156-rollback-" + journal.ID
		if err := copyUpdaterSource0156(backup, tmp, mode); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("rollback copy %s: %w", touched.Path, err)
		}
		if err := replaceFileAtomicPortable(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("rollback switch %s: %w", touched.Path, err)
		}
		syncDirBestEffort0156(filepath.Dir(dst))
	}
	journal.Phase = "rolled-back"
	if err := u.writeJournal(journal); err != nil {
		return err
	}
	return nil
}

func (u *transactionalUpdater0156) recoverIncompleteLocked() ([]string, error) {
	root := filepath.Join(u.controlDir, "transactions")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	recovered := []string{}
	for _, id := range ids {
		journal, err := u.readJournal(id)
		if err != nil {
			return recovered, err
		}
		switch journal.Phase {
		case "committed", "rolled-back":
			continue
		case "staging":
			// No live bytes were touched yet; record a terminal rollback state.
			journal.Phase = "rolled-back"
			journal.Error = "recovered incomplete staging transaction"
			if err := u.writeJournal(journal); err != nil {
				return recovered, err
			}
		default:
			if err := u.rollbackLocked(journal, errors.New("crash recovery")); err != nil {
				return recovered, fmt.Errorf("recover transaction %s: %w", id, err)
			}
		}
		recovered = append(recovered, id)
	}
	return recovered, nil
}

func (u *transactionalUpdater0156) recover(force bool) (map[string]any, error) {
	if err := u.acquireLock(force); err != nil {
		return nil, err
	}
	defer u.releaseLock()
	recovered, err := u.recoverIncompleteLocked()
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": updaterCoreSchema0156, "toolVersion": version, "engine": "unified-transactional-updater", "root": u.root, "recovered": recovered, "status": "recovered"}, nil
}

func (u *transactionalUpdater0156) status() (map[string]any, error) {
	root := filepath.Join(u.controlDir, "transactions")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"schemaVersion": updaterCoreSchema0156, "toolVersion": version, "engine": "unified-transactional-updater", "root": u.root, "transactions": []any{}, "status": "idle"}, nil
	}
	if err != nil {
		return nil, err
	}
	journals := []updaterJournal0156{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		journal, err := u.readJournal(e.Name())
		if err != nil {
			return nil, err
		}
		journals = append(journals, *journal)
	}
	sort.Slice(journals, func(i, j int) bool { return journals[i].CreatedAt < journals[j].CreatedAt })
	state := "idle"
	for _, j := range journals {
		if j.Phase != "committed" && j.Phase != "rolled-back" {
			state = "recovery-required"
			break
		}
	}
	return map[string]any{"schemaVersion": updaterCoreSchema0156, "toolVersion": version, "engine": "unified-transactional-updater", "root": u.root, "transactions": journals, "status": state}, nil
}

func (u *transactionalUpdater0156) transactionDir(id string) string {
	return filepath.Join(u.controlDir, "transactions", id)
}

func (u *transactionalUpdater0156) journalPath(id string) string {
	return filepath.Join(u.transactionDir(id), "journal.json")
}

func (u *transactionalUpdater0156) writeJournal(journal *updaterJournal0156) error {
	journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	path := u.journalPath(journal.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeUpdaterBytes0156(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	if err := replaceFileAtomicPortable(path+".tmp", path); err != nil {
		_ = os.Remove(path + ".tmp")
		return err
	}
	syncDirBestEffort0156(filepath.Dir(path))
	return nil
}

func (u *transactionalUpdater0156) readJournal(id string) (*updaterJournal0156, error) {
	raw, err := os.ReadFile(u.journalPath(id))
	if err != nil {
		return nil, err
	}
	var journal updaterJournal0156
	if err := json.Unmarshal(raw, &journal); err != nil {
		return nil, err
	}
	if journal.SchemaVersion != updaterCoreSchema0156 || journal.ID != id {
		return nil, fmt.Errorf("invalid updater journal %s", id)
	}
	root, err := filepath.Abs(journal.Root)
	if err != nil || filepath.Clean(root) != u.root {
		return nil, fmt.Errorf("updater journal %s root mismatch", id)
	}
	return &journal, nil
}

func (u *transactionalUpdater0156) safeLivePath(rel string) (string, error) {
	if err := validateUpdaterPath0156(rel); err != nil {
		return "", err
	}
	dst := filepath.Join(u.root, filepath.FromSlash(rel))
	clean := filepath.Clean(dst)
	relToRoot, err := filepath.Rel(u.root, clean)
	if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("updater path escapes root: %s", rel)
	}
	parent := filepath.Dir(clean)
	for p := parent; p != u.root; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("updater refuses symlink parent: %s", rel)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("updater parent is not directory: %s", rel)
		}
	}
	if info, err := os.Lstat(clean); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("updater refuses symlink target: %s", rel)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return clean, nil
}

func normalizeUpdaterRequest0156(files []updaterFileSpec0156, remove []string) ([]updaterFileSpec0156, []string, error) {
	seen := map[string]string{}
	pathKey := func(rel string) string {
		if runtime.GOOS == "windows" {
			return strings.ToLower(rel)
		}
		return rel
	}
	normalizedFiles := make([]updaterFileSpec0156, 0, len(files))
	for _, file := range files {
		rel := strings.ReplaceAll(strings.TrimSpace(file.Path), "\\", "/")
		if err := validateUpdaterPath0156(rel); err != nil {
			return nil, nil, err
		}
		key := pathKey(rel)
		if previous, ok := seen[key]; ok {
			return nil, nil, fmt.Errorf("duplicate updater path %s (%s)", rel, previous)
		}
		if file.Size < 0 || len(strings.TrimSpace(file.SHA256)) != 64 {
			return nil, nil, fmt.Errorf("invalid updater metadata for %s", rel)
		}
		if _, err := hex.DecodeString(file.SHA256); err != nil {
			return nil, nil, fmt.Errorf("invalid updater SHA-256 for %s", rel)
		}
		if len(file.Data) == 0 && file.Data == nil && strings.TrimSpace(file.Source) == "" {
			return nil, nil, fmt.Errorf("updater source отсутствует для %s", rel)
		}
		file.Path = rel
		file.SHA256 = strings.ToLower(file.SHA256)
		seen[key] = "write"
		normalizedFiles = append(normalizedFiles, file)
	}
	normalizedRemove := make([]string, 0, len(remove))
	for _, raw := range remove {
		rel := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
		if err := validateUpdaterPath0156(rel); err != nil {
			return nil, nil, err
		}
		key := pathKey(rel)
		if previous, ok := seen[key]; ok {
			return nil, nil, fmt.Errorf("updater path %s одновременно %s и remove", rel, previous)
		}
		seen[key] = "remove"
		normalizedRemove = append(normalizedRemove, rel)
	}
	sort.Slice(normalizedFiles, func(i, j int) bool { return normalizedFiles[i].Path < normalizedFiles[j].Path })
	sort.Strings(normalizedRemove)
	return normalizedFiles, normalizedRemove, nil
}

func validateUpdaterPath0156(rel string) error {
	if rel == "" || strings.ContainsRune(rel, '\x00') || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return fmt.Errorf("небезопасный updater path: %q", rel)
	}
	if strings.Contains(rel, "\\") {
		return fmt.Errorf("updater path должен использовать '/': %q", rel)
	}
	first := rel
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	if strings.Contains(first, ":") || filepath.VolumeName(filepath.FromSlash(rel)) != "" {
		return fmt.Errorf("updater path не может содержать volume/drive prefix: %q", rel)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("небезопасный updater path: %q", rel)
	}
	lower := strings.ToLower(rel)
	if lower == updaterCoreDir0156 || strings.HasPrefix(lower, updaterCoreDir0156+"/") {
		return fmt.Errorf("updater payload не может изменять control directory: %s", rel)
	}
	return nil
}

func copyUpdaterSource0156(src, dst string, mode os.FileMode) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("source должен быть regular file и не symlink")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := os.Chmod(dst, mode); err != nil {
		_ = os.Remove(dst)
		return err
	}
	syncDirBestEffort0156(filepath.Dir(dst))
	return nil
}

func writeUpdaterBytes0156(dst string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := os.Chmod(dst, mode); err != nil {
		_ = os.Remove(dst)
		return err
	}
	syncDirBestEffort0156(filepath.Dir(dst))
	return nil
}

func verifyUpdaterFile0156(path string, expectedSize int64, expectedSHA string) error {
	sum, size, err := hashFile(path)
	if err != nil {
		return err
	}
	if size != expectedSize || !strings.EqualFold(sum, expectedSHA) {
		return fmt.Errorf("checksum/size mismatch: size=%d/%d sha256=%s/%s", size, expectedSize, sum, strings.ToLower(expectedSHA))
	}
	return nil
}

func updaterBytesMetadata0156(data []byte) (int64, string) {
	sum := sha256.Sum256(data)
	return int64(len(data)), hex.EncodeToString(sum[:])
}

func newUpdaterTransactionID0156() (string, error) {
	var entropy [6]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(entropy[:]), nil
}

func syncDirBestEffort0156(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}

func updaterVersionAtLeast0156(ver string) bool {
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(ver, "v")), ".")
	if len(parts) < 3 {
		return false
	}
	major, e1 := strconv.Atoi(parts[0])
	minor, e2 := strconv.Atoi(parts[1])
	patchText := parts[2]
	if i := strings.IndexByte(patchText, '-'); i >= 0 {
		patchText = patchText[:i]
	}
	patch, e3 := strconv.Atoi(patchText)
	if e1 != nil || e2 != nil || e3 != nil {
		return false
	}
	if major != 0 {
		return major > 0
	}
	if minor != 15 {
		return minor > 15
	}
	return patch >= 6
}
