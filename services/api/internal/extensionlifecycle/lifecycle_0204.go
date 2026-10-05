package extensionlifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionpackage"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

const operationLockTTL0204 = 4 * time.Hour

type Manager struct {
	Root            string
	BackupRetention int
	Repo            repository.Repository
	Storage         storage.Storage
}

type Scope struct{ Scope, ScopeID string }

type persistentLock0204 struct {
	SchemaVersion          string    `json:"schemaVersion"`
	ExtensionID            string    `json:"extensionId"`
	Scope                  string    `json:"scope"`
	ScopeID                string    `json:"scopeId,omitempty"`
	DesiredVersion         string    `json:"desiredVersion"`
	CurrentVersion         string    `json:"currentVersion,omitempty"`
	DesiredState           string    `json:"desiredState"`
	CurrentState           string    `json:"currentState"`
	PackageIdentity        string    `json:"packageIdentity,omitempty"`
	CurrentPackageIdentity string    `json:"currentPackageIdentity,omitempty"`
	Generation             int64     `json:"generation"`
	Source                 string    `json:"source"`
	UpdatedAt              time.Time `json:"updatedAt"`
}

type operationLock0204 struct {
	Token     string    `json:"token"`
	PID       int       `json:"pid"`
	Operation string    `json:"operation"`
	CreatedAt time.Time `json:"createdAt"`
}

type preparedArtifact0204 struct {
	Path     string
	Verified extensionpackage.VerifiedPackage
}

func New(root string, backupRetention int, repo repository.Repository, store storage.Storage) *Manager {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "./data/extensions"
	}
	if backupRetention < 1 {
		backupRetention = 10
	}
	if backupRetention > 100 {
		backupRetention = 100
	}
	return &Manager{Root: filepath.Clean(root), BackupRetention: backupRetention, Repo: repo, Storage: store}
}

func normalizeScope0204(scope Scope) (Scope, error) {
	scope.Scope = strings.ToLower(strings.TrimSpace(scope.Scope))
	scope.ScopeID = strings.TrimSpace(scope.ScopeID)
	if scope.Scope == "" {
		scope.Scope = "global"
	}
	switch scope.Scope {
	case "global":
		scope.ScopeID = ""
	case "project":
		if scope.ScopeID == "" {
			return Scope{}, errors.New("project scope requires scopeId")
		}
	default:
		return Scope{}, errors.New("scope must be global or project")
	}
	return scope, nil
}

func safeExtensionID0204(id string) (string, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" || len(id) > 128 {
		return "", errors.New("invalid extension id")
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return "", errors.New("invalid extension id")
		}
	}
	return id, nil
}
func scopeDir0204(root string, scope Scope) string {
	if scope.Scope == "global" {
		return filepath.Join(root, "global")
	}
	sum := sha256.Sum256([]byte(scope.ScopeID))
	return filepath.Join(root, "projects", hex.EncodeToString(sum[:16]))
}
func extensionDir0204(root string, scope Scope, id string) string {
	return filepath.Join(scopeDir0204(root, scope), id)
}
func currentDir0204(root string, scope Scope, id string) string {
	return filepath.Join(extensionDir0204(root, scope, id), "current")
}
func backupRoot0204(root string, scope Scope, id string) string {
	return filepath.Join(extensionDir0204(root, scope, id), "backups")
}
func stagingRoot0204(root string, scope Scope, id string) string {
	return filepath.Join(extensionDir0204(root, scope, id), ".staging")
}
func stateLockPath0204(root string, scope Scope, id string) string {
	return filepath.Join(extensionDir0204(root, scope, id), "neverextensions.lock.json")
}
func operationLockPath0204(root string, scope Scope, id string) string {
	return filepath.Join(extensionDir0204(root, scope, id), ".lifecycle.lock")
}

func randomToken0204() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (m *Manager) acquireOperationLock0204(scope Scope, id, op string) (func(), error) {
	dir := extensionDir0204(m.Root, scope, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	p := operationLockPath0204(m.Root, scope, id)
	for attempt := 0; attempt < 2; attempt++ {
		token, err := randomToken0204()
		if err != nil {
			return nil, err
		}
		payload, _ := json.Marshal(operationLock0204{Token: token, PID: os.Getpid(), Operation: op, CreatedAt: time.Now().UTC()})
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if _, werr := f.Write(append(payload, '\n')); werr != nil {
				f.Close()
				_ = os.Remove(p)
				return nil, werr
			}
			if err := f.Sync(); err != nil {
				f.Close()
				_ = os.Remove(p)
				return nil, err
			}
			if err := f.Close(); err != nil {
				_ = os.Remove(p)
				return nil, err
			}
			return func() {
				data, readErr := os.ReadFile(p)
				if readErr == nil && strings.Contains(string(data), token) {
					_ = os.Remove(p)
				}
			}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		data, _ := os.ReadFile(p)
		var stale operationLock0204
		if json.Unmarshal(data, &stale) == nil && !stale.CreatedAt.IsZero() && time.Since(stale.CreatedAt) > operationLockTTL0204 {
			_ = os.Remove(p)
			continue
		}
		return nil, fmt.Errorf("extension lifecycle operation is already locked: %s/%s", scope.Scope, id)
	}
	return nil, errors.New("failed to acquire extension lifecycle lock")
}

func readFileOptional0204(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err
}
func restoreFile0204(path string, data []byte, existed bool) error {
	if !existed {
		return os.Remove(path)
	}
	return atomicWrite0204(path, data, 0o640)
}
func atomicWrite0204(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := syncDir0204(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}
func syncDir0204(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func lockBytes0204(install model.ExtensionInstall) ([]byte, error) {
	v := persistentLock0204{SchemaVersion: "1.0", ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID, DesiredVersion: install.DesiredVersion, CurrentVersion: install.CurrentVersion, DesiredState: install.DesiredState, CurrentState: install.CurrentState, PackageIdentity: install.PackageIdentity, CurrentPackageIdentity: install.CurrentPackageIdentity, Generation: install.Generation, Source: install.Source, UpdatedAt: install.UpdatedAt}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func writePredictedLock0204(path string, tr model.ExtensionLifecycleTransition, generation int64) error {
	now := time.Now().UTC()
	install := model.ExtensionInstall{ExtensionID: tr.ExtensionID, Scope: tr.Scope, ScopeID: tr.ScopeID, DesiredVersion: tr.DesiredVersion, CurrentVersion: tr.CurrentVersion, DesiredState: tr.DesiredState, CurrentState: tr.CurrentState, PackageIdentity: tr.PackageIdentity, CurrentPackageIdentity: tr.CurrentPackageIdentity, Generation: generation, Source: tr.Source, UpdatedAt: now}
	b, err := lockBytes0204(install)
	if err != nil {
		return err
	}
	return atomicWrite0204(path, b, 0o640)
}

func (m *Manager) validateScope0204(scope Scope) error {
	if scope.Scope == "project" {
		if _, err := m.Repo.GetProject(scope.ScopeID); err != nil {
			return fmt.Errorf("project scope not found: %w", err)
		}
	}
	return nil
}
func currentOrAbsent0204(repo repository.Repository, ctx context.Context, id string, scope Scope) (model.ExtensionInstall, error) {
	v, err := repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if errors.Is(err, repository.ErrNotFound) {
		return model.ExtensionInstall{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, DesiredState: model.ExtensionInstallStateAbsent, CurrentState: model.ExtensionInstallStateAbsent, Generation: 0}, nil
	}
	return v, err
}

func publisherKey0204(key model.ExtensionRegistryPublisherKey) (ed25519.PublicKey, error) {
	if !key.Active || key.RevokedAt != nil || key.Algorithm != "Ed25519" {
		return nil, errors.New("publisher key is inactive/revoked")
	}
	raw, err := base64.StdEncoding.DecodeString(key.PublicKeyBase64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("registry contains invalid Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func (m *Manager) prepareArtifact0204(ctx context.Context, item model.ExtensionRegistryVersion) (preparedArtifact0204, error) {
	if item.YankedAt != nil {
		return preparedArtifact0204{}, errors.New("yanked registry version cannot be installed")
	}
	if m.Storage == nil {
		return preparedArtifact0204{}, errors.New("extension lifecycle storage is not configured")
	}
	if err := os.MkdirAll(filepath.Join(m.Root, ".downloads"), 0o750); err != nil {
		return preparedArtifact0204{}, err
	}
	reader, size, err := m.Storage.Open(item.Artifact.StorageProject, item.Artifact.StorageVersion, item.Artifact.StoragePath)
	if err != nil {
		return preparedArtifact0204{}, err
	}
	defer reader.Close()
	if size != item.Artifact.Size {
		return preparedArtifact0204{}, errors.New("registry artifact storage size mismatch")
	}
	tmp, err := os.CreateTemp(filepath.Join(m.Root, ".downloads"), "artifact-*.nlext")
	if err != nil {
		return preparedArtifact0204{}, err
	}
	p := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(p)
		}
	}()
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(reader, item.Artifact.Size+1))
	if err != nil {
		return preparedArtifact0204{}, err
	}
	if written != item.Artifact.Size || hex.EncodeToString(h.Sum(nil)) != item.Artifact.SHA256 {
		return preparedArtifact0204{}, errors.New("registry artifact bytes do not match immutable metadata")
	}
	if err := tmp.Sync(); err != nil {
		return preparedArtifact0204{}, err
	}
	if err := tmp.Close(); err != nil {
		return preparedArtifact0204{}, err
	}
	key, err := m.Repo.GetExtensionRegistryPublisherKey(ctx, item.PublisherID, item.Artifact.SignatureKeyFingerprint)
	if err != nil {
		return preparedArtifact0204{}, err
	}
	pub, err := publisherKey0204(key)
	if err != nil {
		return preparedArtifact0204{}, err
	}
	verified, err := extensionpackage.VerifyFile(p, pub)
	if err != nil {
		return preparedArtifact0204{}, err
	}
	if verified.PackageIdentity != item.Artifact.PackageIdentity || verified.SHA256 != item.Artifact.SHA256 || verified.Manifest.ID != item.ExtensionID || verified.Manifest.Version != item.Version || verified.Manifest.Publisher != item.PublisherID {
		return preparedArtifact0204{}, errors.New("verified artifact identity does not match registry publication")
	}
	ok = true
	return preparedArtifact0204{Path: p, Verified: verified}, nil
}

func makeStage0204(root string, scope Scope, id string) (string, error) {
	dir := stagingRoot0204(root, scope, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	token, err := randomToken0204()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, token)
	if err := os.Mkdir(p, 0o750); err != nil {
		return "", err
	}
	return p, nil
}
func backupName0204(generation int64, version, identity string) string {
	safeV := strings.NewReplacer("/", "_", "\\", "_", "+", "_", ":", "_").Replace(version)
	short := strings.TrimPrefix(identity, "sha256:")
	if len(short) > 12 {
		short = short[:12]
	}
	return fmt.Sprintf("%020d-%s-%s", generation, safeV, short)
}
func pathExists0204(p string) bool { _, err := os.Lstat(p); return err == nil }

func activateStaged0204(current, stage, backup string) (func(), error) {
	hadCurrent := pathExists0204(current)
	if hadCurrent {
		if backup == "" {
			return nil, errors.New("backup path required when replacing activated extension")
		}
		if err := os.MkdirAll(filepath.Dir(backup), 0o750); err != nil {
			return nil, err
		}
		if pathExists0204(backup) {
			return nil, errors.New("extension backup path already exists")
		}
		if err := os.Rename(current, backup); err != nil {
			return nil, err
		}
		_ = syncDir0204(filepath.Dir(current))
		_ = syncDir0204(filepath.Dir(backup))
	}
	if err := os.Rename(stage, current); err != nil {
		if hadCurrent {
			_ = os.Rename(backup, current)
		}
		return nil, err
	}
	_ = syncDir0204(filepath.Dir(current))
	return func() {
		_ = os.RemoveAll(current)
		if hadCurrent {
			_ = os.Rename(backup, current)
		}
	}, nil
}
func deactivateCurrent0204(current, backup string) (func(), error) {
	if !pathExists0204(current) {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0o750); err != nil {
		return nil, err
	}
	if pathExists0204(backup) {
		return nil, errors.New("extension backup path already exists")
	}
	if err := os.Rename(current, backup); err != nil {
		return nil, err
	}
	_ = syncDir0204(filepath.Dir(current))
	_ = syncDir0204(filepath.Dir(backup))
	return func() {
		_ = os.Rename(backup, current)
		_ = syncDir0204(filepath.Dir(current))
		_ = syncDir0204(filepath.Dir(backup))
	}, nil
}

func copyTree0204(src, dst string) error {
	if err := os.Mkdir(dst, 0o750); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink found in lifecycle backup")
		}
		if d.IsDir() {
			return os.Mkdir(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return errors.New("special file found in lifecycle backup")
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, cpErr := io.Copy(out, in)
		syncErr := out.Sync()
		closeErr := out.Close()
		if cpErr != nil {
			return cpErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
}

func (m *Manager) commitWithLockfile0204(ctx context.Context, before model.ExtensionInstall, tr model.ExtensionLifecycleTransition, rollbackFS func()) (model.ExtensionInstall, error) {
	lockPath := stateLockPath0204(m.Root, Scope{Scope: tr.Scope, ScopeID: tr.ScopeID}, tr.ExtensionID)
	oldBytes, oldExists, err := readFileOptional0204(lockPath)
	if err != nil {
		rollbackFS()
		return model.ExtensionInstall{}, err
	}
	if err := writePredictedLock0204(lockPath, tr, before.Generation+1); err != nil {
		rollbackFS()
		_ = restoreFile0204(lockPath, oldBytes, oldExists)
		return model.ExtensionInstall{}, err
	}
	next, err := m.Repo.TransitionExtensionInstall(ctx, tr)
	if err != nil {
		rollbackFS()
		_ = restoreFile0204(lockPath, oldBytes, oldExists)
		return model.ExtensionInstall{}, err
	}
	actualBytes, err := lockBytes0204(next)
	if err != nil {
		return next, err
	}
	if err := atomicWrite0204(lockPath, actualBytes, 0o640); err != nil {
		return next, fmt.Errorf("lifecycle committed but lockfile refresh failed: %w", err)
	}
	m.pruneBackups0204(Scope{Scope: tr.Scope, ScopeID: tr.ScopeID}, tr.ExtensionID)
	return next, nil
}

func (m *Manager) Install(ctx context.Context, item model.ExtensionRegistryVersion, scope Scope) (model.ExtensionInstall, error) {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	if err := m.validateScope0204(scope); err != nil {
		return model.ExtensionInstall{}, err
	}
	id, err := safeExtensionID0204(item.ExtensionID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	release, err := m.acquireOperationLock0204(scope, id, "install")
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer release()
	before, err := currentOrAbsent0204(m.Repo, ctx, id, scope)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	if before.CurrentState != model.ExtensionInstallStateAbsent {
		return model.ExtensionInstall{}, fmt.Errorf("extension %s is already installed; use update", id)
	}
	prepared, err := m.prepareArtifact0204(ctx, item)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer os.Remove(prepared.Path)
	if _, err := m.Repo.SaveExtensionVersion(ctx, item.Manifest); err != nil {
		return model.ExtensionInstall{}, err
	}
	stage, err := makeStage0204(m.Root, scope, id)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer os.RemoveAll(stage)
	if _, err := extensionpackage.ExtractPayloadFile(prepared.Path, stage, item.Artifact.PackageIdentity); err != nil {
		return model.ExtensionInstall{}, err
	}
	current := currentDir0204(m.Root, scope, id)
	if pathExists0204(current) {
		return model.ExtensionInstall{}, errors.New("activated extension directory exists while persistent state is absent")
	}
	rollbackFS, err := activateStaged0204(current, stage, "")
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	now := time.Now().UTC()
	tr := model.ExtensionLifecycleTransition{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, DesiredVersion: item.Version, CurrentVersion: item.Version, DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled, PackageIdentity: item.Artifact.PackageIdentity, CurrentPackageIdentity: item.Artifact.PackageIdentity, PreviousVersion: before.CurrentVersion, PreviousPackageIdentity: before.CurrentPackageIdentity, Enabled: false, Source: "registry:" + item.PublisherID + "/" + id + "@" + item.Version + "#" + item.Artifact.PackageIdentity, Operation: "install", ExpectedGeneration: before.Generation, ActivatedAt: &now}
	return m.commitWithLockfile0204(ctx, before, tr, rollbackFS)
}

func (m *Manager) Update(ctx context.Context, item model.ExtensionRegistryVersion, scope Scope) (model.ExtensionInstall, error) {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	if err := m.validateScope0204(scope); err != nil {
		return model.ExtensionInstall{}, err
	}
	id, err := safeExtensionID0204(item.ExtensionID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	release, err := m.acquireOperationLock0204(scope, id, "update")
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer release()
	before, err := m.Repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	if before.CurrentState == model.ExtensionInstallStateAbsent {
		return model.ExtensionInstall{}, errors.New("extension is not activated; use install")
	}
	if before.CurrentVersion == item.Version && before.CurrentPackageIdentity == item.Artifact.PackageIdentity {
		return before, nil
	}
	prepared, err := m.prepareArtifact0204(ctx, item)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer os.Remove(prepared.Path)
	if _, err := m.Repo.SaveExtensionVersion(ctx, item.Manifest); err != nil {
		return model.ExtensionInstall{}, err
	}
	stage, err := makeStage0204(m.Root, scope, id)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer os.RemoveAll(stage)
	if _, err := extensionpackage.ExtractPayloadFile(prepared.Path, stage, item.Artifact.PackageIdentity); err != nil {
		return model.ExtensionInstall{}, err
	}
	backup := filepath.Join(backupRoot0204(m.Root, scope, id), backupName0204(before.Generation+1, before.CurrentVersion, before.CurrentPackageIdentity))
	rollbackFS, err := activateStaged0204(currentDir0204(m.Root, scope, id), stage, backup)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	state := before.CurrentState
	if state != model.ExtensionInstallStateEnabled {
		state = model.ExtensionInstallStateDisabled
	}
	now := time.Now().UTC()
	tr := model.ExtensionLifecycleTransition{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, DesiredVersion: item.Version, CurrentVersion: item.Version, DesiredState: state, CurrentState: state, PackageIdentity: item.Artifact.PackageIdentity, CurrentPackageIdentity: item.Artifact.PackageIdentity, PreviousVersion: before.CurrentVersion, PreviousPackageIdentity: before.CurrentPackageIdentity, Enabled: state == model.ExtensionInstallStateEnabled, Source: "registry:" + item.PublisherID + "/" + id + "@" + item.Version + "#" + item.Artifact.PackageIdentity, Operation: "update", BackupPath: backup, ExpectedGeneration: before.Generation, ActivatedAt: &now}
	return m.commitWithLockfile0204(ctx, before, tr, rollbackFS)
}

func (m *Manager) setEnabled0204(ctx context.Context, id string, scope Scope, enabled bool) (model.ExtensionInstall, error) {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	id, err = safeExtensionID0204(id)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	op := "disable"
	state := model.ExtensionInstallStateDisabled
	if enabled {
		op = "enable"
		state = model.ExtensionInstallStateEnabled
	}
	release, err := m.acquireOperationLock0204(scope, id, op)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer release()
	before, err := m.Repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	if before.CurrentState == model.ExtensionInstallStateAbsent {
		return model.ExtensionInstall{}, errors.New("extension is not installed")
	}
	if before.CurrentState == state {
		return before, nil
	}
	tr := model.ExtensionLifecycleTransition{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, DesiredVersion: before.CurrentVersion, CurrentVersion: before.CurrentVersion, DesiredState: state, CurrentState: state, PackageIdentity: before.CurrentPackageIdentity, CurrentPackageIdentity: before.CurrentPackageIdentity, PreviousVersion: before.PreviousVersion, PreviousPackageIdentity: before.PreviousPackageIdentity, Enabled: enabled, Source: before.Source, Operation: op, ExpectedGeneration: before.Generation, ActivatedAt: before.ActivatedAt}
	return m.commitWithLockfile0204(ctx, before, tr, func() {})
}
func (m *Manager) Enable(ctx context.Context, id string, scope Scope) (model.ExtensionInstall, error) {
	return m.setEnabled0204(ctx, id, scope, true)
}
func (m *Manager) Disable(ctx context.Context, id string, scope Scope) (model.ExtensionInstall, error) {
	return m.setEnabled0204(ctx, id, scope, false)
}

func (m *Manager) Uninstall(ctx context.Context, id string, scope Scope) (model.ExtensionInstall, error) {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	id, err = safeExtensionID0204(id)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	release, err := m.acquireOperationLock0204(scope, id, "uninstall")
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer release()
	before, err := m.Repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	if before.CurrentState == model.ExtensionInstallStateAbsent {
		return before, nil
	}
	backup := filepath.Join(backupRoot0204(m.Root, scope, id), backupName0204(before.Generation+1, before.CurrentVersion, before.CurrentPackageIdentity))
	rollbackFS, err := deactivateCurrent0204(currentDir0204(m.Root, scope, id), backup)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	desiredVersion := before.CurrentVersion
	if desiredVersion == "" {
		desiredVersion = before.DesiredVersion
	}
	tr := model.ExtensionLifecycleTransition{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, DesiredVersion: desiredVersion, CurrentVersion: "", DesiredState: model.ExtensionInstallStateAbsent, CurrentState: model.ExtensionInstallStateAbsent, PackageIdentity: before.CurrentPackageIdentity, CurrentPackageIdentity: "", PreviousVersion: before.CurrentVersion, PreviousPackageIdentity: before.CurrentPackageIdentity, Enabled: false, Source: before.Source, Operation: "uninstall", BackupPath: backup, ExpectedGeneration: before.Generation}
	return m.commitWithLockfile0204(ctx, before, tr, rollbackFS)
}

func (m *Manager) Rollback(ctx context.Context, id string, scope Scope) (model.ExtensionInstall, error) {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	id, err = safeExtensionID0204(id)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	release, err := m.acquireOperationLock0204(scope, id, "rollback")
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer release()
	before, err := m.Repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	revs, err := m.Repo.ListExtensionInstallRevisions(ctx, id, scope.Scope, scope.ScopeID, 100)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	var target *model.ExtensionInstallRevision
	for i := range revs {
		rev := &revs[i]
		if rev.BackupPath != "" && rev.FromVersion != "" && pathExists0204(rev.BackupPath) {
			target = rev
			break
		}
	}
	if target == nil {
		return model.ExtensionInstall{}, errors.New("no restorable extension backup is available")
	}
	stage, err := makeStage0204(m.Root, scope, id)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer os.RemoveAll(stage)
	if err := os.Remove(stage); err != nil {
		return model.ExtensionInstall{}, err
	}
	if err := copyTree0204(target.BackupPath, stage); err != nil {
		return model.ExtensionInstall{}, err
	}
	current := currentDir0204(m.Root, scope, id)
	newBackup := ""
	if pathExists0204(current) && before.CurrentVersion != "" {
		newBackup = filepath.Join(backupRoot0204(m.Root, scope, id), backupName0204(before.Generation+1, before.CurrentVersion, before.CurrentPackageIdentity))
	}
	rollbackFS, err := activateStaged0204(current, stage, newBackup)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	state := target.FromState
	if state != model.ExtensionInstallStateEnabled {
		state = model.ExtensionInstallStateDisabled
	}
	now := time.Now().UTC()
	tr := model.ExtensionLifecycleTransition{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, DesiredVersion: target.FromVersion, CurrentVersion: target.FromVersion, DesiredState: state, CurrentState: state, PackageIdentity: target.FromPackageIdentity, CurrentPackageIdentity: target.FromPackageIdentity, PreviousVersion: before.CurrentVersion, PreviousPackageIdentity: before.CurrentPackageIdentity, Enabled: state == model.ExtensionInstallStateEnabled, Source: "rollback:revision:" + fmt.Sprint(target.ID), Operation: "rollback", BackupPath: newBackup, ExpectedGeneration: before.Generation, ActivatedAt: &now}
	return m.commitWithLockfile0204(ctx, before, tr, rollbackFS)
}

func (m *Manager) pruneBackups0204(scope Scope, id string) {
	root := backupRoot0204(m.Root, scope, id)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	dirs := make([]fs.DirEntry, 0)
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() > dirs[j].Name() })
	if len(dirs) <= m.BackupRetention {
		return
	}
	for _, e := range dirs[m.BackupRetention:] {
		_ = os.RemoveAll(filepath.Join(root, e.Name()))
	}
}

func (m *Manager) VerifyLockfile(ctx context.Context, id string, scope Scope) error {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return err
	}
	id, err = safeExtensionID0204(id)
	if err != nil {
		return err
	}
	state, err := m.Repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(stateLockPath0204(m.Root, scope, id))
	if err != nil {
		return err
	}
	var lock persistentLock0204
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	if lock.ExtensionID != state.ExtensionID || lock.Scope != state.Scope || lock.ScopeID != state.ScopeID || lock.DesiredVersion != state.DesiredVersion || lock.CurrentVersion != state.CurrentVersion || lock.DesiredState != state.DesiredState || lock.CurrentState != state.CurrentState || lock.PackageIdentity != state.PackageIdentity || lock.CurrentPackageIdentity != state.CurrentPackageIdentity || lock.Generation != state.Generation {
		return errors.New("persistent extension lockfile does not match repository state")
	}
	if state.CurrentState != model.ExtensionInstallStateAbsent && !pathExists0204(currentDir0204(m.Root, scope, id)) {
		return errors.New("repository says extension is active but current payload directory is missing")
	}
	return nil
}

// CurrentPayloadDir returns the canonical activated payload directory for one
// persisted extension installation. Extension Host uses this instead of
// reconstructing lifecycle paths independently.
func CurrentPayloadDir(root, scope, scopeID, extensionID string) (string, error) {
	s, err := normalizeScope0204(Scope{Scope: scope, ScopeID: scopeID})
	if err != nil {
		return "", err
	}
	id, err := safeExtensionID0204(extensionID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(root) == "" {
		root = "./data/extensions"
	}
	return currentDir0204(filepath.Clean(root), s, id), nil
}
