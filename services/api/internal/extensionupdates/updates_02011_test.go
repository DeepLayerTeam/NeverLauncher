package extensionupdates

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type fakeLifecycle02011 struct{ repo repository.Repository }

func (f *fakeLifecycle02011) Install(ctx context.Context, v model.ExtensionRegistryVersion, s extensionlifecycle.Scope) (model.ExtensionInstall, error) {
	return f.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: v.ExtensionID, Scope: s.Scope, ScopeID: s.ScopeID, DesiredVersion: v.Version, CurrentVersion: v.Version, DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled, PackageIdentity: v.Artifact.PackageIdentity, CurrentPackageIdentity: v.Artifact.PackageIdentity, Source: "test", Operation: "install", ExpectedGeneration: 0})
}
func (f *fakeLifecycle02011) Enable(ctx context.Context, id string, s extensionlifecycle.Scope) (model.ExtensionInstall, error) {
	cur, err := f.repo.GetExtensionInstallState(ctx, id, s.Scope, s.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	return f.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: s.Scope, ScopeID: s.ScopeID, DesiredVersion: cur.CurrentVersion, CurrentVersion: cur.CurrentVersion, DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, PackageIdentity: cur.CurrentPackageIdentity, CurrentPackageIdentity: cur.CurrentPackageIdentity, Source: cur.Source, Operation: "enable", Enabled: true, ExpectedGeneration: cur.Generation})
}
func (f *fakeLifecycle02011) Update(ctx context.Context, v model.ExtensionRegistryVersion, s extensionlifecycle.Scope) (model.ExtensionInstall, error) {
	cur, err := f.repo.GetExtensionInstallState(ctx, v.ExtensionID, s.Scope, s.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	return f.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: v.ExtensionID, Scope: s.Scope, ScopeID: s.ScopeID, DesiredVersion: v.Version, CurrentVersion: v.Version, DesiredState: cur.CurrentState, CurrentState: cur.CurrentState, PackageIdentity: v.Artifact.PackageIdentity, CurrentPackageIdentity: v.Artifact.PackageIdentity, PreviousVersion: cur.CurrentVersion, PreviousPackageIdentity: cur.CurrentPackageIdentity, Source: "test", Operation: "update", Enabled: cur.Enabled, ExpectedGeneration: cur.Generation})
}
func (f *fakeLifecycle02011) Uninstall(ctx context.Context, id string, s extensionlifecycle.Scope) (model.ExtensionInstall, error) {
	cur, err := f.repo.GetExtensionInstallState(ctx, id, s.Scope, s.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	return f.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: s.Scope, ScopeID: s.ScopeID, DesiredVersion: cur.CurrentVersion, CurrentVersion: "", DesiredState: model.ExtensionInstallStateAbsent, CurrentState: model.ExtensionInstallStateAbsent, Source: cur.Source, Operation: "uninstall", ExpectedGeneration: cur.Generation})
}
func (f *fakeLifecycle02011) Rollback(ctx context.Context, id string, s extensionlifecycle.Scope) (model.ExtensionInstall, error) {
	cur, err := f.repo.GetExtensionInstallState(ctx, id, s.Scope, s.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	return f.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: s.Scope, ScopeID: s.ScopeID, DesiredVersion: cur.PreviousVersion, CurrentVersion: cur.PreviousVersion, DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, PackageIdentity: cur.PreviousPackageIdentity, CurrentPackageIdentity: cur.PreviousPackageIdentity, PreviousVersion: cur.CurrentVersion, PreviousPackageIdentity: cur.CurrentPackageIdentity, Source: "rollback:test", Operation: "rollback", Enabled: true, ExpectedGeneration: cur.Generation})
}

type fakeHost02011 struct {
	healthy       bool
	starts, stops int
}

func (h *fakeHost02011) Stop(context.Context, extensionhost.Key) error { h.stops++; return nil }
func (h *fakeHost02011) StartInstallation(context.Context, model.ExtensionInstall) error {
	h.starts++
	return nil
}
func (h *fakeHost02011) Get(k extensionhost.Key) (extensionhost.Status, error) {
	return extensionhost.Status{ExtensionID: k.ExtensionID, Scope: k.Scope, ScopeID: k.ScopeID, State: "running", Healthy: h.healthy}, nil
}

func updateFixture02011(t *testing.T) (*repository.MemoryRepository, model.ExtensionRegistryVersion, model.ExtensionInstall) {
	t.Helper()
	ctx := context.Background()
	r := repository.NewMemoryRepository("http://localhost")
	_, _ = r.SaveExtensionRegistryPublisher(ctx, model.ExtensionRegistryPublisher{ID: "publisher.test", Name: "Publisher", Active: true})
	seed := sha256.Sum256([]byte("update-02011-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	fpRaw := sha256.Sum256(pub)
	fp := "sha256:" + hex.EncodeToString(fpRaw[:])
	_, _ = r.SaveExtensionRegistryPublisherKey(ctx, model.ExtensionRegistryPublisherKey{PublisherID: "publisher.test", Fingerprint: fp, Algorithm: "Ed25519", PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), Active: true})
	old := model.ExtensionManifest{SchemaVersion: "2.0", ID: "update.test", Name: "Update Test", Version: "1.0.0", Publisher: "publisher.test", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/bin/x"}}}
	if _, err := r.SaveExtensionVersion(ctx, old); err != nil {
		t.Fatal(err)
	}
	installed, err := r.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: old.ID, Scope: "global", DesiredVersion: old.Version, CurrentVersion: old.Version, DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, PackageIdentity: "sha256:" + hex.EncodeToString(make([]byte, 32)), CurrentPackageIdentity: "sha256:" + hex.EncodeToString(make([]byte, 32)), Enabled: true, Source: "test", Operation: "install", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256([]byte("update.test@2.0.0"))
	hexsha := hex.EncodeToString(sha[:])
	pubv, err := r.PublishExtensionRegistryVersion(ctx, model.ExtensionRegistryPublication{Manifest: model.ExtensionManifest{SchemaVersion: "2.0", ID: "update.test", Name: "Update Test", Version: "2.0.0", Publisher: "publisher.test", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/bin/x"}}}, PublisherID: "publisher.test", Compatibility: model.ExtensionRegistryCompatibility{MinNeverLauncher: "0.20.0", MaxNeverLauncher: "0.21.99", MinAPI: "3.7", MaxAPI: "3.7"}, Artifact: model.ExtensionRegistryArtifact{PackageIdentity: "sha256:" + hexsha, ExtensionID: "update.test", Version: "2.0.0", SHA256: hexsha, Size: 1, StorageProject: "r", StorageVersion: "v", StoragePath: "x", SignatureKeyFingerprint: fp}, Channels: []string{"stable"}})
	if err != nil {
		t.Fatal(err)
	}
	return r, pubv, installed
}

func TestAutomaticRollbackOnHealthFailure02011(t *testing.T) {
	r, target, installed := updateFixture02011(t)
	life := &fakeLifecycle02011{repo: r}
	host := &fakeHost02011{healthy: false}
	m := &Manager{Repo: r, Lifecycle: life, Host: host, Config: Config{HealthTimeout: 40 * time.Millisecond, LeaseTTL: time.Minute}}
	plan := model.ExtensionUpdatePlan{Scope: "global", LauncherVersion: "0.20.11", APIVersion: "3.7", OS: "linux", Architecture: "amd64", DefaultChannel: "stable", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", FromVersion: "1.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "update", Channel: "stable"}}}
	tx, err := m.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("health failure did not fail transaction")
	}
	if tx.Status != "rolled_back" {
		t.Fatalf("status=%s failure=%s", tx.Status, tx.Failure)
	}
	cur, err := r.GetExtensionInstallState(context.Background(), "update.test", "global", "")
	if err != nil {
		t.Fatal(err)
	}
	if cur.CurrentVersion != installed.CurrentVersion {
		t.Fatalf("rollback version=%s want=%s", cur.CurrentVersion, installed.CurrentVersion)
	}
	if len(tx.Applied) != 1 || len(tx.RolledBack) != 1 {
		t.Fatalf("transaction journal=%+v", tx)
	}
	if host.stops < 2 || host.starts < 2 {
		t.Fatalf("host compensation not exercised: starts=%d stops=%d", host.starts, host.stops)
	}
}

func TestUpdateLeasePreventsConcurrentTransaction02011(t *testing.T) {
	r, target, _ := updateFixture02011(t)
	owner := "0123456789abcdef0123456789abcdef"
	ok, err := r.AcquireExtensionUpdateLease(context.Background(), "global", "", owner, time.Minute)
	if err != nil || !ok {
		t.Fatalf("lease setup ok=%v err=%v", ok, err)
	}
	m := &Manager{Repo: r, Lifecycle: &fakeLifecycle02011{repo: r}, Host: &fakeHost02011{healthy: true}, Config: Config{LeaseTTL: time.Minute}}
	plan := model.ExtensionUpdatePlan{Scope: "global", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", FromVersion: "1.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "update", Channel: "stable"}}}
	_, err = m.Apply(context.Background(), plan)
	if err == nil || !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("expected lease conflict, got %v", err)
	}
}

func TestInterruptedInFlightTransactionRecoveredBeforeNewApply02011(t *testing.T) {
	ctx := context.Background()
	r, target, _ := updateFixture02011(t)
	life := &fakeLifecycle02011{repo: r}
	if _, err := life.Update(ctx, target, extensionlifecycle.Scope{Scope: "global"}); err != nil {
		t.Fatal(err)
	}
	oldPlan := model.ExtensionUpdatePlan{Scope: "global", LauncherVersion: "0.20.11", APIVersion: "3.7", OS: "linux", Architecture: "amd64", DefaultChannel: "stable", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", FromVersion: "1.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "update", Channel: "stable"}}}
	oldTx := model.ExtensionUpdateTransaction{ID: "extupd-interrupted-02011", Scope: "global", Status: "running", Plan: oldPlan, InFlight: "update.test", StartedAt: time.Now().Add(-time.Minute), LeaseOwner: "expired-owner-02011"}
	if _, err := r.SaveExtensionUpdateTransaction(ctx, oldTx); err != nil {
		t.Fatal(err)
	}

	host := &fakeHost02011{healthy: true}
	m := &Manager{Repo: r, Lifecycle: life, Host: host, Config: Config{HealthTimeout: 50 * time.Millisecond, LeaseTTL: time.Minute}}
	newTx, err := m.Apply(ctx, oldPlan)
	if err != nil {
		t.Fatalf("apply after recovery: %v", err)
	}
	if newTx.Status != "succeeded" {
		t.Fatalf("new transaction status=%s", newTx.Status)
	}
	recovered, err := r.GetExtensionUpdateTransaction(ctx, oldTx.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != "rolled_back" || recovered.InFlight != "" || len(recovered.RolledBack) != 1 || recovered.RolledBack[0] != "update.test" {
		t.Fatalf("interrupted transaction not recovered: %+v", recovered)
	}
	cur, err := r.GetExtensionInstallState(ctx, "update.test", "global", "")
	if err != nil {
		t.Fatal(err)
	}
	if cur.CurrentVersion != "2.0.0" {
		t.Fatalf("new transaction did not apply after recovery: current=%s", cur.CurrentVersion)
	}
}
