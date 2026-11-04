package extensionlifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type lifecycleTrustPublication0424 struct {
	repository.Repository
	item model.ExtensionRegistryVersion
}

func (r lifecycleTrustPublication0424) GetExtensionRegistryVersion(ctx context.Context, id, version string) (model.ExtensionRegistryVersion, error) {
	if id == r.item.ExtensionID && version == r.item.Version {
		return r.item, nil
	}
	return r.Repository.GetExtensionRegistryVersion(ctx, id, version)
}

func installSignedDisabled0424(t *testing.T, repo repository.Repository, id, publisher, identity string) model.ExtensionInstall {
	t.Helper()
	ctx := context.Background()
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Signed extension", Version: "1.0.0", Publisher: publisher, API: "1.0", Targets: []model.ExtensionTarget{{Kind: "admin", Entrypoint: "admin/index.html"}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	install, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled, PackageIdentity: identity, CurrentPackageIdentity: identity, Source: "registry:" + publisher + "/" + id + "@1.0.0#" + identity, Operation: "install", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	return install
}

func TestEnableDeniesQuarantinedPackage0424(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	id := "example.quarantined"
	identity := "sha256:" + strings.Repeat("a", 64)
	before := installSignedDisabled0424(t, repo, id, "test.publisher", identity)
	if _, err := repo.SaveExtensionQuarantine(ctx, model.ExtensionQuarantineEntry{ID: "q-0424", PackageIdentity: identity, ArtifactSHA256: strings.Repeat("b", 64), ExtensionID: id, Version: "1.0.0", Reason: "incident"}); err != nil {
		t.Fatal(err)
	}
	manager := New(t.TempDir(), 2, repo, nil)
	if _, err := manager.Enable(ctx, id, Scope{Scope: "global"}); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("quarantined package enabled: %v", err)
	}
	after, err := repo.GetExtensionInstallState(ctx, id, "global", "")
	if err != nil || after.Generation != before.Generation || after.CurrentState != model.ExtensionInstallStateDisabled {
		t.Fatalf("rejected enable mutated state: %+v %v", after, err)
	}
}

func TestEnableRechecksRevokedPublisherKey0424(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	const publisher = "test.publisher"
	if _, err := repo.SaveExtensionRegistryPublisher(ctx, model.ExtensionRegistryPublisher{ID: publisher, Name: "Test", Active: true}); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(public)
	fp := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := repo.SaveExtensionRegistryPublisherKey(ctx, model.ExtensionRegistryPublisherKey{PublisherID: publisher, Fingerprint: fp, Algorithm: "Ed25519", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), Active: true}); err != nil {
		t.Fatal(err)
	}
	identity := "sha256:" + strings.Repeat("c", 64)
	before := installSignedDisabled0424(t, repo, "example.revoked", publisher, identity)
	item := model.ExtensionRegistryVersion{ExtensionID: before.ExtensionID, Version: before.CurrentVersion, PublisherID: publisher, Artifact: model.ExtensionRegistryArtifact{PackageIdentity: identity, SignatureKeyFingerprint: fp}}
	manager := New(t.TempDir(), 2, lifecycleTrustPublication0424{Repository: repo, item: item}, nil)
	if err := manager.requireActiveTrust0424(ctx, before); err != nil {
		t.Fatalf("active key rejected: %v", err)
	}
	if _, err := repo.RevokeExtensionRegistryPublisherKey(ctx, publisher, fp); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Enable(ctx, before.ExtensionID, Scope{Scope: "global"}); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked signing key allowed enable: %v", err)
	}
	after, err := repo.GetExtensionInstallState(ctx, before.ExtensionID, "global", "")
	if err != nil || after.Generation != before.Generation || after.CurrentState != model.ExtensionInstallStateDisabled {
		t.Fatalf("key revocation changed install incorrectly: %+v %v", after, err)
	}
}
