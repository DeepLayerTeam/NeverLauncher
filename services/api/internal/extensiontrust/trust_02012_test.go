package extensiontrust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func trustFixture02012(t *testing.T) (*repository.MemoryRepository, model.ExtensionRegistryVersion, model.ExtensionRegistryPublisherKey) {
	t.Helper()
	repo := repository.NewMemoryRepository("http://example.test")
	ctx := context.Background()
	publisher := model.ExtensionRegistryPublisher{ID: "trusted.publisher", Name: "Trusted Publisher", Active: true}
	if _, err := repo.SaveExtensionRegistryPublisher(ctx, publisher); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(public)
	key := model.ExtensionRegistryPublisherKey{PublisherID: publisher.ID, Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), Algorithm: "Ed25519", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), Active: true}
	key, err = repo.SaveExtensionRegistryPublisherKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	item := model.ExtensionRegistryVersion{ExtensionID: "example.trusted", Version: "1.0.0", PublisherID: publisher.ID, Artifact: model.ExtensionRegistryArtifact{PackageIdentity: "sha256:" + strings.Repeat("a", 64), SHA256: strings.Repeat("b", 64), SignatureKeyFingerprint: key.Fingerprint}}
	return repo, item, key
}

func TestTrustStrictAllowListAndAuditMode02012(t *testing.T) {
	repo, item, _ := trustFixture02012(t)
	ctx := context.Background()
	if _, err := repo.SaveExtensionTrustPolicy(ctx, model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeStrict, AllowedPublishers: []string{"other.publisher"}}); err != nil {
		t.Fatal(err)
	}
	decision, err := EvaluatePublication(ctx, repo, item)
	if err == nil || decision.Allowed {
		t.Fatalf("strict policy accepted non-allowlisted publisher: decision=%+v err=%v", decision, err)
	}
	if _, err := repo.SaveExtensionTrustPolicy(ctx, model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeAudit, AllowedPublishers: []string{"other.publisher"}}); err != nil {
		t.Fatal(err)
	}
	decision, err = EvaluatePublication(ctx, repo, item)
	if err != nil || !decision.Allowed || len(decision.Violations) == 0 {
		t.Fatalf("audit policy should allow with violation: decision=%+v err=%v", decision, err)
	}
}

func TestRevokedKeyAndQuarantineAlwaysFailClosed02012(t *testing.T) {
	repo, item, key := trustFixture02012(t)
	ctx := context.Background()
	if _, err := repo.RevokeExtensionRegistryPublisherKey(ctx, key.PublisherID, key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if decision, err := EvaluatePublication(ctx, repo, item); err == nil || decision.Allowed {
		t.Fatalf("revoked key accepted: decision=%+v err=%v", decision, err)
	}

	repo, item, _ = trustFixture02012(t)
	if _, err := repo.SaveExtensionQuarantine(ctx, model.ExtensionQuarantineEntry{ID: "q-test", PackageIdentity: item.Artifact.PackageIdentity, ArtifactSHA256: item.Artifact.SHA256, ExtensionID: item.ExtensionID, Version: item.Version, PublisherID: item.PublisherID, KeyFingerprint: item.Artifact.SignatureKeyFingerprint, Reason: "malicious test artifact"}); err != nil {
		t.Fatal(err)
	}
	if decision, err := EvaluatePublication(ctx, repo, item); err == nil || decision.Allowed {
		t.Fatalf("quarantined artifact accepted: decision=%+v err=%v", decision, err)
	}
}

func TestRevokedPublisherKeyCannotBeReactivated02012(t *testing.T) {
	repo, _, key := trustFixture02012(t)
	ctx := context.Background()
	if _, err := repo.RevokeExtensionRegistryPublisherKey(ctx, key.PublisherID, key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	key.Active = true
	if _, err := repo.SaveExtensionRegistryPublisherKey(ctx, key); err == nil {
		t.Fatal("revoked publisher key was reactivated")
	}
}
