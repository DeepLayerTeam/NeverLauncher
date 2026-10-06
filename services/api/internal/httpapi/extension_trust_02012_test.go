package httpapi

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

func addRecoveryPublisher02012(t *testing.T, repo repository.Repository, id string) model.ExtensionRegistryPublisherKey {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.SaveExtensionRegistryPublisher(ctx, model.ExtensionRegistryPublisher{ID: id, Name: "Recovery Publisher", Active: true}); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	key, err := repo.SaveExtensionRegistryPublisherKey(ctx, model.ExtensionRegistryPublisherKey{PublisherID: id, Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), Algorithm: "Ed25519", PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), Active: true})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestExtensionRecoveryExportImportPreservesFailClosedTrust02012(t *testing.T) {
	ctx := context.Background()
	source := repository.NewMemoryRepository("http://source.test")
	key := addRecoveryPublisher02012(t, source, "recovery.publisher")
	if _, err := source.RevokeExtensionRegistryPublisherKey(ctx, key.PublisherID, key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := source.SaveExtensionTrustPolicy(ctx, model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeStrict, AllowedPublishers: []string{"recovery.publisher"}}); err != nil {
		t.Fatal(err)
	}
	identity := "sha256:" + strings.Repeat("a", 64)
	if _, err := source.SaveExtensionQuarantine(ctx, model.ExtensionQuarantineEntry{ID: "q-recovery", PackageIdentity: identity, ArtifactSHA256: strings.Repeat("b", 64), ExtensionID: "example.recovery", Version: "1.0.0", PublisherID: key.PublisherID, KeyFingerprint: key.Fingerprint, Reason: "revoked signing key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: "example.recovery", Scope: "global", Reason: "incident", Source: "test"}); err != nil {
		t.Fatal(err)
	}

	sourceServer := Server{Repo: source}
	state, err := sourceServer.buildExtensionRecoveryExport02012(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Quarantine) != 1 || len(state.EmergencyDisables) != 1 || len(state.PublisherKeys) != 1 {
		t.Fatalf("incomplete recovery export: %+v", state)
	}

	target := repository.NewMemoryRepository("http://target.test")
	targetServer := Server{Repo: target}
	counts, err := targetServer.importExtensionRecoveryState02012(ctx, state, false)
	if err != nil {
		t.Fatal(err)
	}
	if counts["quarantine"] != 1 || counts["emergencyDisables"] != 1 || counts["keys"] != 1 {
		t.Fatalf("unexpected import counts: %+v", counts)
	}
	restoredKey, err := target.GetExtensionRegistryPublisherKey(ctx, key.PublisherID, key.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if restoredKey.Active || restoredKey.RevokedAt == nil {
		t.Fatalf("revoked key was not restored fail-closed: %+v", restoredKey)
	}
	if quarantined, err := target.IsExtensionPackageQuarantined(ctx, identity); err != nil || !quarantined {
		t.Fatalf("quarantine not restored: quarantined=%v err=%v", quarantined, err)
	}
	if _, err := target.GetExtensionEmergencyDisable(ctx, "example.recovery", "global", ""); err != nil {
		t.Fatalf("kill-switch not restored: %v", err)
	}
	policy, err := target.GetExtensionTrustPolicy(ctx)
	if err != nil || policy.Mode != model.ExtensionTrustModeStrict || len(policy.AllowedPublishers) != 1 {
		t.Fatalf("trust policy not restored: %+v err=%v", policy, err)
	}
}

func TestRecoveryImportIsIdempotentForActiveQuarantine02012(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://example.test")
	entry := model.ExtensionQuarantineEntry{ID: "q-idempotent", PackageIdentity: "sha256:" + strings.Repeat("c", 64), ArtifactSHA256: strings.Repeat("d", 64), Reason: "malicious artifact", Active: true}
	state := model.ExtensionRecoveryExport{SchemaVersion: "1.0", TrustPolicy: model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeStrict}, Quarantine: []model.ExtensionQuarantineEntry{entry}}
	s := Server{Repo: repo}
	if _, err := s.importExtensionRecoveryState02012(ctx, state, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.importExtensionRecoveryState02012(ctx, state, false); err != nil {
		t.Fatalf("second recovery import must be idempotent: %v", err)
	}
	items, err := repo.ListExtensionQuarantine(ctx, true)
	if err != nil || len(items) != 1 {
		t.Fatalf("idempotent quarantine restore produced duplicates: len=%d err=%v", len(items), err)
	}
}
