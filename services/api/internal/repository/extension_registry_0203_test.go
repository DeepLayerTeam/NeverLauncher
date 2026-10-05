package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func registryTestManifest0203(version string) model.ExtensionManifest {
	return model.ExtensionManifest{
		SchemaVersion: "2.0",
		ID:            "example.registry-extension",
		Name:          "Registry Extension",
		Version:       version,
		Publisher:     "deeplayer.team",
		Description:   "Production registry test extension",
		API:           "1.0",
		Targets:       []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}},
		Permissions:   []string{"project:read"},
	}
}

func registryTestPublication0203(t *testing.T, version string, fingerprint string, marker byte, channels ...string) model.ExtensionRegistryPublication {
	t.Helper()
	sum := sha256.Sum256([]byte{marker})
	sha := hex.EncodeToString(sum[:])
	return model.ExtensionRegistryPublication{
		Manifest:    registryTestManifest0203(version),
		PublisherID: "deeplayer.team",
		Compatibility: model.ExtensionRegistryCompatibility{
			MinNeverLauncher:       "0.20.0",
			MaxNeverLauncher:       "0.20.9",
			SupportedOS:            []string{"linux"},
			SupportedArchitectures: []string{"amd64"},
		},
		Artifact: model.ExtensionRegistryArtifact{
			PackageIdentity:         "sha256:" + sha,
			ExtensionID:             "example.registry-extension",
			Version:                 version,
			SHA256:                  sha,
			Size:                    int64(100 + marker),
			StorageProject:          "neverextensions-registry",
			StorageVersion:          "example.registry-extension-" + version,
			StoragePath:             sha + ".nlext",
			SignatureKeyFingerprint: fingerprint,
		},
		Channels: channels,
	}
}

func TestExtensionRegistryMemoryProductionLifecycle0203(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository("http://localhost")
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(public)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])

	untrusted := registryTestPublication0203(t, "1.0.0", fingerprint, 1, "stable")
	if _, err := repo.PublishExtensionRegistryVersion(ctx, untrusted); !errors.Is(err, ErrConflict) {
		t.Fatalf("untrusted publish error = %v, want ErrConflict", err)
	}
	if _, err := repo.GetExtensionVersion(ctx, untrusted.Manifest.ID, untrusted.Manifest.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("untrusted publish leaked canonical version: %v", err)
	}

	if _, err := repo.SaveExtensionRegistryPublisher(ctx, model.ExtensionRegistryPublisher{ID: "deeplayer.team", Name: "DeepLayer Team", Active: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveExtensionRegistryPublisherKey(ctx, model.ExtensionRegistryPublisherKey{PublisherID: "deeplayer.team", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), Active: true}); err != nil {
		t.Fatal(err)
	}

	v1, err := repo.PublishExtensionRegistryVersion(ctx, untrusted)
	if err != nil {
		t.Fatal(err)
	}
	if len(v1.Channels) != 1 || v1.Channels[0] != "stable" {
		t.Fatalf("v1 channels=%v", v1.Channels)
	}

	compatible, err := repo.SearchExtensionRegistry(ctx, model.ExtensionRegistrySearch{Channel: "stable", LauncherVersion: "0.20.3", OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(compatible) != 1 || compatible[0].Version != "1.0.0" {
		t.Fatalf("compatible search=%+v", compatible)
	}
	incompatible, err := repo.SearchExtensionRegistry(ctx, model.ExtensionRegistrySearch{LauncherVersion: "0.21.0", OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(incompatible) != 0 {
		t.Fatalf("incompatible search returned %d items", len(incompatible))
	}

	v2pub := registryTestPublication0203(t, "1.1.0", fingerprint, 2, "beta")
	if _, err := repo.PublishExtensionRegistryVersion(ctx, v2pub); err != nil {
		t.Fatal(err)
	}
	moved, err := repo.SetExtensionRegistryChannel(ctx, v2pub.Manifest.ID, "stable", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !containsRegistryChannel0203(moved.Channels, "stable") {
		t.Fatalf("stable was not moved: %v", moved.Channels)
	}
	old, err := repo.GetExtensionRegistryVersion(ctx, v2pub.Manifest.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if containsRegistryChannel0203(old.Channels, "stable") {
		t.Fatalf("stable remained on old version: %v", old.Channels)
	}

	mutated := v2pub
	mutated.Compatibility.MaxNeverLauncher = "0.20.8"
	if _, err := repo.PublishExtensionRegistryVersion(ctx, mutated); !errors.Is(err, ErrImmutable) {
		t.Fatalf("compatibility mutation error=%v, want ErrImmutable", err)
	}

	yanked, err := repo.YankExtensionRegistryVersion(ctx, v2pub.Manifest.ID, "1.1.0", "security regression")
	if err != nil {
		t.Fatal(err)
	}
	if yanked.YankedAt == nil || len(yanked.Channels) != 0 {
		t.Fatalf("invalid yank state: %+v", yanked)
	}
	visible, err := repo.SearchExtensionRegistry(ctx, model.ExtensionRegistrySearch{Query: "registry-extension"})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range visible {
		if item.Version == "1.1.0" {
			t.Fatalf("yanked version present in default search")
		}
	}
	all, err := repo.SearchExtensionRegistry(ctx, model.ExtensionRegistrySearch{Query: "registry-extension", IncludeYanked: true})
	if err != nil {
		t.Fatal(err)
	}
	foundYanked := false
	for _, item := range all {
		if item.Version == "1.1.0" && item.YankedAt != nil {
			foundYanked = true
		}
	}
	if !foundYanked {
		t.Fatalf("includeYanked did not return yanked version")
	}
	if _, err := repo.SetExtensionRegistryChannel(ctx, v2pub.Manifest.ID, "stable", "1.1.0"); !errors.Is(err, ErrConflict) {
		t.Fatalf("channel to yanked version error=%v, want ErrConflict", err)
	}
	if _, err := repo.YankExtensionRegistryVersion(ctx, v2pub.Manifest.ID, "1.1.0", "different reason"); !errors.Is(err, ErrImmutable) {
		t.Fatalf("yank mutation error=%v, want ErrImmutable", err)
	}
}
