package httpapi

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const p1TestSigningSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestPublishSignedPublishesVerifiedManifestAtomically(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	_, err := repo.CreateVersion("demo-project", "vanilla", "stable", "0.10.2-test")
	if err != nil {
		t.Fatal(err)
	}
	releaseID := "demo-project-vanilla-0.10.2-test"
	_, err = repo.AddFile(model.FileObject{
		ID:        "fixture",
		ProjectID: "demo-project",
		VersionID: releaseID,
		Path:      "libraries/fixture.jar",
		Size:      7,
		SHA256:    "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
		URL:       "http://example.test/api/v1/files/demo-project/0.10.2-test/libraries/fixture.jar",
		Required:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := Server{Config: config.Config{Environment: "production", ManifestSigningPrivateKey: p1TestSigningSeed}, Repo: repo, State: NewRuntimeState()}
	published, err := s.publishSigned("demo-project", "vanilla", "stable", "0.10.2-test")
	if err != nil {
		t.Fatal(err)
	}
	if published.Status != "published" || published.Manifest.Signature == nil {
		t.Fatalf("published release must contain signature: %#v", published)
	}
	if len(published.Manifest.Files) != 1 || published.Manifest.Files[0].Path != "libraries/fixture.jar" {
		t.Fatalf("published manifest must contain final file list: %#v", published.Manifest.Files)
	}

	signature := published.Manifest.Signature
	publicKey, err := hex.DecodeString(signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(signature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := published.Manifest
	unsigned.Signature = nil
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, sig) {
		t.Fatal("published manifest signature is invalid")
	}
}

func TestPublishSignedDoesNotPublishWhenSigningFails(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	_, err := repo.CreateVersion("demo-project", "vanilla", "stable", "0.10.2-invalid-signing")
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Config: config.Config{Environment: "production", ManifestSigningPrivateKey: "not-a-key"}, Repo: repo, State: NewRuntimeState()}
	if _, err = s.publishSigned("demo-project", "vanilla", "stable", "0.10.2-invalid-signing"); err == nil {
		t.Fatal("publish must fail when signing key is invalid")
	}
	versions, err := repo.ListVersions("demo-project")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range versions {
		if item.Version == "0.10.2-invalid-signing" {
			if item.Status != "draft" || item.Manifest.Signature != nil {
				t.Fatalf("failed signing must leave release draft and unsigned: %#v", item)
			}
			return
		}
	}
	t.Fatal("draft release not found")
}
