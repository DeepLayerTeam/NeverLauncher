package repository

import (
	"errors"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestPublishedReleaseImmutableAtRepositoryLayer(t *testing.T) {
	repo := NewMemoryRepository("https://launcher.example")
	release, err := repo.CreateVersion("demo-project", "vanilla", "stable", "immutable-repo-v4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.AddFile(model.FileObject{ProjectID: "demo-project", VersionID: release.ID, Path: "mods/a.jar", Size: 1, SHA256: "00", Required: true}); err != nil {
		t.Fatal(err)
	}
	release, err = repo.PublishVersionWithManifest("demo-project", "vanilla", "stable", "immutable-repo-v4", release.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if release.Status != "published" {
		t.Fatalf("status=%s", release.Status)
	}
	if _, err = repo.UpdateVersionStatus("demo-project", release.ID, "draft"); !errors.Is(err, ErrImmutable) {
		t.Fatalf("status mutation err=%v", err)
	}
	if _, err = repo.UpdateVersionManifest("demo-project", release.ID, release.Manifest); !errors.Is(err, ErrImmutable) {
		t.Fatalf("manifest mutation err=%v", err)
	}
	if _, err = repo.AddFile(model.FileObject{ProjectID: "demo-project", VersionID: release.ID, Path: "mods/b.jar", Size: 1, SHA256: "11", Required: true}); !errors.Is(err, ErrImmutable) {
		t.Fatalf("file mutation err=%v", err)
	}
	if _, err = repo.PublishVersionWithManifest("demo-project", "vanilla", "stable", "immutable-repo-v4", release.Manifest); !errors.Is(err, ErrImmutable) {
		t.Fatalf("republish err=%v", err)
	}
}
