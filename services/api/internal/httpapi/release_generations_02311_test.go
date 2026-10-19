package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestServerGenerationsAndAuthorizedGameRollback02311(t *testing.T) {
	repo := repository.NewMemoryRepository("http://127.0.0.1")
	srv := Server{Repo: repo}
	old, err := repo.CreateVersion("demo-project", "vanilla", "stable", "v-old")
	if err != nil {
		t.Fatal(err)
	}
	old.Manifest.GameReleaseGeneration = 5
	old.Manifest.Files = []model.ManifestFile{{Path: "mods/old.jar", Size: 7, SHA256: strings.Repeat("a", 64), Required: true}}
	old, err = repo.UpdateVersionManifest(old.ProjectID, old.ID, old.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	old, err = repo.UpdateVersionStatus(old.ProjectID, old.ID, "published")
	if err != nil {
		t.Fatal(err)
	}
	next, err := srv.nextGameReleaseGeneration02311(old.ProjectID, old.ProfileID, old.Channel, "")
	if err != nil || next != 6 {
		t.Fatalf("next=%d err=%v", next, err)
	}
	candidate, err := repo.CreateVersion(old.ProjectID, old.ProfileID, old.Channel, "v-rollback")
	if err != nil {
		t.Fatal(err)
	}
	candidate.Manifest.GameReleaseGeneration = next
	sourceDigest, err := manifestDigest0212(old.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Manifest.RollbackSource = &model.GameRollbackSource02311{Version: old.Version, GameReleaseGeneration: old.Manifest.GameReleaseGeneration, ManifestSHA256: sourceDigest}
	candidate.Manifest.Files = append([]model.ManifestFile(nil), old.Manifest.Files...)
	if err := srv.checkGameReleasePublishGeneration02311(candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Manifest.GameReleaseGeneration = 5
	if err := srv.checkGameReleasePublishGeneration02311(candidate); err == nil {
		t.Fatal("stale generation accepted")
	}
	candidate.Manifest.GameReleaseGeneration = next
	candidate.Manifest.Files[0].SHA256 = strings.Repeat("b", 64)
	if err := srv.checkGameReleasePublishGeneration02311(candidate); err == nil {
		t.Fatal("fake rollback content accepted")
	}
	candidate.Manifest.Files[0].SHA256 = strings.Repeat("a", 64)
	candidate.Manifest.RollbackSource.ManifestSHA256 = strings.Repeat("c", 64)
	if err := srv.checkGameReleasePublishGeneration02311(candidate); err == nil {
		t.Fatal("wrong rollback source digest accepted")
	}
	candidate.Manifest.RollbackSource = nil
	candidate.Manifest.GameReleaseGeneration = 0
	if err := srv.checkGameReleasePublishGeneration02311(candidate); err == nil {
		t.Fatal("legacy downgrade after protected generation accepted")
	}
}
