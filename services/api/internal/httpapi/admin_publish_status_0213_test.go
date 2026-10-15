package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

// Проверяющий компонент сохраняет переход staged -> integrity-passed. Постоянная
// публикация должна ставить в очередь обновлённый статус, а не устаревший снимок staged.
func TestAdminPreparePublishUsesPersistedIntegrityStatus0213(t *testing.T) {
	repo := repository.NewMemoryRepository("http://127.0.0.1")
	store := storage.NewLocalStorage(t.TempDir())
	srv := Server{Repo: repo, Storage: store}
	release, err := repo.CreateVersion("demo-project", "vanilla", "dev", "0.21.5-publish-status")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("integrity-backed release artifact")
	key, size, err := store.Save(release.ProjectID, release.ID, "client/data.jar", strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if _, err := repo.AddFile(model.FileObject{ProjectID: release.ProjectID, VersionID: release.ID, Path: "client/data.jar", URL: key, Size: size, SHA256: hex.EncodeToString(sum[:]), Required: true}); err != nil {
		t.Fatal(err)
	}
	releases, err := repo.ListVersions(release.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	var current model.ReleaseVersion
	for _, candidate := range releases {
		if candidate.ID == release.ID {
			current = candidate
			break
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects/demo-project/versions/"+release.ID+"/publish", nil)
	if _, err := srv.prepareAdminPublish0212(req, current); err == nil {
		t.Fatal("publish must reject a release before explicit signing and integrity validation")
	}
	// Повторите канонический конвейер sign -> stage -> integrity-check
	// до начала административной транзакции публикации.
	manifest := current.Manifest
	manifest.Files = []model.ManifestFile{{Path: "client/data.jar", URL: key, Size: size, SHA256: hex.EncodeToString(sum[:]), Required: true}}
	signed, err := srv.signManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	current, err = repo.UpdateVersionManifest(release.ProjectID, release.ID, signed)
	if err != nil {
		t.Fatal(err)
	}
	current, err = repo.UpdateVersionStatus(release.ProjectID, release.ID, "staged")
	if err != nil {
		t.Fatal(err)
	}
	files, err := repo.ListFiles(release.ProjectID, release.ID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := srv.runPackageIntegrityCheck0212(req, packageLookup{Release: current, Files: files})
	if err != nil || result.Result != "passed" {
		t.Fatalf("explicit integrity validation must pass: result=%+v err=%v", result, err)
	}
	versionsAfter, err := repo.ListVersions(release.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, updated := range versionsAfter {
		if updated.ID == release.ID {
			current = updated
			break
		}
	}
	lookup, err := srv.prepareAdminPublish0212(req, current)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.Release.Status != "integrity-passed" {
		t.Fatalf("publish CAS received stale status %q; want integrity-passed", lookup.Release.Status)
	}
	versions, err := repo.ListVersions(release.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, updated := range versions {
		if updated.ID == release.ID {
			found = true
			if updated.Status != lookup.Release.Status {
				t.Fatalf("persisted status %q disagrees with publish CAS %q", updated.Status, lookup.Release.Status)
			}
		}
	}
	if !found {
		t.Fatal("release missing after prepare")
	}
}
