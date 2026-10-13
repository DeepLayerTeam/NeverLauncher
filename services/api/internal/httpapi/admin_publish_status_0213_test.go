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

// The integrity validator persists a transition from staged to integrity-passed.
// Durable publish must enqueue that updated status, not the stale staged snapshot.
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
