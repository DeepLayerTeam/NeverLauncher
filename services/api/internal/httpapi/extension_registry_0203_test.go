package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func registryHTTPServer0203(t *testing.T) (http.Handler, *repository.MemoryRepository, storage.Storage) {
	t.Helper()
	cfg := config.Config{PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), Environment: "dev", AuthTokenSecret: "registry-http-test-secret", AuthTokenTTLHours: 1, ManifestSigningPrivateKey: p1TestSigningSeed}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	store := storage.NewLocalStorage(cfg.StorageLocalPath)
	handler := Server{Version: "0.20.3", Config: cfg, Repo: repo, Storage: store, State: NewRuntimeState()}.Handler()
	return handler, repo, store
}

func TestNeverExtensionsRegistryHTTP0203(t *testing.T) {
	h, _, _ := registryHTTPServer0203(t)
	token := extensionAdminToken0201(t, h)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/extension-registry/publishers", strings.NewReader(`{"id":"deeplayer.team","name":"DeepLayer Team"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), `"deeplayer.team"`) {
		t.Fatalf("publisher: %d %s", res.Code, res.Body.String())
	}

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBody, _ := json.Marshal(map[string]any{"publicKeyBase64": base64.StdEncoding.EncodeToString(public)})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/extension-registry/publishers/deeplayer.team/keys", bytes.NewReader(keyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), `"algorithm":"Ed25519"`) {
		t.Fatalf("key: %d %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/extension-registry/extensions?q=missing&launcherVersion=0.20.3&os=linux&arch=amd64", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"count":0`) {
		t.Fatalf("search: %d %s", res.Code, res.Body.String())
	}
}

func TestNeverExtensionsRegistryInstallRejectsUnverifiedStorage0203(t *testing.T) {
	h, repo, store := registryHTTPServer0203(t)
	token := extensionAdminToken0201(t, h)
	ctx := context.Background()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(public)
	fingerprint := "sha256:" + hex.EncodeToString(keyDigest[:])
	if _, err := repo.SaveExtensionRegistryPublisher(ctx, model.ExtensionRegistryPublisher{ID: "deeplayer.team", Name: "DeepLayer Team", Active: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveExtensionRegistryPublisherKey(ctx, model.ExtensionRegistryPublisherKey{PublisherID: "deeplayer.team", PublicKeyBase64: base64.StdEncoding.EncodeToString(public), Active: true}); err != nil {
		t.Fatal(err)
	}

	badBytes := []byte("not a signed nlext")
	badDigest := sha256.Sum256(badBytes)
	sha := hex.EncodeToString(badDigest[:])
	storageProject, storageVersion, storagePath := "neverextensions-registry", "example.registry-extension-1.0.0", sha+".nlext"
	if _, _, err := store.Save(storageProject, storageVersion, storagePath, bytes.NewReader(badBytes)); err != nil {
		t.Fatal(err)
	}
	publication := model.ExtensionRegistryPublication{
		Manifest:    model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.registry-extension", Name: "Registry Extension", Version: "1.0.0", Publisher: "deeplayer.team", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}},
		PublisherID: "deeplayer.team",
		Artifact:    model.ExtensionRegistryArtifact{PackageIdentity: "sha256:" + sha, ExtensionID: "example.registry-extension", Version: "1.0.0", SHA256: sha, Size: int64(len(badBytes)), StorageProject: storageProject, StorageVersion: storageVersion, StoragePath: storagePath, SignatureKeyFingerprint: fingerprint},
		Channels:    []string{"stable"},
	}
	if _, err := repo.PublishExtensionRegistryVersion(ctx, publication); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/extension-registry/extensions/example.registry-extension/versions/1.0.0/install", strings.NewReader(`{"scope":"global"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "artifact verification failed") {
		t.Fatalf("install must fail closed: %d %s", res.Code, res.Body.String())
	}
	installs, err := repo.ListExtensionInstalls(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, install := range installs {
		if install.ExtensionID == "example.registry-extension" {
			t.Fatalf("unverified artifact created install: %+v", install)
		}
	}
}
