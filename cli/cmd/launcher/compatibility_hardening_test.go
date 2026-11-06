package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDownloadVanillaArtifactResumesVerifiedPartial(t *testing.T) {
	payload := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	root := t.TempDir()
	rel := "libraries/example/test.jar"
	dest := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	prefix := payload[:11]
	if err := os.WriteFile(dest+".nlpart", prefix, 0o644); err != nil {
		t.Fatal(err)
	}
	var ranged atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != fmt.Sprintf("bytes=%d-", len(prefix)) {
			t.Errorf("Неожиданный заголовок Range: %q", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ranged.Store(true)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(prefix), len(payload)-1, len(payload)))
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)-len(prefix)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[len(prefix):])
	}))
	defer server.Close()

	result, err := downloadVanillaArtifact(context.Background(), server.Client(), vanillaDownloadTask{
		Path: rel, URL: server.URL + "/artifact.jar", SHA1: sha1hex(payload), Size: int64(len(payload)), Kind: "library",
	}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !ranged.Load() || !result.Resumed || result.Cached {
		t.Fatalf("Ожидалось проверенное возобновление загрузки, получено %+v", result)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("Несоответствие итогового содержимого: %q / %v", got, err)
	}
	if _, err := os.Stat(dest + ".nlpart"); !os.IsNotExist(err) {
		t.Fatalf("После публикации остался частично загруженный файл: %v", err)
	}
}

func TestDownloadVanillaArtifactQuarantinesCorruptCache(t *testing.T) {
	payload := []byte("verified-upstream-artifact")
	root := t.TempDir()
	rel := "versions/1.0/1.0.jar"
	dest := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("corrupt-cache"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	result, err := downloadVanillaArtifact(context.Background(), server.Client(), vanillaDownloadTask{
		Path: rel, URL: server.URL + "/client.jar", SHA1: sha1hex(payload), Size: int64(len(payload)), Kind: "client",
	}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Quarantined {
		t.Fatalf("Повреждённый кеш не помещён в карантин: %+v", result)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("Несоответствие при замене: %q / %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".launcher", "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".broken") {
			found = true
		}
	}
	if !found {
		t.Fatal("В карантине отсутствует повреждённый артефакт")
	}
}

func TestVanillaMetadataRecoveryExactVersionOnly(t *testing.T) {
	versionDoc := map[string]any{
		"id": "1.20.4", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads": map[string]any{},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest: map[string]string{"release": "1.20.4", "snapshot": "1.20.4"},
		Versions: []MojangManifestVersion{{
			ID: "1.20.4", Type: "release", SHA1: sha1hex(versionBytes),
		}},
	}
	var manifestUp atomic.Bool
	manifestUp.Store(true)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !manifestUp.Load() {
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/manifest.json":
			manifest.Versions[0].URL = server.URL + "/version.json"
			raw, _ := json.Marshal(manifest)
			_, _ = w.Write(raw)
		case "/version.json":
			_, _ = w.Write(versionBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	first, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "1.20.4")
	if err != nil || first.Recovered {
		t.Fatalf("Первоначальная загрузка из источника неожиданно завершилась сбоем или восстановлением: %+v / %v", first, err)
	}
	manifestUp.Store(false)
	second, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "1.20.4")
	if err != nil || !second.Recovered || string(second.Bytes) != string(versionBytes) {
		t.Fatalf("Не удалось восстановить точную версию: %+v / %v", second, err)
	}
	if _, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "latest-release"); err == nil {
		t.Fatal("Последний релиз неожиданно получен из устаревшего кеша метаданных")
	}
}

func TestFetchVanillaArtifactResponseRestartsWhenRangeIgnored(t *testing.T) {
	payload := []byte("full-body")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, string(payload))
	}))
	defer server.Close()
	resp, resumed, err := fetchVanillaArtifactResponse(context.Background(), server.Client(), vanillaDownloadTask{URL: server.URL, Size: int64(len(payload))}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resumed || resp.StatusCode != http.StatusOK {
		t.Fatalf("При игнорировании Range загрузка должна начинаться заново: возобновление=%v, статус=%d", resumed, resp.StatusCode)
	}
}

func TestDownloadVanillaArtifactRepairsCorruptCompletedPartialInSameRun(t *testing.T) {
	payload := []byte("authoritative-artifact")
	root := t.TempDir()
	rel := "libraries/example/recovered.jar"
	dest := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(strings.Repeat("x", len(payload)))
	if err := os.WriteFile(dest+".nlpart", corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("Range"); got != "" {
			t.Fatalf("Повреждённая завершённая частичная загрузка должна начинаться заново, получен Range=%q", got)
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	result, err := downloadVanillaArtifact(context.Background(), server.Client(), vanillaDownloadTask{
		Path: rel, URL: server.URL + "/artifact.jar", SHA1: sha1hex(payload), Size: int64(len(payload)), Kind: "library",
	}, root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Resumed || requests.Load() != 1 {
		t.Fatalf("Ожидался один запуск с чистого состояния, получено: результат=%+v запросов=%d", result, requests.Load())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("Несоответствие восстановленного содержимого: %q / %v", got, err)
	}
}

func TestVanillaMetadataRecoveryDoesNotResurrectMissingAuthoritativeVersion(t *testing.T) {
	versionDoc := map[string]any{
		"id": "1.20.4", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads": map[string]any{},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{Versions: []MojangManifestVersion{{ID: "1.20.4", Type: "release", SHA1: sha1hex(versionBytes)}}}
	var serveVersion atomic.Bool
	serveVersion.Store(true)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			current := manifest
			if !serveVersion.Load() {
				current.Versions = nil
			} else {
				current.Versions[0].URL = server.URL + "/version.json"
			}
			raw, _ := json.Marshal(current)
			_, _ = w.Write(raw)
		case "/version.json":
			_, _ = w.Write(versionBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	if _, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "1.20.4"); err != nil {
		t.Fatalf("Не удалось первоначально заполнить кеш: %v", err)
	}
	serveVersion.Store(false)
	if _, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "1.20.4"); err == nil {
		t.Fatal("После удаления версии из официального манифеста восстановилась устаревшая версия из кеша")
	}
}
