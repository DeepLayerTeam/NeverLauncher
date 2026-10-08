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
			t.Errorf("unexpected Range header: %q", got)
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
		t.Fatalf("expected verified resume, got %+v", result)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("final payload mismatch: %q / %v", got, err)
	}
	if _, err := os.Stat(dest + ".nlpart"); !os.IsNotExist(err) {
		t.Fatalf("partial file survived publish: %v", err)
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
		t.Fatalf("corrupt cache was not quarantined: %+v", result)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("replacement mismatch: %q / %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".neverlauncher", "quarantine"))
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
		t.Fatal("quarantine does not contain broken artifact")
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
			http.Error(w, "вышестоящий проект недоступный", http.StatusServiceUnavailable)
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
		t.Fatalf("initial upstream fetch failed/recovered unexpectedly: %+v / %v", first, err)
	}
	manifestUp.Store(false)
	second, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "1.20.4")
	if err != nil || !second.Recovered || string(second.Bytes) != string(versionBytes) {
		t.Fatalf("exact-version recovery failed: %+v / %v", second, err)
	}
	if _, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "latest-release"); err == nil {
		t.Fatal("latest-release unexpectedly recovered from stale metadata cache")
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
		t.Fatalf("Range-ignore response must restart from zero: resumed=%v status=%d", resumed, resp.StatusCode)
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
			t.Fatalf("corrupt completed partial must restart from zero, got Range=%q", got)
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
		t.Fatalf("expected one clean restart, got result=%+v requests=%d", result, requests.Load())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("repaired payload mismatch: %q / %v", got, err)
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
		t.Fatalf("initial cache population failed: %v", err)
	}
	serveVersion.Store(false)
	if _, err := resolveVanillaMetadataWithRecovery(context.Background(), server.Client(), root, server.URL+"/manifest.json", "1.20.4"); err == nil {
		t.Fatal("authoritative manifest removal unexpectedly resurrected stale cached version")
	}
}
