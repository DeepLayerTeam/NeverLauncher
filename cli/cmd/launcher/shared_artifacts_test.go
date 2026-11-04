package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func nativeArchiveFixture0277(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for name, value := range files {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestSharedAssets0277EndToEndAndNativeMultiTarget(t *testing.T) {
	asset := []byte("same asset across all profiles")
	lib := []byte("shared maven byte content")
	native := nativeArchiveFixture0277(t, map[string]string{"shared.dll": "native binary"})
	clientJar := []byte("client executable")
	assetIndex, _ := json.Marshal(map[string]any{"objects": map[string]any{"asset.txt": map[string]any{"hash": sha1hex(asset), "size": len(asset)}}})
	const libPath = "/maven/example/shared/1.0/shared-1.0.jar"
	const nativePath = "/maven/example/natives/1.0/natives-1.0-natives-windows.jar"
	var blockArtifacts atomic.Bool
	var libraryRequests, nativeRequests, assetRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		metadata, _ := json.Marshal(map[string]any{
			"id": "fixture-1", "type": "release", "mainClass": "com.example.Main", "assets": "index1",
			"assetIndex":  map[string]any{"id": "index1", "url": base + "/index", "sha1": sha1hex(assetIndex), "size": len(assetIndex)},
			"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
			"javaVersion": map[string]any{"majorVersion": 21}, "arguments": map[string]any{"game": []any{"--version", "fixture-1"}, "jvm": []any{"-cp", "${classpath}"}},
			"libraries": []any{
				map[string]any{"name": "example:shared:1.0", "downloads": map[string]any{"artifact": map[string]any{"path": "example/shared/1.0/shared-1.0.jar", "url": base + libPath, "sha1": sha1hex(lib), "size": len(lib)}}},
				map[string]any{"name": "example:natives:1.0", "natives": map[string]string{"windows": "natives-windows"}, "downloads": map[string]any{"classifiers": map[string]any{"natives-windows": map[string]any{"path": "example/natives/1.0/natives-1.0-natives-windows.jar", "url": base + nativePath, "sha1": sha1hex(native), "size": len(native)}}}},
			},
		})
		switch r.URL.Path {
		case "/manifest":
			_ = json.NewEncoder(w).Encode(MojangVersionManifest{Latest: map[string]string{"release": "fixture-1"}, Versions: []MojangManifestVersion{{ID: "fixture-1", Type: "release", URL: base + "/metadata", SHA1: sha1hex(metadata)}}})
		case "/metadata":
			_, _ = w.Write(metadata)
		case "/index":
			_, _ = w.Write(assetIndex)
		case "/client.jar":
			_, _ = w.Write(clientJar)
		case libPath:
			libraryRequests.Add(1)
			if blockArtifacts.Load() {
				http.Error(w, "blocked", 500)
				return
			}
			_, _ = w.Write(lib)
		case nativePath:
			nativeRequests.Add(1)
			if blockArtifacts.Load() {
				http.Error(w, "blocked", 500)
				return
			}
			_, _ = w.Write(native)
		case "/assets/" + sha1hex(asset)[:2] + "/" + sha1hex(asset):
			assetRequests.Add(1)
			if blockArtifacts.Load() {
				http.Error(w, "blocked", 500)
				return
			}
			_, _ = w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base := t.TempDir()
	cache := filepath.Join(base, "shared-cas")
	install := func(name string) vanillaInstallResult {
		t.Helper()
		result, err := installVanilla(context.Background(), vanillaInstallOptions{MinecraftVersion: "fixture-1", ClientDir: filepath.Join(base, name), VersionManifest: server.URL + "/manifest", AssetBaseURL: server.URL + "/assets", Targets: []vanillaTarget{{OS: "windows", Arch: "x86"}, {OS: "windows", Arch: "x86_64"}}, Workers: 4, StrictUpstream: true, SharedCacheDir: cache, HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		for _, arch := range []string{"x86", "x86_64"} {
			output := filepath.Join(base, name, "natives", "windows", arch, "shared.dll")
			content, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != "native binary" {
				t.Fatalf("wrong native for %s", arch)
			}
		}
		return result
	}
	first := install("one")
	if len(first.Files) < 7 {
		t.Fatalf("missing installed files: %+v", first.Files)
	}
	if libraryRequests.Load() != 1 || nativeRequests.Load() != 1 || assetRequests.Load() != 1 {
		t.Fatalf("first install requests unexpected: lib=%d native=%d assets=%d", libraryRequests.Load(), nativeRequests.Load(), assetRequests.Load())
	}
	blockArtifacts.Store(true)
	second := install("two")
	if second.SharedCacheHits < 3 {
		t.Fatalf("expected shared cache hits, got %d", second.SharedCacheHits)
	}
	if libraryRequests.Load() != 1 || nativeRequests.Load() != 1 || assetRequests.Load() != 1 {
		t.Fatal("shared cache missed and contacted offline artifact endpoint")
	}
	for _, f := range second.Files {
		if (f.Kind == "library" || f.Kind == "native-archive" || f.Kind == "asset") && !f.Cached {
			t.Fatalf("uncached shared artifact %s", f.Path)
		}
	}
	// Materialized bytes are independent; changing a client must not mutate the CAS.
	mutated := filepath.Join(base, "two", "libraries", "example", "shared", "1.0", "shared-1.0.jar")
	if err := os.WriteFile(mutated, []byte("tampered client"), 0644); err != nil {
		t.Fatal(err)
	}
	_, sumSize, err := func() (string, int64, error) {
		sum, size, err := hashFile(filepath.Join(base, "one", "libraries", "example", "shared", "1.0", "shared-1.0.jar"))
		return sum, size, err
	}()
	if err != nil || sumSize != int64(len(lib)) {
		t.Fatal("client files share mutable inode")
	}
	_ = install("three")
	// A forged cache entry must not be silently downloaded around or accepted.
	cachePath := filepath.Join(cache, "sha1", sha1hex(lib)[:2], sha1hex(lib))
	if err := os.WriteFile(cachePath, []byte("wrong bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = installVanilla(context.Background(), vanillaInstallOptions{MinecraftVersion: "fixture-1", ClientDir: filepath.Join(base, "four"), VersionManifest: server.URL + "/manifest", AssetBaseURL: server.URL + "/assets", Workers: 2, StrictUpstream: true, SharedCacheDir: cache, HTTPClient: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "cache") {
		t.Fatalf("corrupt cache accepted: %v", err)
	}
}

func TestSharedArtifacts0277ConcurrentAndUnsafeRoots(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	src := filepath.Join(root, "src.jar")
	data := []byte("same object")
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, err := sharedArtifactsContext0277(context.Background(), cache, filepath.Join(root, "client"))
	if err != nil {
		t.Fatal(err)
	}
	cas := sharedArtifactsFromContext0277(ctx)
	sum := sha256.Sum256(data)
	for i := 0; i < 8; i++ { // independent writers must verify the same stored content
		if err := cas.store(ctx, src, sha1hex(data), hex.EncodeToString(sum[:]), int64(len(data))); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, fmt.Sprintf("target-%d", i))
		hit, sha, size, err := cas.restore(ctx, target, sha1hex(data), int64(len(data)))
		if err != nil || !hit || sha != hex.EncodeToString(sum[:]) || size != int64(len(data)) {
			t.Fatalf("restoration failed: %v", err)
		}
	}
	if _, err := sharedArtifactsContext0277(ctx, filepath.Join(root, "client", "nested"), filepath.Join(root, "client")); err == nil {
		t.Fatal("shared cache in client directory accepted")
	}
	if _, err := sharedArtifactsContext0277(ctx, filepath.Join(root, "nested"), root); err == nil {
		t.Fatal("client in shared cache directory accepted")
	}
}

func TestNativeExtraction0277RejectsConflictingOutputs(t *testing.T) {
	root := t.TempDir()
	a := nativeArchiveFixture0277(t, map[string]string{"lib.dll": "correct"})
	b := nativeArchiveFixture0277(t, map[string]string{"lib.dll": "malicious"})
	for i, data := range [][]byte{a, b} {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%d.jar", i)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dest := filepath.Join(root, "natives")
	if _, err := extractNativeJar(filepath.Join(root, "0.jar"), dest, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := extractNativeJar(filepath.Join(root, "1.jar"), dest, nil); err == nil {
		t.Fatal("conflicting native overwritten")
	}
	got, err := os.ReadFile(filepath.Join(dest, "lib.dll"))
	if err != nil || string(got) != "correct" {
		t.Fatal("native file corrupted after conflict")
	}
}
func TestNativeClassifier0277UnknownArchitectureFailClosed(t *testing.T) {
	targets := []vanillaTarget{{OS: "linux", Arch: "x86_64"}, {OS: "linux", Arch: "aarch64"}, {OS: "windows", Arch: "x86"}, {OS: "osx", Arch: "aarch64"}}
	for _, target := range targets {
		if libraryArtifactAppliesToTarget("example:artifact:1.0:natives-linux-unknown", target) {
			t.Fatalf("unknown native accepted: %+v", target)
		}
	}
	if !libraryArtifactAppliesToTarget("org.lwjgl:lwjgl:3.3.3:natives-macos-arm64", vanillaTarget{OS: "osx", Arch: "aarch64"}) {
		t.Fatal("macos arm64 native not selected")
	}
	if !libraryArtifactAppliesToTarget("org.example:legacy:1:natives-windows", vanillaTarget{OS: "windows", Arch: "x86"}) {
		t.Fatal("legacy x86 target excluded")
	}
	if libraryArtifactAppliesToTarget("org.lwjgl:lwjgl:3.3.3:natives-windows-arm64", vanillaTarget{OS: "windows", Arch: "x86_64"}) {
		t.Fatal("arm64 native installed on x64")
	}
}

func TestVanillaLibraries0277ConflictPerTarget(t *testing.T) {
	libs := []MojangLibrary{{Name: "com.example:engine:1.0"}, {Name: "com.example:engine:2.0"}}
	if err := validateVanillaLibraryConflicts0277(libs, []vanillaTarget{{OS: "linux", Arch: "x86_64"}}); err == nil {
		t.Fatal("conflicting classpath revisions accepted")
	}
	libs[1].Rules = []map[string]any{{"action": "allow", "os": map[string]any{"name": "windows"}}}
	if err := validateVanillaLibraryConflicts0277(libs, []vanillaTarget{{OS: "linux", Arch: "x86_64"}}); err != nil {
		t.Fatal(err)
	}
	// Native classifiers are separate artifacts; they are not a classpath conflict.
	libs = append(libs[:1], MojangLibrary{Name: "com.example:engine:2.0:natives-linux-arm64"})
	if err := validateVanillaLibraryConflicts0277(libs, []vanillaTarget{{OS: "linux", Arch: "x86_64"}, {OS: "linux", Arch: "aarch64"}}); err != nil {
		t.Fatal(err)
	}
}
