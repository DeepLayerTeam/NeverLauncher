package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the actual installer and ZIP extractor, not just a
// version list or a manifest. The artifacts are served by a local HTTP CDN.
func TestVanilla0402NativeDuplicateIsPublishedOnce(t *testing.T) {
	install, root := vanilla0402Fixture(t, vanillaTarget{OS: "linux", Arch: "x86_64"}, []nativeFixture0402{
		{"org.example:one:1.0", "lib/one.jar", "libshared.so", "same-bytes"},
		{"org.example:two:1.0", "lib/two.jar", "libshared.so", "same-bytes"},
	})
	if install.Status != "installed-and-verified" {
		t.Fatalf("unexpected install result: %+v", install)
	}
	nativePath := "natives/linux/x86_64/libshared.so"
	count := 0
	for _, f := range install.Files {
		if f.Path == nativePath {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("same native path reported %d times; want exactly once", count)
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(nativePath)))
	if err != nil || string(b) != "same-bytes" {
		t.Fatalf("native not installed: %q, %v", b, err)
	}
}

func TestVanilla0402MacOSArm64NativesAreLoadableFromRoot(t *testing.T) {
	install, root := vanilla0402Fixture(t, vanillaTarget{OS: "osx", Arch: "aarch64"}, []nativeFixture0402{
		{"org.lwjgl:lwjgl-glfw:3.3.4:natives-macos-arm64", "org/lwjgl/lwjgl-glfw/3.3.4/lwjgl-glfw-3.3.4-natives-macos-arm64.jar", "macos/arm64/org/lwjgl/libglfw.dylib", "real-dylib-bytes"},
	})
	if install.Status != "installed-and-verified" {
		t.Fatal(install.Status)
	}
	alias := "natives/osx/aarch64/libglfw.dylib"
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(alias)))
	if err != nil || string(b) != "real-dylib-bytes" {
		t.Fatalf("macOS java.library.path alias missing: %q %v", b, err)
	}
	found := false
	for _, file := range install.Files {
		if file.Path == alias && file.Size == int64(len(b)) && len(file.SHA256) == 64 {
			found = true
		}
	}
	if !found {
		t.Fatalf("native alias missing from verified file list: %s", alias)
	}
	// Repeat the extraction from the already verified files: a second
	// identical signed archive must reuse the same alias, not overwrite it.
	nativeRoot := filepath.Join(root, "natives", "osx", "aarch64")
	aliasPaths, err := flattenLWJGLMacOSNatives(nativeRoot,
		[]string{"macos/arm64/org/lwjgl/libglfw.dylib"}, "aarch64")
	if err != nil || len(aliasPaths) != 1 || aliasPaths[0] != "libglfw.dylib" {
		t.Fatalf("identical LWJGL native alias rejected: %v %v", aliasPaths, err)
	}
}

func TestVanilla0402MacOSRejectsCrossArchitectureAndCollisions(t *testing.T) {
	root := t.TempDir()
	wrong := filepath.Join(root, "macos", "x64", "org", "lwjgl")
	if err := os.MkdirAll(wrong, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrong, "libtest.dylib"), []byte("x64-only"), 0644); err != nil {
		t.Fatal(err)
	}
	aliases, err := flattenLWJGLMacOSNatives(root, []string{"macos/x64/org/lwjgl/libtest.dylib"}, "aarch64")
	if err != nil || len(aliases) != 0 {
		t.Fatalf("Apple Silicon inherited x64 native: %v %v", aliases, err)
	}
	if _, err := os.Stat(filepath.Join(root, "libtest.dylib")); !os.IsNotExist(err) {
		t.Fatalf("cross-architecture alias created: %v", err)
	}
	if _, err := flattenLWJGLMacOSNatives(root, nil, "arm"); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
	nested := filepath.Join(root, "macos", "arm64", "org", "lwjgl")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "libtest.dylib"), []byte("arm64"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "libtest.dylib"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := flattenLWJGLMacOSNatives(root, []string{"macos/arm64/org/lwjgl/libtest.dylib"}, "aarch64"); err == nil {
		t.Fatal("collision accepted")
	}
	actual, err := os.ReadFile(filepath.Join(root, "libtest.dylib"))
	if err != nil || string(actual) != "old" {
		t.Fatalf("collision overwrote existing library: %q %v", actual, err)
	}
}

func TestVanilla0402VerifiedResourceCopy(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "asset"), filepath.Join(root, "resources", "data")
	if err := os.WriteFile(src, []byte("untampered"), 0644); err != nil {
		t.Fatal(err)
	}
	sha := sha1hex([]byte("untampered"))
	if err := copyFileVerified(src, dst, int64(len("untampered")), sha); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("corrupted!"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyFileVerified(src, dst, int64(len("untampered")), sha); err == nil {
		t.Fatal("changed asset accepted")
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != "untampered" {
		t.Fatalf("previous verified asset replaced on failure: %q %v", b, err)
	}
}

type nativeFixture0402 struct{ name, path, native, payload string }

func vanilla0402Fixture(t *testing.T, target vanillaTarget, nativeFixtures []nativeFixture0402) (vanillaInstallResult, string) {
	t.Helper()
	data := map[string][]byte{}
	asset := []byte("{}")
	data["/assets/"+sha1hex(asset)[:2]+"/"+sha1hex(asset)] = asset
	idx, err := json.Marshal(map[string]any{"objects": map[string]any{"minecraft/test.json": map[string]any{"hash": sha1hex(asset), "size": len(asset)}}})
	if err != nil {
		t.Fatal(err)
	}
	data["/assets/index.json"] = idx
	client := []byte("client-jar-test-bytes")
	data["/client.jar"] = client
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	libs := make([]any, 0, len(nativeFixtures))
	for i, fi := range nativeFixtures {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		entry, e := zw.Create(fi.native)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := entry.Write([]byte(fi.payload)); e != nil {
			t.Fatal(e)
		}
		if e := zw.Close(); e != nil {
			t.Fatal(e)
		}
		jarPath := fmt.Sprintf("/lib-%d.jar", i)
		data[jarPath] = buf.Bytes()
		classifier := "natives-" + target.OS
		if strings.Contains(fi.name, ":natives-") {
			classifier = ""
		}
		if classifier == "" {
			libs = append(libs, map[string]any{"name": fi.name, "downloads": map[string]any{"artifact": map[string]any{"path": fi.path, "url": server.URL + jarPath, "sha1": sha1hex(buf.Bytes()), "size": buf.Len()}}})
		} else {
			libs = append(libs, map[string]any{"name": fi.name, "natives": map[string]any{target.OS: classifier}, "downloads": map[string]any{"classifiers": map[string]any{classifier: map[string]any{"path": fi.path, "url": server.URL + jarPath, "sha1": sha1hex(buf.Bytes()), "size": buf.Len()}}}})
		}
	}
	ver, err := json.Marshal(map[string]any{
		"id": "fixture-0402", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"assetIndex":  map[string]any{"id": "test-assets", "url": server.URL + "/assets/index.json", "sha1": sha1hex(idx), "size": len(idx)},
		"downloads":   map[string]any{"client": map[string]any{"url": server.URL + "/client.jar", "sha1": sha1hex(client), "size": len(client)}},
		"javaVersion": map[string]any{"majorVersion": 21},
		"arguments":   map[string]any{"game": []string{"--username", "${auth_player_name}"}, "jvm": []string{"-cp", "${classpath}"}},
		"libraries":   libs,
	})
	if err != nil {
		t.Fatal(err)
	}
	data["/version.json"] = ver
	manifest, err := json.Marshal(MojangVersionManifest{Latest: map[string]string{"release": "fixture-0402"}, Versions: []MojangManifestVersion{{ID: "fixture-0402", Type: "release", URL: server.URL + "/version.json", SHA1: sha1hex(ver)}}})
	if err != nil {
		t.Fatal(err)
	}
	data["/manifest.json"] = manifest
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if v, ok := data[r.URL.Path]; ok {
			_, _ = w.Write(v)
			return
		}
		http.NotFound(w, r)
	})
	root := t.TempDir()
	got, err := installVanilla(context.Background(), vanillaInstallOptions{MinecraftVersion: "fixture-0402", ClientDir: root, VersionManifest: server.URL + "/manifest.json", AssetBaseURL: server.URL + "/assets", Targets: []vanillaTarget{target}, Workers: 3, StrictUpstream: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return got, root
}
