package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha1hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func testNativeZip(t *testing.T) []byte {
	t.Helper()
	return testNamedNativeZip(t, "libtest-native.bin", []byte("native-binary"))
}

func testNamedNativeZip(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	meta, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = meta.Write([]byte("Manifest-Version: 1.0\n"))
	native, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = native.Write(payload)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInstallVanillaMaterializesVerifiedClient(t *testing.T) {
	clientJar := []byte("fake-client-jar")
	libraryJar := []byte("fake-library-jar")
	nativeJar := testNativeZip(t)
	legacyNativeJar := testNamedNativeZip(t, "liblegacy-native.bin", []byte("legacy-native-binary"))
	logging := []byte("<Configuration/>")
	asset := []byte("asset-object")
	assetHash := sha1hex(asset)
	target := currentVanillaTarget()
	classifier := "natives-" + target.OS

	var base string
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	base = server.URL

	assetIndex := map[string]any{
		"objects": map[string]any{
			"minecraft/lang/en_us.json": map[string]any{"hash": assetHash, "size": len(asset)},
		},
	}
	assetIndexBytes, _ := json.Marshal(assetIndex)

	version := map[string]any{
		"id":          "test-vanilla",
		"type":        "release",
		"mainClass":   "net.minecraft.client.main.Main",
		"assets":      "test-assets",
		"assetIndex":  map[string]any{"id": "test-assets", "url": base + "/asset-index.json", "sha1": sha1hex(assetIndexBytes), "size": len(assetIndexBytes)},
		"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
		"javaVersion": map[string]any{"majorVersion": 21},
		"arguments": map[string]any{
			"jvm":  []any{"-Djava.library.path=${natives_directory}", "-cp", "${classpath}"},
			"game": []any{"--username", "${auth_player_name}", "--version", "${version_name}"},
		},
		"libraries": []any{
			map[string]any{
				"name": "org.example:testlib:1.0",
				"downloads": map[string]any{
					"artifact":    map[string]any{"path": "org/example/testlib/1.0/testlib-1.0.jar", "url": base + "/library.jar", "sha1": sha1hex(libraryJar), "size": len(libraryJar)},
					"classifiers": map[string]any{classifier: map[string]any{"path": "org/example/testlib/1.0/testlib-1.0-" + classifier + ".jar", "url": base + "/native.jar", "sha1": sha1hex(nativeJar), "size": len(nativeJar)}},
				},
				"natives": map[string]any{target.OS: classifier},
				"extract": map[string]any{"exclude": []any{"META-INF/"}},
			},
			map[string]any{
				"name": "org.lwjgl.lwjgl:lwjgl-platform:2.9.1",
				"downloads": map[string]any{
					"classifiers": map[string]any{classifier: map[string]any{"path": "org/lwjgl/lwjgl/lwjgl-platform/2.9.1/lwjgl-platform-2.9.1-" + classifier + ".jar", "url": base + "/legacy-native.jar", "sha1": sha1hex(legacyNativeJar), "size": len(legacyNativeJar)}},
				},
				"natives": map[string]any{target.OS: classifier},
				"extract": map[string]any{"exclude": []any{"META-INF/"}},
			},
		},
		"logging": map[string]any{"client": map[string]any{"argument": "-Dlog4j.configurationFile=${path}", "file": map[string]any{"id": "client-test.xml", "url": base + "/logging.xml", "sha1": sha1hex(logging), "size": len(logging)}}},
	}
	versionBytes, _ := json.Marshal(version)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "test-vanilla", "snapshot": "test-vanilla"},
		Versions: []MojangManifestVersion{{ID: "test-vanilla", Type: "release", URL: base + "/version.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
	mux.HandleFunc("/library.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(libraryJar) })
	mux.HandleFunc("/native.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(nativeJar) })
	mux.HandleFunc("/legacy-native.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(legacyNativeJar) })
	mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })
	mux.HandleFunc("/logging.xml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(logging) })
	mux.HandleFunc(fmt.Sprintf("/assets/%s/%s", assetHash[:2], assetHash), func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(asset) })

	dir := t.TempDir()
	result, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "latest-release",
		ClientDir:        dir,
		VersionManifest:  base + "/manifest.json",
		AssetBaseURL:     base + "/assets",
		LibraryBaseURL:   base + "/libraries",
		Targets:          []vanillaTarget{target},
		Workers:          4,
		StrictUpstream:   true,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "installed-and-verified" || result.MinecraftVersion != "test-vanilla" || result.JavaMajorVersion != 21 {
		t.Fatalf("unexpected result: %+v", result)
	}
	required := []string{
		"versions/test-vanilla/test-vanilla.json",
		"versions/test-vanilla/test-vanilla.jar",
		"libraries/org/example/testlib/1.0/testlib-1.0.jar",
		"libraries/org/example/testlib/1.0/testlib-1.0-" + classifier + ".jar",
		"assets/indexes/test-assets.json",
		"assets/objects/" + assetHash[:2] + "/" + assetHash,
		"assets/log_configs/client-test.xml",
		"natives/" + target.OS + "/libtest-native.bin",
		"natives/" + target.OS + "/liblegacy-native.bin",
		".neverlauncher/vanilla-install.json",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}

	for _, file := range result.Files {
		if file.Path == "libraries/org/lwjgl/lwjgl/lwjgl-platform/2.9.1/lwjgl-platform-2.9.1.jar" {
			t.Fatalf("classifier-only legacy library leaked into classpath materialization: %+v", file)
		}
	}

	staleNative := filepath.Join(dir, "natives", target.OS, "stale-from-previous-run.bin")
	if err := os.WriteFile(staleNative, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	second, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "test-vanilla", ClientDir: dir, VersionManifest: base + "/manifest.json",
		AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries", Targets: []vanillaTarget{target}, Workers: 2,
		StrictUpstream: true, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Cached == 0 {
		t.Fatalf("expected cache hits on second install: %+v", second)
	}
	if _, err := os.Stat(staleNative); !os.IsNotExist(err) {
		t.Fatalf("stale native survived rematerialization: %v", err)
	}

	packagePath := filepath.Join(t.TempDir(), "client-package.json")
	if err := handleRuntimeVanillaPackage([]string{
		"--minecraft", "test-vanilla",
		"--client-dir", dir,
		"--version-manifest", base + "/manifest.json",
		"--asset-base-url", base + "/assets",
		"--library-base-url", base + "/libraries",
		"--target", target.OS + "/" + target.Arch,
		"--project", "test-project",
		"--profile", "vanilla",
		"--channel", "stable",
		"--version", "1.0.0",
		"--output", packagePath,
	}); err != nil {
		t.Fatalf("vanilla-package failed: %v", err)
	}
	packageManifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		t.Fatalf("generated package is not consumable: %v", err)
	}
	if packageManifest.ProjectID != "test-project" || packageManifest.Version != "1.0.0" {
		t.Fatalf("unexpected generated package: %+v", packageManifest)
	}
	seenLogging, seenNative := false, false
	for _, file := range packageManifest.Files {
		if strings.HasPrefix(file.Path, ".neverlauncher/") {
			t.Fatalf("local Vanilla state leaked into client package: %s", file.Path)
		}
		seenLogging = seenLogging || file.Path == "assets/log_configs/client-test.xml"
		seenNative = seenNative || file.Path == "natives/"+target.OS+"/libtest-native.bin"
	}
	if !seenLogging || !seenNative {
		t.Fatalf("generated package missing runtime artifacts: logging=%v native=%v", seenLogging, seenNative)
	}
	raw, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper map[string]any
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	if _, ok := wrapper["manifestSettings"]; !ok {
		t.Fatal("vanilla-package does not include manifestSettings")
	}
}

func TestInstallVanillaPre16AliasAndVirtualAssets(t *testing.T) {
	clientJar := []byte("legacy-client-jar")
	asset := []byte("legacy-sound")
	assetHash := sha1hex(asset)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	base := server.URL

	assetIndex := map[string]any{
		"objects": map[string]any{
			"sound/random/click.ogg": map[string]any{"hash": assetHash, "size": len(asset)},
		},
	}
	assetIndexBytes, _ := json.Marshal(assetIndex)
	versionDoc := map[string]any{
		"id":        "1.0",
		"type":      "release",
		"mainClass": "net.minecraft.launchwrapper.Launch",
		"assets":    "pre-1.6",
		"assetIndex": map[string]any{
			"id": "pre-1.6", "url": base + "/pre-1.6.json", "sha1": sha1hex(assetIndexBytes), "size": len(assetIndexBytes),
		},
		"downloads": map[string]any{
			"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)},
		},
		"javaVersion":        map[string]any{"majorVersion": 8},
		"libraries":          []any{},
		"minecraftArguments": "${auth_player_name} ${auth_session} --gameDir ${game_directory} --assetsDir ${game_assets}",
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "1.0", "snapshot": "1.0"},
		Versions: []MojangManifestVersion{{ID: "1.0", Type: "release", URL: base + "/1.0.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/1.0.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
	mux.HandleFunc("/pre-1.6.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })
	mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(asset) })

	dir := t.TempDir()
	stale := filepath.Join(dir, "assets", "virtual", "pre-1.6", "stale.txt")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "1.0.0",
		ClientDir:        dir,
		VersionManifest:  base + "/manifest.json",
		AssetBaseURL:     base + "/assets",
		Targets:          []vanillaTarget{currentVanillaTarget()},
		Workers:          2,
		StrictUpstream:   true,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.MinecraftVersion != "1.0" || result.JavaMajorVersion != 8 {
		t.Fatalf("unexpected canonical legacy result: %+v", result)
	}
	virtualAsset := filepath.Join(dir, "assets", "virtual", "pre-1.6", "sound", "random", "click.ogg")
	if got, err := os.ReadFile(virtualAsset); err != nil || !bytes.Equal(got, asset) {
		t.Fatalf("pre-1.6 virtual asset missing/corrupt: %v %q", err, got)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale pre-1.6 virtual asset survived rebuild: %v", err)
	}
	found := false
	for _, file := range result.Files {
		if file.Path == "assets/virtual/pre-1.6/sound/random/click.ogg" && file.Kind == "virtual-asset" {
			found = true
		}
	}
	if !found {
		t.Fatalf("virtual asset not bound into install evidence: %+v", result.Files)
	}
}

func TestExtractNativeJarRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create("../escape.dll")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("bad"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "native.jar")
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := extractNativeJar(archive, filepath.Join(t.TempDir(), "natives"), nil); err == nil {
		t.Fatal("traversal archive accepted")
	}
}

func TestValidateRemoteURLRejectsPlainHTTPExceptLoopback(t *testing.T) {
	if err := validateRemoteURL("http://example.com/file.jar"); err == nil {
		t.Fatal("plain HTTP accepted")
	}
	if err := validateRemoteURL("http://127.0.0.1:8080/file.jar"); err != nil {
		t.Fatalf("loopback HTTP rejected: %v", err)
	}
	if err := validateRemoteURL("https://example.com/file.jar"); err != nil {
		t.Fatalf("HTTPS rejected: %v", err)
	}
}
