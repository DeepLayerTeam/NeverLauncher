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
	modernNativeJar := testNamedNativeZip(t, "libmodern-native.bin", []byte("modern-native-binary"))
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
			map[string]any{
				"name": "org.lwjgl:lwjgl-glfw:3.4.1:" + classifier,
				"downloads": map[string]any{
					"artifact": map[string]any{"path": "org/lwjgl/lwjgl-glfw/3.4.1/lwjgl-glfw-3.4.1-" + classifier + ".jar", "url": base + "/modern-native.jar", "sha1": sha1hex(modernNativeJar), "size": len(modernNativeJar)},
				},
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
	mux.HandleFunc("/modern-native.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(modernNativeJar) })
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
		"natives/" + target.OS + "/" + target.Arch + "/libtest-native.bin",
		"natives/" + target.OS + "/" + target.Arch + "/liblegacy-native.bin",
		"natives/" + target.OS + "/" + target.Arch + "/libmodern-native.bin",
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
		if file.Path == "libraries/org/lwjgl/lwjgl-glfw/3.4.1/lwjgl-glfw-3.4.1-"+classifier+".jar" && file.Kind != "native-archive" {
			t.Fatalf("modern Mojang native artifact was not marked as native archive: %+v", file)
		}
	}

	staleNative := filepath.Join(dir, "natives", target.OS, target.Arch, "stale-from-previous-run.bin")
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
		seenNative = seenNative || file.Path == "natives/"+target.OS+"/"+target.Arch+"/libtest-native.bin"
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

func TestJavaMajorFromVersionEnforcesJava16And17VanillaRange(t *testing.T) {
	cases := []struct {
		version string
		major   int
	}{
		{"1.17.1", 16},
		{"1.18.2", 17},
		{"1.19.4", 17},
		{"1.20.1", 17},
		{"1.20.2", 17},
		{"1.20.4", 17},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			got, err := javaMajorFromVersion(tc.version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(tc.major)}})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.major {
				t.Fatalf("Minecraft %s Java=%d, want %d", tc.version, got, tc.major)
			}
			if _, err := javaMajorFromVersion(tc.version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(tc.major + 1)}}); err == nil {
				t.Fatalf("Minecraft %s accepted wrong Java major", tc.version)
			}
			if _, err := javaMajorFromVersion(tc.version, MojangVersionFile{}); err == nil {
				t.Fatalf("Minecraft %s accepted missing javaVersion.majorVersion", tc.version)
			}
		})
	}

	legacy, err := javaMajorFromVersion("1.16.5", MojangVersionFile{})
	if err != nil || legacy != 8 {
		t.Fatalf("legacy Java fallback changed: major=%d err=%v", legacy, err)
	}
}

func TestJavaMajorFromVersionEnforces0170v2Grid(t *testing.T) {
	want := map[string]int{
		"1.17": 16,
		"1.18": 17, "1.18.1": 17,
		"1.19": 17, "1.19.1": 17, "1.19.2": 17, "1.19.3": 17,
		"1.20": 17, "1.20.3": 17,
	}
	if len(java16_17Vanilla0170v2Releases) != len(want) {
		t.Fatalf("0.17.0v2 Java 16/17 release grid=%d, want %d", len(java16_17Vanilla0170v2Releases), len(want))
	}
	for version, major := range want {
		expected, ok := expectedJavaMajorForVanilla0170v2(version)
		if !ok || expected != major {
			t.Fatalf("Minecraft %s 0.17.0v2 expected Java=%d ok=%v, want %d/true", version, expected, ok, major)
		}
		got, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(major)}})
		if err != nil || got != major {
			t.Fatalf("Minecraft %s Java=%d err=%v, want %d", version, got, err, major)
		}
		if _, err := javaMajorFromVersion(version, MojangVersionFile{}); err == nil || !strings.Contains(err.Error(), "0.17.0v2") {
			t.Fatalf("Minecraft %s accepted missing Java metadata: %v", version, err)
		}
		wrong := 17
		if major == 17 {
			wrong = 16
		}
		if _, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(wrong)}}); err == nil || !strings.Contains(err.Error(), "0.17.0v2") {
			t.Fatalf("Minecraft %s accepted wrong Java %d: %v", version, wrong, err)
		}
	}
	for _, outside := range []string{"1.17.1", "1.18.2", "1.19.4", "1.20.1", "1.20.2", "1.20.4", "1.20.5"} {
		if _, ok := expectedJavaMajorForVanilla0170v2(outside); ok {
			t.Fatalf("%s unexpectedly classified as newly added 0.17.0v2 release", outside)
		}
	}
}

func TestJavaMajorFromVersionEnforces0170v3Grid(t *testing.T) {
	want := map[string]int{"1.21.11": 21, "26.2": 25}
	if len(java21_25Vanilla0170v3Releases) != len(want) {
		t.Fatalf("0.17.0v3 Java 21/25 release grid=%d, want %d", len(java21_25Vanilla0170v3Releases), len(want))
	}
	for version, major := range want {
		expected, ok := expectedJavaMajorForVanilla0170v3(version)
		if !ok || expected != major {
			t.Fatalf("Minecraft %s 0.17.0v3 expected Java=%d ok=%v, want %d/true", version, expected, ok, major)
		}
		got, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(major)}})
		if err != nil || got != major {
			t.Fatalf("Minecraft %s Java=%d err=%v, want %d", version, got, err, major)
		}
		if _, err := javaMajorFromVersion(version, MojangVersionFile{}); err == nil || !strings.Contains(err.Error(), "0.17.0v3") {
			t.Fatalf("Minecraft %s accepted missing Java metadata: %v", version, err)
		}
		wrong := 17
		if major == 25 {
			wrong = 21
		}
		if _, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(wrong)}}); err == nil || !strings.Contains(err.Error(), "0.17.0v3") {
			t.Fatalf("Minecraft %s accepted wrong Java %d: %v", version, wrong, err)
		}
	}
	for _, outside := range []string{"1.21.10", "26.1.2", "26.3"} {
		if _, ok := expectedJavaMajorForVanilla0170v3(outside); ok {
			t.Fatalf("%s unexpectedly classified as newly added 0.17.0v3 release", outside)
		}
	}
}

func TestLegacyVanilla0170v1GridIsExactJava8(t *testing.T) {
	if len(legacyVanilla0170v1Releases) != 53 {
		t.Fatalf("legacy 0.17.0v1 release grid=%d, want 53", len(legacyVanilla0170v1Releases))
	}
	for _, minecraftVersion := range legacyVanilla0170v1Releases {
		t.Run(minecraftVersion, func(t *testing.T) {
			if !isLegacyVanilla0170v1Release(minecraftVersion) {
				t.Fatalf("%s missing from exact 0.17.0v1 release set", minecraftVersion)
			}
			got, err := javaMajorFromVersion(minecraftVersion, MojangVersionFile{})
			if err != nil || got != 8 {
				t.Fatalf("Minecraft %s Java=%d err=%v, want exact Java 8 fallback", minecraftVersion, got, err)
			}
			got, err = javaMajorFromVersion(minecraftVersion, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(8)}})
			if err != nil || got != 8 {
				t.Fatalf("Minecraft %s explicit Java 8 rejected: major=%d err=%v", minecraftVersion, got, err)
			}
			if _, err := javaMajorFromVersion(minecraftVersion, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(17)}}); err == nil {
				t.Fatalf("Minecraft %s accepted tampered Java 17 metadata", minecraftVersion)
			}
		})
	}
	for _, outside := range []string{"1.2.5", "1.3.2", "1.4.7", "1.5.2", "1.6.4", "1.7.10", "1.8.9", "1.9.4", "1.10.2", "1.11.2", "1.12.2", "1.13.2", "1.14.4", "1.15.2", "1.16.5"} {
		if isLegacyVanilla0170v1Release(outside) {
			t.Fatalf("anchor %s unexpectedly classified as newly added 0.17.0v1 release", outside)
		}
	}
}

func TestInstallVanilla0170v1MaterializesLegacyReleaseWithoutJavaVersion(t *testing.T) {
	clientJar := []byte("legacy-1.2.1-client")
	assetIndexBytes := []byte(`{"objects":{}}`)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	base := server.URL

	versionDoc := map[string]any{
		"id":        "1.2.1",
		"type":      "release",
		"mainClass": "net.minecraft.client.Minecraft",
		"assets":    "pre-1.6",
		"assetIndex": map[string]any{
			"id": "pre-1.6", "url": base + "/pre-1.6.json", "sha1": sha1hex(assetIndexBytes), "size": len(assetIndexBytes),
		},
		"downloads": map[string]any{
			"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)},
		},
		"libraries":          []any{},
		"minecraftArguments": "${auth_player_name} ${auth_session} --gameDir ${game_directory} --assetsDir ${game_assets}",
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "1.2.1"},
		Versions: []MojangManifestVersion{{ID: "1.2.1", Type: "release", URL: base + "/1.2.1.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/1.2.1.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
	mux.HandleFunc("/pre-1.6.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })

	dir := t.TempDir()
	result, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "1.2.1",
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
	if result.MinecraftVersion != "1.2.1" || result.JavaMajorVersion != 8 {
		t.Fatalf("unexpected 0.17.0v1 legacy result: %+v", result)
	}
	for _, rel := range []string{"versions/1.2.1/1.2.1.json", "versions/1.2.1/1.2.1.jar", "assets/indexes/pre-1.6.json"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("missing materialized %s: %v", rel, err)
		}
	}
}

func TestInstallVanilla0170v2MaterializesModernJavaTransition(t *testing.T) {
	for _, tc := range []struct {
		version   string
		javaMajor int
	}{{"1.17", 16}, {"1.20.3", 17}} {
		t.Run(tc.version, func(t *testing.T) {
			clientJar := []byte("modern-client-" + tc.version)
			assetIndexBytes := []byte(`{"objects":{}}`)
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			base := server.URL
			versionDoc := map[string]any{
				"id": tc.version, "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": tc.version,
				"assetIndex":  map[string]any{"id": tc.version, "url": base + "/assets.json", "sha1": sha1hex(assetIndexBytes), "size": len(assetIndexBytes)},
				"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
				"javaVersion": map[string]any{"majorVersion": tc.javaMajor},
				"arguments": map[string]any{
					"jvm":  []any{"-Djava.library.path=${natives_directory}", "-cp", "${classpath}"},
					"game": []any{"--username", "${auth_player_name}", "--version", "${version_name}", "--assetsDir", "${assets_root}", "--assetIndex", "${assets_index_name}"},
				},
				"libraries": []any{},
			}
			versionBytes, _ := json.Marshal(versionDoc)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": tc.version}, Versions: []MojangManifestVersion{{ID: tc.version, Type: "release", URL: base + "/version.json", SHA1: sha1hex(versionBytes)}}}
			manifestBytes, _ := json.Marshal(manifest)
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
			mux.HandleFunc("/assets.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })

			dir := t.TempDir()
			result, err := installVanilla(context.Background(), vanillaInstallOptions{
				MinecraftVersion: tc.version, ClientDir: dir, VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/objects",
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.MinecraftVersion != tc.version || result.JavaMajorVersion != tc.javaMajor || result.Status != "installed-and-verified" {
				t.Fatalf("unexpected 0.17.0v2 result: %+v", result)
			}
			for _, rel := range []string{"versions/" + tc.version + "/" + tc.version + ".json", "versions/" + tc.version + "/" + tc.version + ".jar", "assets/indexes/" + tc.version + ".json"} {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatalf("missing materialized %s: %v", rel, err)
				}
			}
		})
	}
}

func TestInstallVanilla0170v3MaterializesJava21And25Releases(t *testing.T) {
	for _, tc := range []struct {
		version   string
		javaMajor int
	}{{"1.21.11", 21}, {"26.2", 25}} {
		t.Run(tc.version, func(t *testing.T) {
			clientJar := []byte("modern-v3-client-" + tc.version)
			assetIndexBytes := []byte(`{"objects":{}}`)
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			base := server.URL
			versionDoc := map[string]any{
				"id": tc.version, "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": tc.version,
				"assetIndex":  map[string]any{"id": tc.version, "url": base + "/assets.json", "sha1": sha1hex(assetIndexBytes), "size": len(assetIndexBytes)},
				"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
				"javaVersion": map[string]any{"majorVersion": tc.javaMajor},
				"arguments": map[string]any{
					"jvm":  []any{"-Djava.library.path=${natives_directory}", "-cp", "${classpath}"},
					"game": []any{"--username", "${auth_player_name}", "--version", "${version_name}", "--assetsDir", "${assets_root}", "--assetIndex", "${assets_index_name}"},
				},
				"libraries": []any{},
			}
			versionBytes, _ := json.Marshal(versionDoc)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": tc.version}, Versions: []MojangManifestVersion{{ID: tc.version, Type: "release", URL: base + "/version.json", SHA1: sha1hex(versionBytes)}}}
			manifestBytes, _ := json.Marshal(manifest)
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
			mux.HandleFunc("/assets.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })

			dir := t.TempDir()
			result, err := installVanilla(context.Background(), vanillaInstallOptions{
				MinecraftVersion: tc.version, ClientDir: dir, VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/objects",
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.MinecraftVersion != tc.version || result.JavaMajorVersion != tc.javaMajor || result.Status != "installed-and-verified" {
				t.Fatalf("unexpected 0.17.0v3 result: %+v", result)
			}
			for _, rel := range []string{"versions/" + tc.version + "/" + tc.version + ".json", "versions/" + tc.version + "/" + tc.version + ".jar", "assets/indexes/" + tc.version + ".json"} {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatalf("missing materialized %s: %v", rel, err)
				}
			}
		})
	}
}

func TestInstallVanillaServer0170v3RejectsWrongJavaBeforeArtifactDownload(t *testing.T) {
	serverJar := []byte("must-not-download-v3-server")
	serverRequested := false
	mux := http.NewServeMux()
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	versionDoc := map[string]any{
		"id": "26.2", "type": "release",
		"downloads":   map[string]any{"server": map[string]any{"url": httpServer.URL + "/server.jar", "sha1": sha1hex(serverJar), "size": len(serverJar)}},
		"javaVersion": map[string]any{"majorVersion": 21},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "26.2", "snapshot": "26.2"},
		Versions: []MojangManifestVersion{{ID: "26.2", Type: "release", URL: httpServer.URL + "/26.2.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/26.2.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/server.jar", func(w http.ResponseWriter, r *http.Request) {
		serverRequested = true
		_, _ = w.Write(serverJar)
	})

	_, err := installVanillaServer(context.Background(), "26.2", t.TempDir(), httpServer.URL+"/manifest.json", httpServer.Client())
	if err == nil || !strings.Contains(err.Error(), "0.17.0v3") {
		t.Fatalf("expected 0.17.0v3 exact-Java rejection, got %v", err)
	}
	if serverRequested {
		t.Fatal("26.2 server artifact was downloaded before 0.17.0v3 exact-Java metadata validation")
	}
}

func TestValidateVanillaLaunchMetadataRejectsNonExecutableProfile(t *testing.T) {
	if err := validateVanillaLaunchMetadata(vanillaVersionMetadata{MojangVersionFile: MojangVersionFile{ID: "1.8.8"}}); err == nil {
		t.Fatal("legacy metadata without minecraftArguments/arguments.game was accepted")
	}
	if err := validateVanillaLaunchMetadata(vanillaVersionMetadata{MojangVersionFile: MojangVersionFile{ID: "1.8.8", MinecraftArgs: "--username ${auth_player_name}"}}); err != nil {
		t.Fatalf("legacy minecraftArguments rejected: %v", err)
	}
	if err := validateVanillaLaunchMetadata(vanillaVersionMetadata{MojangVersionFile: MojangVersionFile{ID: "1.16.4", Arguments: MojangArguments{Game: []any{"--username", "${auth_player_name}"}}}}); err != nil {
		t.Fatalf("modern arguments.game rejected: %v", err)
	}
}

func TestJavaMajorFromVersionEnforcesJava21VanillaRange(t *testing.T) {
	versions := []string{
		"1.20.5", "1.20.6", "1.21", "1.21.1", "1.21.2", "1.21.3", "1.21.4",
		"1.21.5", "1.21.6", "1.21.7", "1.21.8", "1.21.9", "1.21.10",
	}
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			got, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(21)}})
			if err != nil || got != 21 {
				t.Fatalf("Minecraft %s Java=%d err=%v, want 21", version, got, err)
			}
			if _, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(17)}}); err == nil {
				t.Fatalf("Minecraft %s accepted Java 17", version)
			}
			if _, err := javaMajorFromVersion(version, MojangVersionFile{}); err == nil {
				t.Fatalf("Minecraft %s accepted missing javaVersion.majorVersion", version)
			}
		})
	}
	for _, version := range []string{"1.20.4", "1.21.11", "1.22"} {
		if _, enforced := expectedJavaMajorForVanilla0167(version); enforced {
			t.Fatalf("Minecraft %s unexpectedly covered by 0.16.7 Java 21 policy", version)
		}
	}
}

func TestJavaMajorFromVersionEnforcesJava25VanillaRange(t *testing.T) {
	versions := []string{"26.1", "26.1.1", "26.1.2", "26.3"}
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			got, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(25)}})
			if err != nil || got != 25 {
				t.Fatalf("Minecraft %s Java=%d err=%v, want 25", version, got, err)
			}
			if _, err := javaMajorFromVersion(version, MojangVersionFile{JavaVersion: map[string]any{"majorVersion": float64(21)}}); err == nil {
				t.Fatalf("Minecraft %s accepted Java 21", version)
			}
			if _, err := javaMajorFromVersion(version, MojangVersionFile{}); err == nil {
				t.Fatalf("Minecraft %s accepted missing javaVersion.majorVersion", version)
			}
		})
	}
	for _, version := range []string{"1.21.10", "26.2", "26.3.1", "26.4"} {
		if _, enforced := expectedJavaMajorForVanilla0168(version); enforced {
			t.Fatalf("Minecraft %s unexpectedly covered by 0.16.8 Java 25 policy", version)
		}
	}
}

func TestInstallVanillaRejectsWrongJavaBeforeArtifactDownload(t *testing.T) {
	clientJar := []byte("must-not-download")
	clientRequested := false
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	versionDoc := map[string]any{
		"id": "1.17.1", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads":   map[string]any{"client": map[string]any{"url": server.URL + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
		"javaVersion": map[string]any{"majorVersion": 17},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "1.17.1", "snapshot": "1.17.1"},
		Versions: []MojangManifestVersion{{ID: "1.17.1", Type: "release", URL: server.URL + "/1.17.1.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/1.17.1.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) {
		clientRequested = true
		_, _ = w.Write(clientJar)
	})

	_, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "1.17.1",
		ClientDir:        t.TempDir(),
		VersionManifest:  server.URL + "/manifest.json",
		Targets:          []vanillaTarget{currentVanillaTarget()},
		StrictUpstream:   true,
		HTTPClient:       server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "Java mismatch") {
		t.Fatalf("expected exact-Java rejection, got %v", err)
	}
	if clientRequested {
		t.Fatal("client artifact was downloaded before exact-Java metadata validation")
	}
}

func TestInstallVanilla0168RejectsWrongJavaBeforeArtifactDownload(t *testing.T) {
	clientJar := []byte("must-not-download-0168")
	clientRequested := false
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	versionDoc := map[string]any{
		"id": "26.3", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads":   map[string]any{"client": map[string]any{"url": server.URL + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
		"javaVersion": map[string]any{"majorVersion": 21},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "26.3", "snapshot": "26.3"},
		Versions: []MojangManifestVersion{{ID: "26.3", Type: "release", URL: server.URL + "/26.3.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/26.3.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) {
		clientRequested = true
		_, _ = w.Write(clientJar)
	})

	_, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "26.3",
		ClientDir:        t.TempDir(),
		VersionManifest:  server.URL + "/manifest.json",
		Targets:          []vanillaTarget{currentVanillaTarget()},
		StrictUpstream:   true,
		HTTPClient:       server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "Java mismatch") {
		t.Fatalf("expected 0.16.8 exact-Java rejection, got %v", err)
	}
	if clientRequested {
		t.Fatal("26.3 client artifact was downloaded before exact-Java metadata validation")
	}
}

func TestInstallVanilla0167RejectsWrongJavaBeforeArtifactDownload(t *testing.T) {
	clientJar := []byte("must-not-download-0167")
	clientRequested := false
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	versionDoc := map[string]any{
		"id": "1.21.10", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads":   map[string]any{"client": map[string]any{"url": server.URL + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)}},
		"javaVersion": map[string]any{"majorVersion": 17},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "1.21.10", "snapshot": "1.21.10"},
		Versions: []MojangManifestVersion{{ID: "1.21.10", Type: "release", URL: server.URL + "/1.21.10.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/1.21.10.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) {
		clientRequested = true
		_, _ = w.Write(clientJar)
	})

	_, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: "1.21.10",
		ClientDir:        t.TempDir(),
		VersionManifest:  server.URL + "/manifest.json",
		Targets:          []vanillaTarget{currentVanillaTarget()},
		StrictUpstream:   true,
		HTTPClient:       server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "Java mismatch") {
		t.Fatalf("expected 0.16.7 exact-Java rejection, got %v", err)
	}
	if clientRequested {
		t.Fatal("1.21.10 client artifact was downloaded before exact-Java metadata validation")
	}
}

func TestVanillaRuleAndNativeClassifierMatchTargetArchitecture(t *testing.T) {
	arm := vanillaTarget{OS: "windows", Arch: "aarch64"}
	x64 := vanillaTarget{OS: "windows", Arch: "x86_64"}

	rules := []map[string]any{{"action": "allow", "os": map[string]any{"name": "windows-arm64", "arch": "aarch64|arm64"}}}
	if !rulesAllowTarget(rules, arm) {
		t.Fatal("windows ARM64 target did not match composite Mojang OS/arch rule")
	}
	if rulesAllowTarget(rules, x64) {
		t.Fatal("windows x64 target incorrectly matched ARM64 Mojang rule")
	}
	if !libraryArtifactAppliesToTarget("org.lwjgl:lwjgl-glfw:3.4.1:natives-windows-arm64", arm) {
		t.Fatal("ARM64 native classifier was rejected for Windows ARM64")
	}
	if libraryArtifactAppliesToTarget("org.lwjgl:lwjgl-glfw:3.4.1:natives-windows-arm64", x64) {
		t.Fatal("ARM64 native classifier leaked into Windows x64")
	}
	if !libraryArtifactAppliesToTarget("org.lwjgl:lwjgl-glfw:3.4.1:natives-windows", x64) {
		t.Fatal("legacy Windows native classifier was rejected for x64")
	}
	if libraryArtifactAppliesToTarget("org.lwjgl:lwjgl-glfw:3.4.1:natives-windows", arm) {
		t.Fatal("legacy x64 Windows native classifier leaked into ARM64")
	}
	if !libraryArtifactAppliesToTarget("com.example:plain-library:1.0.0", arm) {
		t.Fatal("non-native library must be architecture-neutral")
	}
	if libraryArtifactAppliesToTarget("org.lwjgl:lwjgl-glfw:3.4.1:natives-linux", arm) {
		t.Fatal("Linux native classifier must never materialize on Windows")
	}
	if !isClassifiedNativeLibrary("org.lwjgl:lwjgl-glfw:3.4.1:natives-windows-arm64") {
		t.Fatal("modern artifact-based native classifier was not recognized")
	}
	if isClassifiedNativeLibrary("org.lwjgl:lwjgl-glfw:3.4.1") {
		t.Fatal("ordinary library must not be extracted as native archive")
	}
}

func TestInstallVanillaServerMaterializesVerifiedMatchingServer(t *testing.T) {
	serverJar := []byte("fake-mojang-server-jar")
	clientJar := []byte("fake-client")
	mux := http.NewServeMux()
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	base := httpServer.URL

	versionDoc := map[string]any{
		"id": "1.20.4", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads": map[string]any{
			"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(clientJar), "size": len(clientJar)},
			"server": map[string]any{"url": base + "/server.jar", "sha1": sha1hex(serverJar), "size": len(serverJar)},
		},
		"javaVersion": map[string]any{"majorVersion": 17},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	manifest := MojangVersionManifest{
		Latest:   map[string]string{"release": "1.20.4"},
		Versions: []MojangManifestVersion{{ID: "1.20.4", Type: "release", URL: base + "/version.json", SHA1: sha1hex(versionBytes)}},
	}
	manifestBytes, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
	mux.HandleFunc("/server.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(serverJar) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })

	dir := t.TempDir()
	result, err := installVanillaServer(context.Background(), "1.20.4", dir, base+"/manifest.json", httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "installed-and-verified" || result.MinecraftVersion != "1.20.4" || result.JavaMajorVersion != 17 {
		t.Fatalf("unexpected server result: %+v", result)
	}
	got, err := os.ReadFile(filepath.Join(dir, "server.jar"))
	if err != nil || !bytes.Equal(got, serverJar) {
		t.Fatalf("matching server jar missing/corrupt: %v %q", err, got)
	}
	if result.SHA1 != sha1hex(serverJar) || len(result.SHA256) != 64 || result.Size != int64(len(serverJar)) {
		t.Fatalf("server integrity evidence invalid: %+v", result)
	}
	second, err := installVanillaServer(context.Background(), "1.20.4", dir, base+"/manifest.json", httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !second.Cached || second.SHA256 != result.SHA256 {
		t.Fatalf("verified server cache not reused: first=%+v second=%+v", result, second)
	}
}

func TestInstallVanillaServerRejectsMissingServerDownload(t *testing.T) {
	versionDoc := map[string]any{
		"id": "test-no-server", "type": "release", "mainClass": "net.minecraft.client.main.Main",
		"downloads":   map[string]any{"client": map[string]any{"url": "https://example.invalid/client.jar", "sha1": strings.Repeat("a", 40), "size": 1}},
		"javaVersion": map[string]any{"majorVersion": 21},
	}
	versionBytes, _ := json.Marshal(versionDoc)
	mux := http.NewServeMux()
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	manifest := MojangVersionManifest{Latest: map[string]string{"release": "test-no-server"}, Versions: []MojangManifestVersion{{ID: "test-no-server", Type: "release", URL: httpServer.URL + "/version.json", SHA1: sha1hex(versionBytes)}}}
	manifestBytes, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })

	_, err := installVanillaServer(context.Background(), "test-no-server", t.TempDir(), httpServer.URL+"/manifest.json", httpServer.Client())
	if err == nil || !strings.Contains(err.Error(), "downloads.server") {
		t.Fatalf("missing verified server artifact must fail closed, got %v", err)
	}
}
