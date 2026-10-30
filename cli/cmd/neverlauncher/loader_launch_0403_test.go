package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// This integration test executes an actual Java entrypoint after HTTP-backed
// materialization. It verifies Maven dependency resolution, not a Mojang game
// boot (which requires licensed upstream artifacts and a graphical host).
func TestFabricQuilt0403MaterializedClasspathRunsOnJVM(t *testing.T) {
	for _, binary := range []string{"java", "javac", "jar"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("Java integration needs %s: %v", binary, err)
		}
	}
	for _, tc := range []struct{ loader, version, entrypoint, coordinate string }{
		{"fabric", "0.16.10", "net.fabricmc.loader.impl.launch.knot.KnotClient", "net.fabricmc:fabric-loader:0.16.10"},
		{"quilt", "0.27.1", "org.quiltmc.loader.impl.launch.knot.KnotClient", "org.quiltmc:quilt-loader:0.27.1"},
	} {
		t.Run(tc.loader, func(t *testing.T) {
			compileDir := t.TempDir()
			dependency := compileFixtureJar0403(t, compileDir, "org.example.Shared", "package org.example; public final class Shared { public static String result() { return \"LOADER_CLASSPATH_OK\"; } }", nil)
			mainName := tc.entrypoint[strings.LastIndex(tc.entrypoint, ".")+1:]
			packageName := tc.entrypoint[:strings.LastIndex(tc.entrypoint, ".")]
			launcher := compileFixtureJar0403(t, compileDir, tc.entrypoint, fmt.Sprintf("package %s; public final class %s { public static void main(String[] args) { System.out.println(org.example.Shared.result()); } }", packageName, mainName), []string{dependency})
			libraryArtifacts := map[string][]byte{}
			loaderPath, err := strictMavenPath(tc.coordinate)
			if err != nil {
				t.Fatal(err)
			}
			libraryArtifacts["/maven/"+loaderPath] = mustRead0403(t, launcher)
			dependencyName := "org.example:shared:1.0.0@jar"
			dependencyPath, err := strictMavenPath(dependencyName)
			if err != nil {
				t.Fatal(err)
			}
			libraryArtifacts["/maven/"+dependencyPath] = mustRead0403(t, dependency)
			clientJar := []byte("client jar fixture, JVM entrypoint is the loader")
			assetBytes := []byte("asset fixture")
			assetSHA := sha10403(assetBytes)
			index, _ := json.Marshal(map[string]any{"objects": map[string]any{"asset.txt": map[string]any{"hash": assetSHA, "size": len(assetBytes)}}})
			var base string
			var unexpectedFetch atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body []byte
				switch r.URL.Path {
				case "/manifest.json":
					version := version0403(base, clientJar, index)
					body, _ = json.Marshal(map[string]any{"latest": map[string]any{"release": "fixture-0403"}, "versions": []any{map[string]any{"id": "fixture-0403", "type": "release", "url": base + "/version.json", "sha1": sha10403(version)}}})
				case "/version.json":
					body = version0403(base, clientJar, index)
				case "/client.jar":
					body = clientJar
				case "/asset-index.json":
					body = index
				case "/assets/" + assetSHA[:2] + "/" + assetSHA:
					body = assetBytes
				case "/meta/versions/loader/fixture-0403":
					body, _ = json.Marshal([]any{map[string]any{"loader": map[string]any{"version": tc.version, "maven": tc.coordinate, "stable": true}}})
				case "/meta/versions/loader/fixture-0403/" + tc.version + "/profile/json":
					body, _ = json.Marshal(map[string]any{
						"id": tc.loader + "-loader-" + tc.version + "-fixture-0403", "inheritsFrom": "fixture-0403", "mainClass": tc.entrypoint,
						"libraries": []any{
							map[string]any{"name": tc.coordinate, "url": base + "/maven"},
							map[string]any{"name": dependencyName, "url": base + "/maven"},
							// This unavailable Windows-only dependency must not prevent Linux installation.
							map[string]any{"name": "org.example:windows-only:1.0", "url": base + "/unavailable", "rules": []any{map[string]any{"action": "allow", "os": map[string]any{"name": "windows"}}}},
							// Server-only library must never enter the client classpath.
							map[string]any{"name": "org.example:server-only:1.0", "clientreq": false},
						},
						"arguments": map[string]any{"jvm": []any{"-Dloader.fixture=" + tc.loader}},
					})
				default:
					if strings.HasSuffix(r.URL.Path, ".sha1") {
						if jar, ok := libraryArtifacts[strings.TrimSuffix(r.URL.Path, ".sha1")]; ok {
							body = []byte(sha10403(jar))
							break
						}
					}
					if jar, ok := libraryArtifacts[r.URL.Path]; ok {
						body = jar
						break
					}
					unexpectedFetch.Add(1)
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			base = server.URL
			clientDir := t.TempDir()
			result, err := installMetaLoader(context.Background(), loaderMaterializeOptions{
				Loader: tc.loader, MinecraftVersion: "fixture-0403", LoaderVersion: tc.version, ClientDir: clientDir,
				VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/maven", MetaBaseURL: base + "/meta",
				Targets: []vanillaTarget{{OS: "linux", Arch: "x86_64"}}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := unexpectedFetch.Load(); got != 0 {
				t.Fatalf("fetched %d libraries for unsupported platform", got)
			}
			if result.MainClass != tc.entrypoint {
				t.Fatalf("wrong mainClass: %s", result.MainClass)
			}
			profileData := mustRead0403(t, filepath.Join(clientDir, filepath.FromSlash(result.ProfilePath)))
			var profile loaderVersionProfile
			if err := json.Unmarshal(profileData, &profile); err != nil {
				t.Fatal(err)
			}
			var classpath []string
			for _, library := range profile.Libraries[:2] {
				path := filepath.Join(clientDir, "libraries", filepath.FromSlash(library.Downloads.Artifact.Path))
				if _, err := os.Stat(path); err != nil {
					t.Fatal(err)
				}
				classpath = append(classpath, path)
			}
			classpath = append(classpath, filepath.Join(clientDir, "versions", "fixture-0403", "fixture-0403.jar"))
			cmd := exec.Command("java", "-cp", strings.Join(classpath, string(os.PathListSeparator)), result.MainClass)
			output, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(output)) != "LOADER_CLASSPATH_OK" {
				t.Fatalf("JVM launcher failed: %v: %s", err, output)
			}
		})
	}
}

func version0403(base string, clientJar, index []byte) []byte {
	data, _ := json.Marshal(map[string]any{
		"id": "fixture-0403", "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": "fixture-assets",
		"assetIndex":  map[string]any{"id": "fixture-assets", "url": base + "/asset-index.json", "sha1": sha10403(index), "size": len(index)},
		"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha10403(clientJar), "size": len(clientJar)}},
		"javaVersion": map[string]any{"majorVersion": 21},
		"arguments":   map[string]any{"game": []any{"--username", "${auth_player_name}"}, "jvm": []any{"-cp", "${classpath}"}},
		"libraries":   []any{},
	})
	return data
}

func sha10403(data []byte) string { digest := sha1.Sum(data); return hex.EncodeToString(digest[:]) }
func mustRead0403(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func compileFixtureJar0403(t *testing.T, dir, className, source string, classpath []string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "src", filepath.FromSlash(strings.ReplaceAll(className, ".", "/"))+".java")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, strings.ReplaceAll(className, ".", "-"))
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"-d", outputDir}
	if len(classpath) != 0 {
		args = append(args, "-cp", strings.Join(classpath, string(os.PathListSeparator)))
	}
	args = append(args, sourcePath)
	if out, err := exec.Command("javac", args...).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v: %s", err, out)
	}
	jarPath := outputDir + ".jar"
	if out, err := exec.Command("jar", "--create", "--file", jarPath, "-C", outputDir, ".").CombinedOutput(); err != nil {
		t.Fatalf("jar: %v: %s", err, out)
	}
	return jarPath
}

func TestLoader0403RejectsMavenArtifactPathDrift(t *testing.T) {
	name := "org.example:demo:1.0"
	if _, err := strictMavenPath(name + "@zip"); err == nil {
		t.Fatal("non-JAR Maven extension allowed")
	}
	if rel, err := strictMavenPath(name + "@jar"); err != nil || rel != "org/example/demo/1.0/demo-1.0.jar" {
		t.Fatalf("jar suffix: %s %v", rel, err)
	}
	for _, name := range []string{"org..example:demo:1.0", "org.example:../demo:1.0", "org.example:demo:..", "org.example:demo:1.0@zip"} {
		if _, err := strictMavenPath(name); err == nil {
			t.Errorf("unsafe Maven coordinate accepted %q", name)
		}
	}
	jar := []byte("fixture")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(jar) }))
	defer server.Close()
	profile := loaderVersionProfile{Libraries: []MojangLibrary{{Name: name, URL: server.URL, Downloads: MojangLibraryDownloads{Artifact: MojangDownload{Path: "different/path.jar", URL: server.URL, SHA1: sha10403(jar)}}}}}
	if _, err := materializeLoaderLibraries(context.Background(), server.Client(), t.TempDir(), &profile, 1, true); err == nil || !strings.Contains(err.Error(), "Maven identity") {
		t.Fatalf("wrong artifact path must fail, got %v", err)
	}
}
