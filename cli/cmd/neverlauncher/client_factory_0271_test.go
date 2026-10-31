package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// These are real HTTP-backed materializer invocations, not mocked install
// adapters. The fixture is deliberately small enough to run offline in CI.
func TestClientFactory0271VanillaTransactionReplayAndTampering(t *testing.T) {
	clientJar := []byte("fixture-client-jar")
	asset := []byte("fixture-asset")
	hash := sha1hex(asset)
	var newest atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			target := "fixture-1"
			if newest.Load() {
				target = "fixture-2"
			}
			metaBytes := fixtureFactoryMetadata0271("http://"+r.Host, "fixture-1", clientJar, asset)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": target}, Versions: []MojangManifestVersion{{ID: "fixture-1", Type: "release", URL: "http://" + r.Host + "/version.json", SHA1: sha1hex(metaBytes)}}}
			_ = json.NewEncoder(w).Encode(manifest)
		case "/version.json":
			w.Write(fixtureFactoryMetadata0271("http://"+r.Host, "fixture-1", clientJar, asset))
		case "/asset-index.json":
			w.Write(fixtureFactoryAssets0271(asset))
		case "/client.jar":
			w.Write(clientJar)
		case "/assets/" + hash[:2] + "/" + hash:
			w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "client")
	opts := factoryBuildOptions0271{Loader: "vanilla", Minecraft: "latest-release", ClientDir: dir, VersionManifest: server.URL + "/manifest.json", AssetBaseURL: server.URL + "/assets", HTTPClient: server.Client(), Workers: 2, StrictUpstream: true}
	first, err := executeFactoryBuild0271(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.MinecraftVersion != "fixture-1" || first.Java.Major != 21 || first.Launch.MainClass == "" || len(first.Sources) < 3 || len(first.Outputs) < 3 || first.ReproducibilitySHA256 == "" {
		t.Fatalf("incomplete materialization: %+v", first)
	}
	if err := verifyFactoryPlan0271(dir, first); err != nil {
		t.Fatal(err)
	}
	newest.Store(true)
	second, err := executeFactoryBuild0271(context.Background(), opts)
	if err != nil {
		t.Fatalf("rebuild incorrectly resolved latest or invalidated pinned inputs: %v", err)
	}
	if second.ReproducibilitySHA256 != first.ReproducibilitySHA256 {
		t.Fatal("replay identity changed")
	}
	jar := filepath.Join(dir, "versions", "fixture-1", "fixture-1.jar")
	if err := os.WriteFile(jar, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(dir, first); err == nil {
		t.Fatal("tampered output passed verification")
	}
	if _, err := executeFactoryBuild0271(context.Background(), opts); err == nil {
		t.Fatal("corrupt previous build was trusted")
	}
	saved, _ := os.ReadFile(jar)
	if string(saved) != "tampered" {
		t.Fatal("failed build modified existing directory")
	}
}
func fixtureFactoryAssets0271(asset []byte) []byte {
	b, _ := json.Marshal(map[string]any{"objects": map[string]any{"test.txt": map[string]any{"hash": sha1hex(asset), "size": len(asset)}}})
	return b
}
func fixtureFactoryMetadata0271(base, id string, client, asset []byte) []byte {
	index := fixtureFactoryAssets0271(asset)
	b, _ := json.Marshal(map[string]any{
		"id": id, "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": "fixture-assets",
		"assetIndex":  map[string]any{"id": "fixture-assets", "url": base + "/asset-index.json", "sha1": sha1hex(index), "size": len(index)},
		"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(client), "size": len(client)}},
		"javaVersion": map[string]any{"majorVersion": 21}, "arguments": map[string]any{"game": []any{"--username", "${auth_player_name}"}, "jvm": []any{"-cp", "${classpath}"}}, "libraries": []any{},
	})
	return b
}
func TestClientFactory0271RejectsUnpinnedOutputAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "extra.jar"), []byte("untested"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := executeFactoryBuild0271(context.Background(), factoryBuildOptions0271{Loader: "vanilla", Minecraft: "latest-release", ClientDir: dir, StrictUpstream: true})
	if err == nil || !strings.Contains(err.Error(), "empty destination") {
		t.Fatalf("nonempty unmanaged directory accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "extra.jar")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "libraries")); err == nil {
		if _, err := scanFactoryOutputs0271(dir); err == nil {
			t.Fatal("symlink accepted as build output")
		}
	}
}
func TestClientFactory0271RejectsModifiedLock(t *testing.T) {
	p := factoryPlan0271{SchemaVersion: factoryPlanSchema0271, Loader: "vanilla", MinecraftVersion: "1.21.1", Targets: []vanillaTarget{{OS: "linux", Arch: "x64"}}, Java: factoryJava0271{Major: 21}, Launch: factoryLaunch0271{MainClass: "net.minecraft.client.main.Main"}, Steps: factorySteps0271("vanilla"), Sources: []factorySource0271{{Path: "versions/1.21.1/1.21.1.json", Kind: "version-metadata", URL: "https://example.org/1.21.1.json", SHA256: strings.Repeat("b", 64), Size: 2}}, Outputs: []factoryOutput0271{{Path: "versions/1.21.1/1.21.1.jar", SHA256: strings.Repeat("a", 64), Size: 12}}}
	d, err := factoryDigest0271(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ReproducibilitySHA256 = d
	if err := validateFactoryPlan0271(p); err != nil {
		t.Fatal(err)
	}
	p.Outputs[0].Size++
	if err := validateFactoryPlan0271(p); err == nil {
		t.Fatal("modified output lock passed")
	}
}

func TestClientFactory0271FabricQuiltPinnedAdapterReplay(t *testing.T) {
	for _, tc := range []struct{ loader, version, coordinate, main string }{
		{"fabric", "0.16.10", "net.fabricmc:fabric-loader:0.16.10", "net.fabricmc.loader.impl.launch.knot.KnotClient"},
		{"quilt", "0.27.1", "org.quiltmc:quilt-loader:0.27.1", "org.quiltmc.loader.impl.launch.knot.KnotClient"},
	} {
		t.Run(tc.loader, func(t *testing.T) {
			minecraft := "test-vanilla"
			clientJar := []byte("fixture-vanilla")
			asset := []byte("fixture-assets")
			assetHash := sha1hex(asset)
			loaderJar := []byte("fixture-loader-" + tc.loader)
			loaderPath, err := strictMavenPath(tc.coordinate)
			if err != nil {
				t.Fatal(err)
			}
			var listed atomic.Int32
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			meta := fixtureFactoryMetadata0271(server.URL, minecraft, clientJar, asset)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": minecraft}, Versions: []MojangManifestVersion{{ID: minecraft, Type: "release", URL: server.URL + "/version.json", SHA1: sha1hex(meta)}}}
			manifestBytes, _ := json.Marshal(manifest)
			profileID := tc.loader + "-loader-" + tc.version + "-" + minecraft
			profile := map[string]any{"id": profileID, "inheritsFrom": minecraft, "mainClass": tc.main, "libraries": []any{map[string]any{"name": tc.coordinate, "url": server.URL + "/maven"}}}
			profileBytes, _ := json.Marshal(profile)
			listBytes, _ := json.Marshal([]any{map[string]any{"loader": map[string]any{"version": tc.version, "stable": true, "maven": tc.coordinate}}})
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { w.Write(meta) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { w.Write(clientJar) })
			mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { w.Write(fixtureFactoryAssets0271(asset)) })
			mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { w.Write(asset) })
			mux.HandleFunc("/"+tc.loader+"/meta/versions/loader/"+minecraft, func(w http.ResponseWriter, r *http.Request) { listed.Add(1); w.Write(listBytes) })
			mux.HandleFunc("/"+tc.loader+"/meta/versions/loader/"+minecraft+"/"+tc.version+"/profile/json", func(w http.ResponseWriter, r *http.Request) { w.Write(profileBytes) })
			mux.HandleFunc("/maven/"+loaderPath, func(w http.ResponseWriter, r *http.Request) { w.Write(loaderJar) })
			mux.HandleFunc("/maven/"+loaderPath+".sha1", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sha1hex(loaderJar))) })
			dir := filepath.Join(t.TempDir(), "client")
			opts := factoryBuildOptions0271{Loader: tc.loader, Minecraft: "latest-release", LoaderVersion: "latest-stable", ClientDir: dir, VersionManifest: server.URL + "/manifest.json", MetaBaseURL: server.URL + "/" + tc.loader + "/meta", AssetBaseURL: server.URL + "/assets", LibraryBaseURL: server.URL + "/libraries", HTTPClient: server.Client(), Workers: 2, StrictUpstream: true}
			first, err := executeFactoryBuild0271(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if first.LoaderVersion != tc.version || first.Launch.MainClass != tc.main || first.LoaderResolutionSHA256 == "" {
				t.Fatalf("incomplete %s install: %+v", tc.loader, first)
			}
			if len(first.Sources) < 4 {
				t.Fatalf("%s sources not captured: %+v", tc.loader, first.Sources)
			}
			second, err := executeFactoryBuild0271(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if second.ReproducibilitySHA256 != first.ReproducibilitySHA256 {
				t.Fatal("loader replay changed digest")
			}
			if listed.Load() != 1 {
				t.Fatalf("loader metadata re-resolved on replay: %d", listed.Load())
			}
			if err := verifyFactoryPlan0271(dir, second); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientFactory0271ForgeNeoForgeProcessorsAreRealAndPinned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture Java executable uses POSIX shell")
	}
	for _, tc := range []struct{ loader, version string }{{"forge", "52.0.1"}, {"neoforge", "21.1.105"}} {
		t.Run(tc.loader, func(t *testing.T) {
			minecraft := "1.21.1"
			clientJar := []byte("minecraft-client")
			asset := []byte("minecraft-asset")
			assetHash := sha1hex(asset)
			generated := []byte("forge-generated-runtime")
			processorJar := testProcessorJar(t)
			installer := testForgeInstaller(t, tc.loader, minecraft, tc.version, generated, processorJar)
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			meta := fixtureFactoryMetadata0271(server.URL, minecraft, clientJar, asset)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": minecraft}, Versions: []MojangManifestVersion{{ID: minecraft, Type: "release", URL: server.URL + "/version.json", SHA1: sha1hex(meta)}}}
			manifestBytes, _ := json.Marshal(manifest)
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { w.Write(meta) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { w.Write(clientJar) })
			mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { w.Write(fixtureFactoryAssets0271(asset)) })
			mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { w.Write(asset) })
			mux.HandleFunc("/installer.jar", func(w http.ResponseWriter, r *http.Request) { w.Write(installer) })
			mux.HandleFunc("/installer.jar.sha1", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sha1hex(installer))) })
			opts := factoryBuildOptions0271{Loader: tc.loader, Minecraft: "latest-release", LoaderVersion: tc.version, ClientDir: filepath.Join(t.TempDir(), "client"), JavaExecutable: testFakeJava(t, generated), InstallerURL: server.URL + "/installer.jar", InstallerSHA1: sha1hex(installer), VersionManifest: server.URL + "/manifest.json", AssetBaseURL: server.URL + "/assets", LibraryBaseURL: server.URL + "/libraries", HTTPClient: server.Client(), Workers: 2, StrictUpstream: true}
			first, err := executeFactoryBuild0271(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if first.Loader != tc.loader || first.LoaderVersion != tc.version || len(first.Processors) == 0 || len(first.Processors[0].Outputs) == 0 || len(first.Sources) < 3 {
				t.Fatalf("incomplete processor evidence: %+v", first)
			}
			next, err := executeFactoryBuild0271(context.Background(), opts)
			if err != nil {
				t.Fatalf("processor replay: %v", err)
			}
			if next.ReproducibilitySHA256 != first.ReproducibilitySHA256 {
				t.Fatal("processor replay changed identity")
			}
		})
	}
}

func TestClientFactory0271RejectsOutputInsideManagedTree(t *testing.T) {
	root := t.TempDir()
	for _, output := range []string{filepath.Join(root, "result.json"), filepath.Join(root, ".launcher", "install-plan.json"), root} {
		if err := rejectFactoryOutputPath0271(root, output); err == nil {
			t.Fatalf("unsafe --output allowed: %s", output)
		}
	}
	if err := rejectFactoryOutputPath0271(root, filepath.Join(t.TempDir(), "result.json")); err != nil {
		t.Fatal(err)
	}
}
