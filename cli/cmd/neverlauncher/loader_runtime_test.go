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
	"path/filepath"
	"strings"
	"testing"
)

func TestFabricAndQuiltMaterializersProduceConsumableClientTree(t *testing.T) {
	for _, tc := range []struct {
		loader        string
		loaderVersion string
		mainClass     string
		coordinate    string
	}{
		{loader: "fabric", loaderVersion: "0.16.10", mainClass: "net.fabricmc.loader.impl.launch.knot.KnotClient", coordinate: "net.fabricmc:fabric-loader:0.16.10"},
		{loader: "quilt", loaderVersion: "0.27.1", mainClass: "org.quiltmc.loader.impl.launch.knot.KnotClient", coordinate: "org.quiltmc:quilt-loader:0.27.1"},
	} {
		t.Run(tc.loader, func(t *testing.T) {
			clientJar := []byte("minecraft-client")
			asset := []byte("minecraft-asset")
			assetHash := sha1HexLocal(asset)
			loaderJar := []byte(tc.loader + "-loader-jar")
			loaderSHA1 := sha1HexLocal(loaderJar)

			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			base := server.URL

			assetIndex := map[string]any{"objects": map[string]any{"test.txt": map[string]any{"hash": assetHash, "size": len(asset)}}}
			assetIndexBytes, _ := json.Marshal(assetIndex)
			version := map[string]any{
				"id": "test-vanilla", "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": "test-assets",
				"assetIndex":  map[string]any{"id": "test-assets", "url": base + "/asset-index.json", "sha1": sha1HexLocal(assetIndexBytes), "size": len(assetIndexBytes)},
				"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1HexLocal(clientJar), "size": len(clientJar)}},
				"javaVersion": map[string]any{"majorVersion": 21},
				"arguments": map[string]any{
					"jvm":  []any{"-Djava.library.path=${natives_directory}", "-cp", "${classpath}"},
					"game": []any{"--username", "${auth_player_name}", "--version", "${version_name}"},
				},
				"libraries": []any{},
			}
			versionBytes, _ := json.Marshal(version)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": "test-vanilla"}, Versions: []MojangManifestVersion{{ID: "test-vanilla", Type: "release", URL: base + "/version.json", SHA1: sha1HexLocal(versionBytes)}}}
			manifestBytes, _ := json.Marshal(manifest)

			metaBase := base + "/" + tc.loader + "/meta"
			profileID := tc.loader + "-loader-" + tc.loaderVersion + "-test-vanilla"
			profile := map[string]any{
				"id": profileID, "inheritsFrom": "test-vanilla", "type": "release", "mainClass": tc.mainClass,
				"arguments": map[string]any{"game": []any{"--" + tc.loader + ".test", "true"}, "jvm": []any{"-Dneverloader=" + tc.loader}},
				"libraries": []any{map[string]any{"name": tc.coordinate, "url": base + "/maven"}},
			}
			profileBytes, _ := json.Marshal(profile)
			loaderListBytes, _ := json.Marshal([]any{map[string]any{"loader": map[string]any{"version": tc.loaderVersion, "stable": true, "maven": tc.coordinate}}})
			mavenPath, err := strictMavenPath(tc.coordinate)
			if err != nil {
				t.Fatal(err)
			}

			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(versionBytes) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
			mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })
			mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(asset) })
			mux.HandleFunc("/"+tc.loader+"/meta/versions/loader/test-vanilla", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(loaderListBytes) })
			mux.HandleFunc("/"+tc.loader+"/meta/versions/loader/test-vanilla/"+tc.loaderVersion+"/profile/json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(profileBytes) })
			mux.HandleFunc("/maven/"+mavenPath, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(loaderJar) })
			mux.HandleFunc("/maven/"+mavenPath+".sha1", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, loaderSHA1) })

			dir := t.TempDir()
			result, err := installMetaLoader(context.Background(), loaderMaterializeOptions{
				Loader: tc.loader, MinecraftVersion: "latest-release", LoaderVersion: "latest-stable", ClientDir: dir,
				VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries", MetaBaseURL: metaBase,
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 3, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "installed-and-verified" || result.LoaderVersion != tc.loaderVersion || result.MainClass != tc.mainClass {
				t.Fatalf("unexpected result: %+v", result)
			}
			for _, rel := range []string{
				"versions/test-vanilla/test-vanilla.json",
				"versions/test-vanilla/test-vanilla.jar",
				"versions/" + profileID + "/" + profileID + ".json",
				"libraries/" + mavenPath,
			} {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatalf("missing %s: %v", rel, err)
				}
			}
			profileDisk, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(result.ProfilePath)))
			if err != nil {
				t.Fatal(err)
			}
			var resolved loaderVersionProfile
			if err := json.Unmarshal(profileDisk, &resolved); err != nil {
				t.Fatal(err)
			}
			artifact := resolved.Libraries[0].Downloads.Artifact
			if artifact.SHA1 != loaderSHA1 || artifact.Size != int64(len(loaderJar)) || artifact.URL == "" {
				t.Fatalf("loader artifact was not pinned into profile: %+v", artifact)
			}

			packageManifest := filepath.Join(t.TempDir(), "package.json")
			args := []string{
				"--minecraft", "test-vanilla", "--loader-version", tc.loaderVersion, "--client-dir", dir,
				"--version-manifest", base + "/manifest.json", "--asset-base-url", base + "/assets", "--library-base-url", base + "/libraries",
				"--meta-base-url", metaBase, "--target", currentVanillaTarget().OS + "/" + currentVanillaTarget().Arch,
				"--project", "test-project", "--profile", tc.loader, "--channel", "stable", "--version", "1.0.0", "--output", packageManifest,
			}
			if err := handleRuntimeLoaderPackage(tc.loader, args); err != nil {
				t.Fatalf("%s-package failed: %v", tc.loader, err)
			}
			pkg, err := readClientPackageManifest(packageManifest)
			if err != nil {
				t.Fatal(err)
			}
			seenProfile, seenLoaderJar := false, false
			for _, file := range pkg.Files {
				if strings.HasPrefix(file.Path, ".neverlauncher/") {
					t.Fatalf("local loader state leaked into package: %s", file.Path)
				}
				seenProfile = seenProfile || file.Path == result.ProfilePath
				seenLoaderJar = seenLoaderJar || file.Path == "libraries/"+mavenPath
			}
			if !seenProfile || !seenLoaderJar {
				t.Fatalf("package missing loader runtime artifacts: profile=%v loaderJar=%v", seenProfile, seenLoaderJar)
			}
			raw, err := os.ReadFile(packageManifest)
			if err != nil {
				t.Fatal(err)
			}
			var wrapper map[string]any
			if err := json.Unmarshal(raw, &wrapper); err != nil {
				t.Fatal(err)
			}
			settings := wrapper["manifestSettings"].(map[string]any)
			minecraft := settings["minecraft"].(map[string]any)
			if minecraft["loader"] != tc.loader || minecraft["loaderVersion"] != tc.loaderVersion {
				t.Fatalf("incorrect manifest settings: %+v", minecraft)
			}
		})
	}
}

func TestLoaderVersionSelectionAndMavenValidation(t *testing.T) {
	if _, err := strictMavenPath("broken"); err == nil {
		t.Fatal("invalid Maven coordinate accepted")
	}
	if got, err := strictMavenPath("net.fabricmc:fabric-loader:0.16.10"); err != nil || got != "net/fabricmc/fabric-loader/0.16.10/fabric-loader-0.16.10.jar" {
		t.Fatalf("unexpected maven path: %q %v", got, err)
	}
	if parseSHA1Sidecar("not-a-sha") != "" {
		t.Fatal("invalid sidecar accepted")
	}
	if parseSHA1Sidecar(strings.Repeat("a", 40)+"  file.jar") != strings.Repeat("a", 40) {
		t.Fatal("valid sidecar was not parsed")
	}
}

func sha1HexLocal(data []byte) string {
	h := sha1.Sum(data)
	return hex.EncodeToString(h[:])
}
