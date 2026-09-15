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
	"runtime"
	"strings"
	"testing"
)

func TestForgeAndNeoForgeProcessorMaterializers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture Java executable uses POSIX shell; production implementation is cross-platform")
	}
	for _, loader := range []string{"forge", "neoforge"} {
		t.Run(loader, func(t *testing.T) {
			clientJar := []byte("minecraft-client")
			asset := []byte("minecraft-asset")
			assetHash := sha1HexLocal(asset)
			generated := []byte("generated-runtime-jar")
			processorJar := testProcessorJar(t)

			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			base := server.URL

			assetIndex := map[string]any{"objects": map[string]any{"test.txt": map[string]any{"hash": assetHash, "size": len(asset)}}}
			assetIndexBytes, _ := json.Marshal(assetIndex)
			vanillaVersion := map[string]any{
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
			vanillaVersionBytes, _ := json.Marshal(vanillaVersion)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": "test-vanilla"}, Versions: []MojangManifestVersion{{ID: "test-vanilla", Type: "release", URL: base + "/version.json", SHA1: sha1HexLocal(vanillaVersionBytes)}}}
			manifestBytes, _ := json.Marshal(manifest)

			installer := testForgeInstaller(t, loader, generated, processorJar)
			installerSHA1 := sha1HexLocal(installer)
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(vanillaVersionBytes) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
			mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })
			mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(asset) })
			mux.HandleFunc("/installer.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(installer) })
			mux.HandleFunc("/installer.jar.sha1", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, installerSHA1) })

			javaPath := testFakeJava(t, generated)
			dir := t.TempDir()
			result, err := installForgeLike(context.Background(), forgeMaterializeOptions{
				Loader: loader, MinecraftVersion: "latest-release", LoaderVersion: "1.0.0", ClientDir: dir,
				JavaExecutable: javaPath, InstallerURL: base + "/installer.jar", VersionManifest: base + "/manifest.json",
				AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries", Targets: []vanillaTarget{currentVanillaTarget()},
				Workers: 3, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "installed-and-verified" || result.Loader != loader || result.ProcessorRan != 1 || result.ProcessorSkipped != 0 {
				t.Fatalf("unexpected result: %+v", result)
			}
			generatedRel, err := mavenCoordinatePath("com.example:generated:1.0")
			if err != nil {
				t.Fatal(err)
			}
			for _, rel := range []string{
				"versions/test-vanilla/test-vanilla.jar",
				result.ProfilePath,
				"libraries/com/example/processor/1.0/processor-1.0.jar",
				"libraries/" + generatedRel,
			} {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatalf("missing %s: %v", rel, err)
				}
			}
			gotGenerated, err := os.ReadFile(filepath.Join(dir, "libraries", filepath.FromSlash(generatedRel)))
			if err != nil || !bytes.Equal(gotGenerated, generated) {
				t.Fatalf("processor output mismatch: %q %v", gotGenerated, err)
			}

			// Idempotency: verified processor output must skip the expensive processor on the next run.
			second, err := installForgeLike(context.Background(), forgeMaterializeOptions{
				Loader: loader, MinecraftVersion: "test-vanilla", LoaderVersion: "1.0.0", ClientDir: dir,
				JavaExecutable: javaPath, InstallerURL: base + "/installer.jar", InstallerSHA1: installerSHA1,
				VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries",
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if second.ProcessorSkipped != 1 || second.ProcessorRan != 0 {
				t.Fatalf("expected processor cache hit: %+v", second)
			}

			packagePath := filepath.Join(t.TempDir(), "package.json")
			args := []string{
				"--minecraft", "test-vanilla", "--loader-version", "1.0.0", "--client-dir", dir, "--java", javaPath,
				"--installer-url", base + "/installer.jar", "--installer-sha1", installerSHA1,
				"--version-manifest", base + "/manifest.json", "--asset-base-url", base + "/assets", "--library-base-url", base + "/libraries",
				"--target", currentVanillaTarget().OS + "/" + currentVanillaTarget().Arch,
				"--project", "test-project", "--profile", loader, "--channel", "stable", "--version", "1.0.0", "--output", packagePath,
			}
			if err := handleRuntimeForgeLikePackage(loader, args); err != nil {
				t.Fatalf("%s-package failed: %v", loader, err)
			}
			pkg, err := readClientPackageManifest(packagePath)
			if err != nil {
				t.Fatal(err)
			}
			seenProfile, seenGenerated := false, false
			for _, file := range pkg.Files {
				if strings.HasPrefix(file.Path, ".neverlauncher/") {
					t.Fatalf("local installer state leaked into package: %s", file.Path)
				}
				seenProfile = seenProfile || file.Path == result.ProfilePath
				seenGenerated = seenGenerated || file.Path == "libraries/"+generatedRel
			}
			if !seenProfile || !seenGenerated {
				t.Fatalf("package missing Forge/NeoForge artifacts: profile=%v generated=%v", seenProfile, seenGenerated)
			}
		})
	}
}

func TestForgeNeoForgeMavenVersionSelection(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	forgeMetadata := `<metadata><versioning><versions><version>1.20.1-47.3.0</version><version>1.20.1-47.4.0</version><version>1.21.1-52.0.1</version></versions></versioning></metadata>`
	neoMetadata := `<metadata><versioning><versions><version>21.1.100-beta</version><version>21.1.105</version><version>21.4.20</version></versions></versioning></metadata>`
	mux.HandleFunc("/forge.xml", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, forgeMetadata) })
	mux.HandleFunc("/neo.xml", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, neoMetadata) })

	loaderVersion, artifactVersion, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "forge", "1.20.1", "latest-stable", server.URL+"/forge.xml")
	if err != nil || loaderVersion != "47.4.0" || artifactVersion != "1.20.1-47.4.0" {
		t.Fatalf("forge selection: %q %q %v", loaderVersion, artifactVersion, err)
	}
	loaderVersion, artifactVersion, _, err = resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "latest-stable", server.URL+"/neo.xml")
	if err != nil || loaderVersion != "21.1.105" || artifactVersion != "21.1.105" {
		t.Fatalf("neoforge selection: %q %q %v", loaderVersion, artifactVersion, err)
	}
	if _, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.20.1", "latest-stable", server.URL+"/neo.xml"); err == nil {
		t.Fatal("incompatible NeoForge/Minecraft pair accepted")
	}
}

func TestInstallerArchiveSecurityAndCoordinateParsing(t *testing.T) {
	if got, err := mavenCoordinatePath("net.minecraftforge:installertools:1.4.1:fatjar@jar"); err != nil || got != "net/minecraftforge/installertools/1.4.1/installertools-1.4.1-fatjar.jar" {
		t.Fatalf("unexpected Maven path: %q %v", got, err)
	}
	if got, err := mavenCoordinatePath("de.oceanlabs.mcp:mcp_config:1.20.1:mappings@txt"); err != nil || !strings.HasSuffix(got, "mcp_config-1.20.1-mappings.txt") {
		t.Fatalf("unexpected extended Maven path: %q %v", got, err)
	}
	if _, err := safeArchiveRelative("../escape"); err == nil {
		t.Fatal("installer archive traversal accepted")
	}
	if !neoForgeVersionMatchesMinecraft("21.1.105", "1.21.1") || neoForgeVersionMatchesMinecraft("21.4.20", "1.21.1") {
		t.Fatal("NeoForge Minecraft compatibility mapping incorrect")
	}
}

func testProcessorJar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifest, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = manifest.Write([]byte("Manifest-Version: 1.0\nMain-Class: com.example.Processor\n\n"))
	payload, err := zw.Create("com/example/Processor.class")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = payload.Write([]byte("fixture-bytecode-placeholder"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testForgeInstaller(t *testing.T, loader string, generated, processorJar []byte) []byte {
	t.Helper()
	profileID := "test-vanilla-" + loader + "-1.0.0"
	profile := map[string]any{
		"spec": 0, "profile": "com.example:" + loader + ":1.0.0", "version": profileID, "json": "/version.json", "minecraft": "test-vanilla",
		"data": map[string]any{
			"OUT":      map[string]any{"client": "[com.example:generated:1.0]", "server": ""},
			"OUT_SHA":  map[string]any{"client": "'" + sha1HexLocal(generated) + "'", "server": ""},
			"BINPATCH": map[string]any{"client": "/data/client.lzma", "server": "/data/server.lzma"},
		},
		"processors": []any{map[string]any{
			"sides": []any{"client"}, "jar": "com.example:processor:1.0", "classpath": []any{},
			"args": []any{"--patch", "{BINPATCH}", "--out", "{OUT}"}, "outputs": map[string]any{"{OUT}": "{OUT_SHA}"},
		}},
		"libraries": []any{map[string]any{"name": "com.example:processor:1.0"}},
	}
	versionProfile := map[string]any{
		"id": profileID, "inheritsFrom": "test-vanilla", "type": "release", "mainClass": "cpw.mods.bootstraplauncher.BootstrapLauncher",
		"arguments": map[string]any{"game": []any{"--launchTarget", "forgeclient"}, "jvm": []any{"-D" + loader + ".fixture=true"}},
		"libraries": []any{map[string]any{"name": "com.example:generated:1.0"}},
	}
	profileBytes, _ := json.Marshal(profile)
	versionBytes, _ := json.Marshal(versionProfile)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		"install_profile.json": profileBytes,
		"version.json":         versionBytes,
		"maven/com/example/processor/1.0/processor-1.0.jar": processorJar,
		"data/client.lzma": []byte("binary-patch-fixture"),
	} {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testFakeJava(t *testing.T, output []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "java-fixture")
	script := `#!/bin/sh
if [ "$1" = "-version" ]; then
  echo 'openjdk version "21.0.11" 2026-04-21' >&2
  exit 0
fi
previous=""
for argument in "$@"; do
  if [ "$previous" = "--out" ]; then
    mkdir -p "$(dirname "$argument")"
    printf '%s' 'OUTPUT_PLACEHOLDER' > "$argument"
    exit 0
  fi
  previous="$argument"
done
echo "missing --out" >&2
exit 17
`
	script = strings.Replace(script, "OUTPUT_PLACEHOLDER", string(output), 1)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
