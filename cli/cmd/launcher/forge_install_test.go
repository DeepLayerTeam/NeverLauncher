package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// Forge must not fetch incompatible library coordinates while creating a
// target-specific client; irrelevant entries remain in its launch profile.
func TestForgeNeoForgeLibrariesOnlyForSelectedTargets0404(t *testing.T) {
	for _, loader := range []string{"forge", "neoforge"} {
		t.Run(loader, func(t *testing.T) {
			payload := []byte("targeted-java-library")
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/linux.jar" {
					http.Error(w, "unexpected platform request", http.StatusNotFound)
					return
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			libs := []MojangLibrary{
				{Name: "example:os-specific:1.0", Rules: []map[string]any{{"action": "allow", "os": map[string]any{"name": "windows"}}}, Downloads: MojangLibraryDownloads{Artifact: MojangDownload{URL: server.URL + "/windows.jar", SHA1: sha1HexLocal(payload)}}},
				{Name: "example:linux-specific:1.0", Rules: []map[string]any{{"action": "allow", "os": map[string]any{"name": "linux"}}}, Downloads: MojangLibraryDownloads{Artifact: MojangDownload{URL: server.URL + "/linux.jar", SHA1: sha1HexLocal(payload)}}},
				{Name: "example:classifier:1.0:natives-windows", Downloads: MojangLibraryDownloads{Artifact: MojangDownload{URL: server.URL + "/windows-native.jar", SHA1: sha1HexLocal(payload)}}},
			}
			dir := t.TempDir()
			files, err := materializeForgeLibraries(context.Background(), server.Client(), dir, &libs, loader, 3, true, vanillaTarget{OS: "linux", Arch: "x86_64"})
			if err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 || len(files) != 1 || !strings.Contains(files[0].Path, "linux-specific") {
				t.Fatalf("wrong target downloads: requests=%d files=%+v", requests.Load(), files)
			}
			if libs[0].Name != "example:os-specific:1.0" || libs[2].Name != "example:classifier:1.0:natives-windows" {
				t.Fatal("must preserve non-applicable metadata")
			}
			for _, rel := range []string{"libraries/example/os-specific/1.0/os-specific-1.0.jar", "libraries/example/classifier/1.0/classifier-1.0-natives-windows.jar"} {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); !os.IsNotExist(err) {
					t.Fatalf("unselected library downloaded: %s (%v)", rel, err)
				}
			}
		})
	}
}

func TestForgeLibraryRejectsMavenArtifactSubstitution0404(t *testing.T) {
	libraries := []MojangLibrary{{Name: "example:real:1.0", Downloads: MojangLibraryDownloads{Artifact: MojangDownload{Path: "example/other/1.0/other-1.0.jar", URL: "https://example.org/other.jar", SHA1: strings.Repeat("a", 40)}}}}
	if _, err := materializeForgeLibraries(context.Background(), nil, t.TempDir(), &libraries, "forge", 2, true); err == nil || !strings.Contains(err.Error(), "Maven identity") {
		t.Fatalf("incorrect artifact path accepted: %v", err)
	}
	// Irrelevant incompatible entry must not make a Linux-only install fail.
	libraries[0].Rules = []map[string]any{{"action": "allow", "os": map[string]any{"name": "windows"}}}
	if files, err := materializeForgeLibraries(context.Background(), nil, t.TempDir(), &libraries, "forge", 2, true, vanillaTarget{OS: "linux", Arch: "x86_64"}); err != nil || len(files) != 0 {
		t.Fatalf("irrelevant Windows artifact should be skipped: %v %+v", err, files)
	}
}

func javaBase64Encode0404(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func makeForgeTestJar0404(t *testing.T, className, source string, withMainManifest bool) []byte {
	t.Helper()
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("JDK javac unavailable")
	}
	work := t.TempDir()
	name := filepath.Join(work, filepath.FromSlash(strings.ReplaceAll(className, ".", "/"))+".java")
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("javac", "-d", work, name)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("javac: %s: %v", output, err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if withMainManifest {
		w, err := zw.Create("META-INF/MANIFEST.MF")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(w, "Manifest-Version: 1.0\r\nMain-Class: %s\r\n\r\n", className)
	}
	classPath := strings.ReplaceAll(className, ".", "/") + ".class"
	data, err := os.ReadFile(filepath.Join(work, filepath.FromSlash(classPath)))
	if err != nil {
		t.Fatal(err)
	}
	w, err := zw.Create(classPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Exercise a modern Forge/NeoForge installer with a real JVM processor and
// actual Java class loading, not a shell stand-in for the processor command.
// The Minecraft base/loader entrypoint here are deterministic fixtures, not Mojang binaries.
func TestForgeNeoForgeInstallerRunsRealJVMProcessorAndPatchedClasspath0404(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses the OS java executable; CI JVM target varies")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("java unavailable")
	}
	generated := makeForgeTestJar0404(t, "cpw.mods.bootstraplauncher.BootstrapLauncher", `package cpw.mods.bootstraplauncher; public class BootstrapLauncher { public static void main(String[] args) { System.out.println("LOADER_STARTED " + String.join(" ", args)); } }`, false)
	// Processor transforms the installer patch input into a verified runtime JAR.
	importBase64 := "java.util.Base64.getDecoder().decode(\"" + javaBase64Encode0404(generated) + "\")"
	source := `import java.nio.file.*; public class PatchProcessor { public static void main(String[] args) throws Exception { Path patch=null,out=null; for (int i=0;i<args.length;i++) { if (args[i].equals("--patch")) patch=Path.of(args[++i]); else if(args[i].equals("--out")) out=Path.of(args[++i]); } if(patch==null||out==null||!Files.readString(patch).equals("binary-patch-fixture")) throw new IllegalStateException("patch input missing or corrupt"); Files.createDirectories(out.getParent()); Files.write(out, ` + importBase64 + `); } }`
	processorJar := makeForgeTestJar0404(t, "PatchProcessor", source, true)
	for _, loader := range []string{"forge", "neoforge"} {
		t.Run(loader, func(t *testing.T) {
			minecraft := "1.21.1"
			loaderVersion := "52.0.1"
			if loader == "neoforge" {
				loaderVersion = "21.1.105"
			}
			clientJar := []byte("minecraft-base-fixture")
			asset := []byte("fixture-asset")
			assetHash := sha1HexLocal(asset)
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			idx, _ := json.Marshal(map[string]any{"objects": map[string]any{"test.txt": map[string]any{"hash": assetHash, "size": len(asset)}}})
			v, _ := json.Marshal(map[string]any{"id": minecraft, "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": "test-assets", "assetIndex": map[string]any{"id": "test-assets", "url": server.URL + "/index.json", "sha1": sha1HexLocal(idx), "size": len(idx)}, "downloads": map[string]any{"client": map[string]any{"url": server.URL + "/client.jar", "sha1": sha1HexLocal(clientJar), "size": len(clientJar)}}, "javaVersion": map[string]any{"majorVersion": 21}, "libraries": []any{}, "arguments": map[string]any{"game": []any{"--demo"}}})
			manifest, _ := json.Marshal(MojangVersionManifest{Latest: map[string]string{"release": minecraft}, Versions: []MojangManifestVersion{{ID: minecraft, Type: "release", URL: server.URL + "/version.json", SHA1: sha1HexLocal(v)}}})
			installer := testForgeInstaller(t, loader, minecraft, loaderVersion, generated, processorJar)
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifest) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(v) })
			mux.HandleFunc("/index.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(idx) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
			mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(asset) })
			mux.HandleFunc("/installer.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(installer) })
			mux.HandleFunc("/installer.jar.sha1", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, sha1HexLocal(installer)) })
			clientDir := t.TempDir()
			res, err := installForgeLike(context.Background(), forgeMaterializeOptions{Loader: loader, MinecraftVersion: minecraft, LoaderVersion: loaderVersion, ClientDir: clientDir, JavaExecutable: java, InstallerURL: server.URL + "/installer.jar", VersionManifest: server.URL + "/manifest.json", AssetBaseURL: server.URL + "/assets", LibraryBaseURL: server.URL + "/libraries", Targets: []vanillaTarget{{OS: "linux", Arch: "x86_64"}}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if res.ProcessorRan != 1 || res.ProfilePath == "" {
				t.Fatalf("processor did not execute: %+v", res)
			}
			generatedPath := filepath.Join(clientDir, "libraries", "com", "example", "generated", "1.0", "generated-1.0.jar")
			run := exec.Command(java, "-cp", generatedPath, "cpw.mods.bootstraplauncher.BootstrapLauncher", "--launchTarget", loader+"client")
			output, err := run.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "LOADER_STARTED --launchTarget "+loader+"client") {
				t.Fatalf("generated classpath cannot execute: %v %s", err, output)
			}
		})
	}
}
