package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Build a full, verified client via a single workspace operation: download a
// pinned Modrinth pack, install a local mod and Maven JAR, register classpath,
// apply authentication mode and publish the resulting client.
func TestMirrorWorkspace0405ModpackLibrariesAuthlibAndRollback(t *testing.T) {
	modBytes := []byte("mirror-workspace-modrinth-mod")
	modHash512 := sha512.Sum512(modBytes)
	server := fixtureModpackServer0275(t, modBytes)
	defer server.Close()
	index := map[string]any{
		"formatVersion": 1, "game": "minecraft", "versionId": "1.0", "name": "Workspace Pack",
		"dependencies": map[string]string{"minecraft": "fixture-1"},
		"files": []any{map[string]any{
			"path": "mods/remote.jar", "hashes": map[string]string{
				"sha1": sha1hex(modBytes), "sha512": hex.EncodeToString(modHash512[:]),
			}, "downloads": []string{server.URL + "/mod.jar"}, "fileSize": len(modBytes),
		}},
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	archive := packFixtureZip0275(t, map[string][]byte{
		"modrinth.index.json": raw, "overrides/config/workspace.properties": []byte("from=modpack"),
	})
	folder := t.TempDir()
	packCopy := filepath.Join(folder, "input.mrpack")
	zipData, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packCopy, zipData, 0600); err != nil {
		t.Fatal(err)
	}
	extraBytes := []byte("workspace-extra-mod")
	if err := os.WriteFile(filepath.Join(folder, "extra.jar"), extraBytes, 0600); err != nil {
		t.Fatal(err)
	}
	libraryBytes := mirrorZip0274(t, []string{"example/Library.class"}, []string{"verified-bytecode"})
	if err := os.WriteFile(filepath.Join(folder, "library.jar"), libraryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	compatRaw, _ := json.Marshal(compatRequest0279{SchemaVersion: compatSchema0279, AuthMode: "offline"})
	if err := os.WriteFile(filepath.Join(folder, "authlib.json"), compatRaw, 0600); err != nil {
		t.Fatal(err)
	}
	ws := mirrorWorkspace0274{
		SchemaVersion: "launcher.mirror-workspace.v1", Minecraft: "fixture-1", Loader: "vanilla", Modpack: "input.mrpack",
		Mods:          []mirrorArtifact0274{{Path: "mods/extra.jar", File: "extra.jar", SHA256: mirrorSHA0274(extraBytes)}},
		Libraries:     []mirrorWorkspaceLibrary0405{{Coordinate: "example:library:1.0", File: "library.jar", SHA256: mirrorSHA0274(libraryBytes)}},
		Compatibility: "authlib.json",
	}
	writeWS := func() string {
		t.Helper()
		data, e := json.Marshal(ws)
		if e != nil {
			t.Fatal(e)
		}
		name := filepath.Join(folder, "workspace.json")
		if e = os.WriteFile(name, data, 0600); e != nil {
			t.Fatal(e)
		}
		return name
	}
	workspaceFile := writeWS()
	args := func(target string) []string {
		return []string{"apply-workspace", "--file", workspaceFile, "--client-dir", target,
			"--version-manifest", server.URL + "/manifest.json", "--asset-base-url", server.URL + "/assets"}
	}
	target := filepath.Join(folder, "nested", "published-client")
	if err := handleRuntimeMirror0274(args(target)); err != nil {
		t.Fatal(err)
	}
	plan, err := readFactoryPlan0271(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(target, plan); err != nil {
		t.Fatal(err)
	}
	if plan.Compatibility == nil || plan.Compatibility.AuthMode != "offline" {
		t.Fatal("authentication compatibility not present in published plan")
	}
	for rel, expected := range map[string]string{
		"mods/remote.jar": mirrorSHA0274(modBytes),
		"mods/extra.jar":  mirrorSHA0274(extraBytes),
		"libraries/example/library/1.0/library-1.0.jar": mirrorSHA0274(libraryBytes),
	} {
		if _, err := mirrorCheckedHash0274(filepath.Join(target, filepath.FromSlash(rel)), expected); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(filepath.Join(target, "config/workspace.properties"))
	if err != nil || string(content) != "from=modpack" {
		t.Fatalf("modpack override not delivered: %s (%v)", content, err)
	}
	profile, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(plan.Launch.ProfilePath)))
	if err != nil || !strings.Contains(string(profile), `"name": "example:library:1.0"`) {
		t.Fatalf("Maven library is missing from runtime profile: %v", err)
	}
	if err := handleRuntimeMirror0274(args(target)); err == nil {
		t.Fatal("existing verified client must not be silently overwritten")
	}

	// A wrong hash must not leave a partially published target.
	ws.Mods[0].SHA256 = strings.Repeat("0", 64)
	writeWS()
	broken := filepath.Join(folder, "nested", "broken-client")
	if err := handleRuntimeMirror0274(args(broken)); err == nil {
		t.Fatal("tampered mod accepted")
	}
	if _, err := os.Lstat(broken); !os.IsNotExist(err) {
		t.Fatalf("failed transaction created target: %v", err)
	}
	// The pack's pinned loader cannot be silently replaced by workspace metadata.
	ws.Mods[0].SHA256 = mirrorSHA0274(extraBytes)
	ws.Minecraft = "some-other-minecraft"
	writeWS()
	mismatch := filepath.Join(folder, "nested", "wrong-version")
	if err := handleRuntimeMirror0274(args(mismatch)); err == nil {
		t.Fatal("pack/workspace version mismatch accepted")
	}
	if _, err := os.Lstat(mismatch); !os.IsNotExist(err) {
		t.Fatalf("mismatched client published: %v", err)
	}
}

func TestMirrorWorkspace0405AuthlibPatchDeliveredAndVerified(t *testing.T) {
	s := fixtureModpackServer0275(t, nil)
	defer s.Close()
	folder := t.TempDir()
	base := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "LICENSE"}, []string{"base", "license"})
	patch := mirrorZip0274(t, []string{"com/mojang/authlib/A.class"}, []string{"patched"})
	result := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "LICENSE"}, []string{"patched", "license"})
	for name, content := range map[string][]byte{"base.jar": base, "patch.jar": patch} {
		if err := os.WriteFile(filepath.Join(folder, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ws := mirrorWorkspace0274{
		SchemaVersion: "launcher.mirror-workspace.v1", Minecraft: "fixture-1", Loader: "vanilla",
		Libraries: []mirrorWorkspaceLibrary0405{{Coordinate: "com.mojang:authlib:4.0", File: "base.jar", SHA256: mirrorSHA0274(base)}},
		AuthlibPatches: []mirrorWorkspaceAuthlibPatch0405{{
			Target: "libraries/com/mojang/authlib/4.0/authlib-4.0.jar", Patch: "patch.jar",
			BaseSHA256: mirrorSHA0274(base), PatchSHA256: mirrorSHA0274(patch), ExpectedSHA256: mirrorSHA0274(result),
		}},
	}
	data, _ := json.Marshal(ws)
	workspaceFile := filepath.Join(folder, "workspace.json")
	if err := os.WriteFile(workspaceFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(folder, "client")
	if err := handleRuntimeMirror0274([]string{"apply-workspace", "--file", workspaceFile, "--client-dir", dst,
		"--version-manifest", s.URL + "/manifest.json", "--asset-base-url", s.URL + "/assets"}); err != nil {
		t.Fatal(err)
	}
	p, err := readFactoryPlan0271(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(dst, p); err != nil {
		t.Fatal(err)
	}
	if _, err := mirrorCheckedHash0274(filepath.Join(dst, "libraries/com/mojang/authlib/4.0/authlib-4.0.jar"), mirrorSHA0274(result)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "libraries/com/mojang/authlib/4.0/authlib-4.0.jar"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(dst, p); err == nil {
		t.Fatal("corrupt transformed authlib was not rejected")
	}
}

// A Maven dependency registered by a workspace is loaded by a real Java VM
// from the installed client tree, not merely written to an InstallPlan.
func TestMirrorWorkspace0405RegisteredLibraryRunsOnJVM(t *testing.T) {
	for _, program := range []string{"javac", "jar", "java"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Skipf("Java toolchain unavailable: %s", program)
		}
	}
	s := fixtureModpackServer0275(t, nil)
	defer s.Close()
	folder := t.TempDir()
	javaSource := filepath.Join(folder, "Main.java")
	if err := os.WriteFile(javaSource, []byte("package workspace; public class Main { public static void main(String[] args) { System.out.print(\"workspace-0405-ok\"); } }"), 0600); err != nil {
		t.Fatal(err)
	}
	classes := filepath.Join(folder, "classes")
	if err := os.Mkdir(classes, 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("javac", "-d", classes, javaSource).CombinedOutput(); err != nil {
		t.Fatalf("javac failed: %s: %v", output, err)
	}
	library := filepath.Join(folder, "workspace-library.jar")
	if output, err := exec.Command("jar", "cf", library, "-C", classes, ".").CombinedOutput(); err != nil {
		t.Fatalf("jar failed: %s: %v", output, err)
	}
	sha, _, err := hashFile(library)
	if err != nil {
		t.Fatal(err)
	}
	ws := mirrorWorkspace0274{
		SchemaVersion: "launcher.mirror-workspace.v1", Minecraft: "fixture-1", Loader: "vanilla",
		Libraries: []mirrorWorkspaceLibrary0405{{Coordinate: "workspace:fixture:1.0", File: "workspace-library.jar", SHA256: sha}},
	}
	data, _ := json.Marshal(ws)
	wsFile := filepath.Join(folder, "workspace.json")
	if err := os.WriteFile(wsFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(folder, "installed")
	if err := handleRuntimeMirror0274([]string{"apply-workspace", "--file", wsFile, "--client-dir", target,
		"--version-manifest", s.URL + "/manifest.json", "--asset-base-url", s.URL + "/assets", "--output", filepath.Join(folder, "result.json")}); err != nil {
		t.Fatal(err)
	}
	plan, err := readFactoryPlan0271(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(target, plan); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(target, "libraries/workspace/fixture/1.0/fixture-1.0.jar")
	output, err := exec.Command("java", "-cp", installed, "workspace.Main").CombinedOutput()
	if err != nil || string(output) != "workspace-0405-ok" {
		t.Fatalf("registered Java library does not execute: %s: %v", output, err)
	}
}

// A CurseForge pack containing only redistributable ZIP overrides requires
// no CurseForge credential: no API lookup is necessary for those actual bytes.
func TestMirrorWorkspace0405CurseOverridesWithoutAPIKey(t *testing.T) {
	s := fixtureModpackServer0275(t, nil)
	defer s.Close()
	index := map[string]any{
		"manifestVersion": 1, "manifestType": "minecraftModpack", "name": "Overrides Only", "version": "1.0",
		"minecraft": map[string]any{"version": "fixture-1", "modLoaders": []any{}},
		"files":     []any{}, "overrides": "overrides",
	}
	metadata, _ := json.Marshal(index)
	pack := packFixtureZip0275(t, map[string][]byte{"manifest.json": metadata, "overrides/config/installed.toml": []byte("enabled=true")})
	folder := t.TempDir()
	contents, err := os.ReadFile(pack)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "pack.zip"), contents, 0600); err != nil {
		t.Fatal(err)
	}
	workspace := mirrorWorkspace0274{SchemaVersion: "launcher.mirror-workspace.v1", Minecraft: "fixture-1", Loader: "vanilla", Modpack: "pack.zip"}
	wsBytes, _ := json.Marshal(workspace)
	wsFile := filepath.Join(folder, "workspace.json")
	if err := os.WriteFile(wsFile, wsBytes, 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(folder, "client")
	if err := handleRuntimeMirror0274([]string{"apply-workspace", "--file", wsFile, "--client-dir", dst,
		"--version-manifest", s.URL + "/manifest.json", "--asset-base-url", s.URL + "/assets", "--output", filepath.Join(folder, "report.json")}); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(filepath.Join(dst, "config/installed.toml"))
	if err != nil || string(bytes) != "enabled=true" {
		t.Fatalf("CurseForge overrides not installed: %s, %v", bytes, err)
	}
	plan, err := readFactoryPlan0271(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(dst, plan); err != nil {
		t.Fatal(err)
	}
}
