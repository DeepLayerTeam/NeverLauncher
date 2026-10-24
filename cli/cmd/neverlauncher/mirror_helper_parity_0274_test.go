package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func mirrorSHA0274(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func mirrorMinimalClient0274(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "client")
	if err := os.MkdirAll(filepath.Join(root, "versions", "1.21.1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "versions", "1.21.1", "1.21.1.json"), []byte(`{"mainClass":"net.minecraft.client.main.Main"}`), 0644); err != nil {
		t.Fatal(err)
	}
	outputs, err := scanFactoryOutputs0271(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := factoryPlan0271{SchemaVersion: factoryPlanSchema0271, MinecraftVersion: "1.21.1", Loader: "vanilla", Targets: []vanillaTarget{{OS: "linux", Arch: "x64"}}, Java: factoryJava0271{Major: 21}, Launch: factoryLaunch0271{MainClass: "net.minecraft.client.main.Main", ProfilePath: "versions/1.21.1/1.21.1.json"}, Steps: factorySteps0271("vanilla"), Sources: []factorySource0271{{Path: "versions/1.21.1/1.21.1.json", Kind: "metadata", URL: "https://example.com/1.21.1.json", SHA256: outputs[0].SHA256, Size: outputs[0].Size}}, Outputs: outputs}
	plan.ReproducibilitySHA256, err = factoryDigest0271(plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicBytes(factoryPlanPath0271(root), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(root, plan); err != nil {
		t.Fatal(err)
	}
	return root
}
func mirrorZip0274(t *testing.T, names []string, contents []string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	for i, name := range names {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetMode(0644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(contents[i])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestMirrorHelper0274ModsTransactionAndRecovery(t *testing.T) {
	root := mirrorMinimalClient0274(t)
	jar := []byte("valid mod payload")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(jar) }))
	defer server.Close()
	manifest := filepath.Join(t.TempDir(), "mods.json")
	artifact := []mirrorArtifact0274{{Path: "mods/example.jar", URL: server.URL + "/mod.jar", SHA256: mirrorSHA0274(jar), Side: "client"}}
	content, _ := json.Marshal(artifact)
	os.WriteFile(manifest, content, 0600)
	if err := handleRuntimeMirror0274([]string{"install-mods", "--client-dir", root, "--manifest", manifest, "--output", filepath.Join(t.TempDir(), "result.json")}); err != nil {
		t.Fatal(err)
	}
	p, err := readFactoryPlan0271(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(root, p); err != nil {
		t.Fatal(err)
	}
	if _, err := mirrorCheckedHash0274(filepath.Join(root, "mods", "example.jar"), mirrorSHA0274(jar)); err != nil {
		t.Fatal(err)
	}
	oldDigest := p.ReproducibilitySHA256
	artifact[0].Path = "mods/bad.jar"
	artifact[0].SHA256 = strings.Repeat("0", 64)
	content, _ = json.Marshal(artifact)
	os.WriteFile(manifest, content, 0600)
	if err := handleRuntimeMirror0274([]string{"install-mods", "--client-dir", root, "--manifest", manifest}); err == nil {
		t.Fatal("wrong hash must fail")
	}
	if _, err := os.Stat(filepath.Join(root, "mods", "bad.jar")); !os.IsNotExist(err) {
		t.Fatal("failed transaction modified live client")
	}
	after, err := readFactoryPlan0271(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.ReproducibilitySHA256 != oldDigest {
		t.Fatal("failed transaction changed plan")
	}
	// Source path traversal must be rejected before installing.
	artifact[0].Path = "mods/../../bad.jar"
	artifact[0].SHA256 = mirrorSHA0274(jar)
	content, _ = json.Marshal(artifact)
	os.WriteFile(manifest, content, 0600)
	if err := handleRuntimeMirror0274([]string{"install-mods", "--client-dir", root, "--manifest", manifest}); err == nil {
		t.Fatal("unsafe path accepted")
	}
}
func TestMirrorHelper0274DedupeWithoutClasspathModification(t *testing.T) {
	root := mirrorMinimalClient0274(t)
	jar := mirrorZip0274(t, []string{"x.class"}, []string{"hello"})
	file := filepath.Join(t.TempDir(), "lib.jar")
	os.WriteFile(file, jar, 0600)
	for _, suffix := range []string{"a/1/a-1.jar", "b/2/b-2.jar"} {
		p, err := mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
			return mirrorAddArtifacts0274(context.Background(), stage, []mirrorArtifact0274{{Path: "libraries/" + suffix, File: file, SHA256: mirrorSHA0274(jar)}}, "lwjgl-download")
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyFactoryPlan0271(root, p); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := readFactoryPlan0271(root)
	p, err := mirrorTransactional0274(context.Background(), root, mirrorDedupeLibraries0274)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(root, p); err != nil {
		t.Fatal(err)
	}
	first, _ := os.Stat(filepath.Join(root, "libraries/a/1/a-1.jar"))
	second, _ := os.Stat(filepath.Join(root, "libraries/b/2/b-2.jar"))
	if !os.SameFile(first, second) {
		t.Fatal("duplicate library jars were not deduplicated")
	}
	if before.Outputs[0] != p.Outputs[0] {
		t.Fatal("content unexpectedly changed")
	}
	previous := p.ReproducibilitySHA256
	p, err = mirrorTransactional0274(context.Background(), root, mirrorDedupeLibraries0274)
	if err != nil {
		t.Fatal(err)
	}
	if p.ReproducibilitySHA256 != previous {
		t.Fatal("idempotent dedup changed lock")
	}
}
func TestMirrorHelper0274PatchAuthlibVerifiedBytes(t *testing.T) {
	root := mirrorMinimalClient0274(t)
	base := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "LICENSE"}, []string{"original", "license"})
	patch := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "com/mojang/authlib/B.class"}, []string{"patched", "new"})
	expected := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "LICENSE", "com/mojang/authlib/B.class"}, []string{"patched", "license", "new"})
	baseFile := filepath.Join(t.TempDir(), "base.jar")
	patchFile := filepath.Join(t.TempDir(), "patch.jar")
	os.WriteFile(baseFile, base, 0600)
	os.WriteFile(patchFile, patch, 0600)
	target := "libraries/com/mojang/authlib/4.0/authlib-4.0.jar"
	_, err := mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorAddArtifacts0274(context.Background(), stage, []mirrorArtifact0274{{Path: target, File: baseFile, SHA256: mirrorSHA0274(base)}}, "lwjgl-download")
	})
	if err != nil {
		t.Fatal(err)
	}
	old, _ := readFactoryPlan0271(root)
	_, err = mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorPatchAuthlib0274(stage, target, patchFile, mirrorSHA0274(base), mirrorSHA0274(patch), strings.Repeat("0", 64))
	})
	if err == nil {
		t.Fatal("incorrect expected output accepted")
	}
	still, _ := readFactoryPlan0271(root)
	if still.ReproducibilitySHA256 != old.ReproducibilitySHA256 {
		t.Fatal("failed patch mutated live plan")
	}
	p, err := mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorPatchAuthlib0274(stage, target, patchFile, mirrorSHA0274(base), mirrorSHA0274(patch), mirrorSHA0274(expected))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(root, p); err != nil {
		t.Fatal(err)
	}
	if _, err := mirrorCheckedHash0274(filepath.Join(root, filepath.FromSlash(target)), mirrorSHA0274(expected)); err != nil {
		t.Fatal(err)
	}
	badPatch := mirrorZip0274(t, []string{"org/evil/Injected.class"}, []string{"bad"})
	os.WriteFile(patchFile, badPatch, 0600)
	if _, err = mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorPatchAuthlib0274(stage, target, patchFile, mirrorSHA0274(expected), mirrorSHA0274(badPatch), mirrorSHA0274(expected))
	}); err == nil {
		t.Fatal("unauthorized patch entry accepted")
	}
}
func TestMirrorHelper0274InstallerDownloadPinning(t *testing.T) {
	bytes := []byte("trusted forge installer bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bytes) }))
	defer server.Close()
	cache := t.TempDir()
	out := filepath.Join(t.TempDir(), "download.json")
	args := []string{"download-installer", "--loader", "forge", "--minecraft", "1.21.1", "--loader-version", "52.0.1", "--cache-dir", cache, "--url", server.URL + "/installer.jar", "--sha256", mirrorSHA0274(bytes), "--output", out}
	if err := handleRuntimeMirror0274(args); err != nil {
		t.Fatal(err)
	}
	if err := handleRuntimeMirror0274(args); err != nil {
		t.Fatal("verified cache should be idempotent: ", err)
	}
	file := filepath.Join(cache, "forge", "1.21.1-52.0.1", "installer.jar")
	if err := os.WriteFile(file, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := handleRuntimeMirror0274(args); err == nil {
		t.Fatal("tampered installer reused")
	}
}
func TestMirrorHelper0274WorkspaceAppliesActualVanillaWithMods(t *testing.T) {
	clientJar := []byte("fixture client")
	asset := []byte("fixture asset")
	mod := []byte("fixture mod")
	assetHash := sha1hex(asset)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	meta := fixtureFactoryMetadata0271(server.URL, "test-vanilla", clientJar, asset)
	manifest := MojangVersionManifest{Latest: map[string]string{"release": "test-vanilla"}, Versions: []MojangManifestVersion{{ID: "test-vanilla", Type: "release", URL: server.URL + "/version.json", SHA1: sha1hex(meta)}}}
	mb, _ := json.Marshal(manifest)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mb) })
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { w.Write(meta) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { w.Write(clientJar) })
	mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { w.Write(fixtureFactoryAssets0271(asset)) })
	mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { w.Write(asset) })
	folder := t.TempDir()
	modPath := filepath.Join(folder, "fixture.jar")
	os.WriteFile(modPath, mod, 0600)
	workspace := mirrorWorkspace0274{SchemaVersion: "neverlauncher.mirror-workspace.v1", Minecraft: "test-vanilla", Loader: "vanilla", Mods: []mirrorArtifact0274{{Path: "mods/fixture.jar", File: "fixture.jar", SHA256: mirrorSHA0274(mod)}}}
	data, _ := json.Marshal(workspace)
	workspaceFile := filepath.Join(folder, "workspace.json")
	os.WriteFile(workspaceFile, data, 0600)
	dir := filepath.Join(folder, "client")
	args := []string{"apply-workspace", "--file", workspaceFile, "--client-dir", dir, "--version-manifest", server.URL + "/manifest.json", "--asset-base-url", server.URL + "/assets", "--library-base-url", server.URL + "/libraries", "--output", filepath.Join(folder, "result.json")}
	if err := handleRuntimeMirror0274(args); err != nil {
		t.Fatal(err)
	}
	plan, err := readFactoryPlan0271(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(dir, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := mirrorCheckedHash0274(filepath.Join(dir, "mods/fixture.jar"), mirrorSHA0274(mod)); err != nil {
		t.Fatal(err)
	}
	if err := handleRuntimeMirror0274(args); err == nil {
		t.Fatal("existing published dir should reject reapplication")
	}
	workspace.Mods[0].SHA256 = strings.Repeat("0", 64)
	data, _ = json.Marshal(workspace)
	os.WriteFile(workspaceFile, data, 0600)
	broken := filepath.Join(folder, "client-broken")
	args = []string{"apply-workspace", "--file", workspaceFile, "--client-dir", broken, "--version-manifest", server.URL + "/manifest.json", "--asset-base-url", server.URL + "/assets"}
	if err := handleRuntimeMirror0274(args); err == nil {
		t.Fatal("wrong workspace mod hash accepted")
	}
	if _, err := os.Stat(broken); !os.IsNotExist(err) {
		t.Fatal("failed workspace published partial client")
	}
}

// This is the real Forge installer + processor pipeline, using an offline
// installer file and real worker subprocess instead of a hand-written plan.
func TestMirrorHelper0274LaunchVerifiedLocalForgeInstaller(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture processor Java executable is a POSIX script")
	}
	clientJar := []byte("minecraft-client")
	asset := []byte("minecraft-asset")
	generated := []byte("forge-generated-runtime")
	processorJar := testProcessorJar(t)
	installer := testForgeInstaller(t, "forge", "1.21.1", "52.0.1", generated, processorJar)
	sourceFile := filepath.Join(t.TempDir(), "installer.jar")
	if err := os.WriteFile(sourceFile, installer, 0600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	meta := fixtureFactoryMetadata0271(server.URL, "1.21.1", clientJar, asset)
	manifest := MojangVersionManifest{Latest: map[string]string{"release": "1.21.1"}, Versions: []MojangManifestVersion{{ID: "1.21.1", Type: "release", URL: server.URL + "/version.json", SHA1: sha1hex(meta)}}}
	mb, _ := json.Marshal(manifest)
	assetHash := sha1hex(asset)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mb) })
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { w.Write(meta) })
	mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { w.Write(clientJar) })
	mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { w.Write(fixtureFactoryAssets0271(asset)) })
	mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { w.Write(asset) })
	mux.HandleFunc("/installer.jar", func(w http.ResponseWriter, r *http.Request) {
		t.Error("tried to download verified local installer")
		w.WriteHeader(http.StatusForbidden)
	})
	root := filepath.Join(t.TempDir(), "client")
	args := []string{"launch-installer", "--client-dir", root, "--loader", "forge", "--minecraft", "1.21.1", "--loader-version", "52.0.1", "--installer-file", sourceFile, "--installer-sha256", mirrorSHA0274(installer), "--installer-url", server.URL + "/installer.jar", "--java", testFakeJava(t, generated), "--version-manifest", server.URL + "/manifest.json", "--asset-base-url", server.URL + "/assets", "--library-base-url", server.URL + "/libraries", "--output", filepath.Join(t.TempDir(), "result.json")}
	if err := handleRuntimeMirror0274(args); err != nil {
		t.Fatal(err)
	}
	plan, err := readFactoryPlan0271(root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Loader != "forge" || len(plan.Processors) == 0 || plan.LoaderVersion != "52.0.1" {
		t.Fatal("installer did not execute processor pipeline")
	}
	if err := verifyFactoryPlan0271(root, plan); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorHelper0274LWJGLCoordinateAndProfileRegistration(t *testing.T) {
	root := mirrorMinimalClient0274(t)
	contents := mirrorZip0274(t, []string{"org/lwjgl/GL.class"}, []string{"bytecode"})
	source := filepath.Join(t.TempDir(), "lwjgl.jar")
	if err := os.WriteFile(source, contents, 0600); err != nil {
		t.Fatal(err)
	}
	coord := "org.lwjgl:lwjgl:3.3.3"
	out := filepath.Join(t.TempDir(), "result.json")
	args := []string{"lwjgl-download", "--client-dir", root, "--coordinate", coord, "--source-file", source, "--sha256", mirrorSHA0274(contents), "--output", out}
	if err := handleRuntimeMirror0274(args); err != nil {
		t.Fatal(err)
	}
	p, err := readFactoryPlan0271(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFactoryPlan0271(root, p); err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p.Launch.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	var parsed MojangVersionFile
	if err := json.Unmarshal(profile, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Libraries) != 1 || parsed.Libraries[0].Name != coord {
		t.Fatalf("LWJGL not added to runtime profile: %s", profile)
	}
	if err := handleRuntimeMirror0274(args); err == nil {
		t.Fatal("duplicate coordinate must be rejected")
	}
	args[5] = "org.evil:fake:1.0" // args[4] = --coordinate, args[5] = value
	if err := handleRuntimeMirror0274(args); err == nil {
		t.Fatal("unrelated group accepted as LWJGL")
	}
}

func TestMirrorHelper0274ModrinthRequiredDependencyResolution(t *testing.T) {
	first := []byte("root mod")
	dependency := []byte("required dependency")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		var content any
		switch r.URL.Path {
		case "/version/rootVer":
			content = map[string]any{"id": "rootVer", "project_id": "rootProj", "game_versions": []string{"1.21.1"}, "loaders": []string{"fabric"}, "files": []any{map[string]any{"filename": "root.jar", "url": base + "/files/root.jar", "primary": true, "hashes": map[string]any{"sha256": mirrorSHA0274(first)}}}, "dependencies": []any{map[string]any{"project_id": "childProj", "dependency_type": "required"}}}
		case "/project/rootProj":
			content = map[string]any{"id": "rootProj", "client_side": "required"}
		case "/project/childProj":
			content = map[string]any{"id": "childProj", "client_side": "required"}
		case "/project/childProj/version":
			content = []any{map[string]any{"id": "childVer", "project_id": "childProj", "game_versions": []string{"1.21.1"}, "loaders": []string{"fabric"}, "date_published": "2026-10-01T00:00:00Z"}}
		case "/version/childVer":
			content = map[string]any{"id": "childVer", "project_id": "childProj", "game_versions": []string{"1.21.1"}, "loaders": []string{"fabric"}, "files": []any{map[string]any{"filename": "child.jar", "url": base + "/files/child.jar", "hashes": map[string]any{"sha256": mirrorSHA0274(dependency)}}}}
		case "/files/root.jar":
			w.Write(first)
			return
		case "/files/child.jar":
			w.Write(dependency)
			return
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(content)
	}))
	defer server.Close()
	plan := factoryPlan0271{Loader: "fabric", MinecraftVersion: "1.21.1"}
	mods, err := resolveModrinthMods0274(context.Background(), server.URL, "rootVer", plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].VersionID != "childVer" || mods[1].VersionID != "rootVer" {
		t.Fatalf("unexpected dependency ordering: %+v", mods)
	}
	stage := t.TempDir()
	actions, err := mirrorAddArtifacts0274(context.Background(), stage, mods, "install-mods")
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0].ProjectID != "childProj" || actions[1].VersionID != "rootVer" {
		t.Fatalf("missing provenance: %+v", actions)
	}
	if _, err := mirrorCheckedHash0274(filepath.Join(stage, "mods/child.jar"), mirrorSHA0274(dependency)); err != nil {
		t.Fatal(err)
	}
	plan.Loader = "forge"
	if _, err = resolveModrinthMods0274(context.Background(), server.URL, "rootVer", plan); err == nil {
		t.Fatal("incompatible loader version accepted")
	}
}
