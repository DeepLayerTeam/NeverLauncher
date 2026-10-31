package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func compatJarFixture0279(t *testing.T, agent bool) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	if agent {
		f, err := w.Create("META-INF/MANIFEST.MF")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte("Manifest-Version: 1.0\nPremain-Class: example.Agent\n\n")); err != nil {
			t.Fatal(err)
		}
	}
	f, err := w.Create("example/Fixture.class")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("class-fixture")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func compatFixture0279(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "client with spaces")
	target := currentVanillaTarget()
	parent := "versions/1.12.2/1.12.2.json"
	putLegacyTestFile0278(t, root, parent, []byte(`{"id":"1.12.2","mainClass":"net.minecraft.client.main.Main","minecraftArguments":"--username ${auth_player_name} --accessToken ${auth_access_token} --userType ${user_type}"}`))
	putLegacyTestFile0278(t, root, "versions/1.12.2/1.12.2.jar", []byte("fixture-client"))
	putLegacyTestFile0278(t, root, "natives/"+target.OS+"/"+target.Arch+"/fixture.so", []byte("native"))
	legacy, err := resolveLegacyLaunch0278(root, "vanilla", "1.12.2", parent, 8, []vanillaTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeLegacyLaunch0278(root, legacy); err != nil {
		t.Fatal(err)
	}
	outputs, err := scanFactoryOutputs0271(root)
	if err != nil {
		t.Fatal(err)
	}
	p := factoryPlan0271{SchemaVersion: factoryPlanSchema0271, Loader: "vanilla", MinecraftVersion: "1.12.2", MinecraftReleaseType: "release", Targets: []vanillaTarget{target}, Java: factoryJava0271{Major: 8}, Launch: factoryLaunch0271{ProfilePath: parent, MainClass: legacy.MainClass, AssetIndex: "1.12", NativesDirectory: "natives"}, Steps: factorySteps0271("vanilla"), Legacy: legacy, Outputs: outputs, Sources: []factorySource0271{{Path: parent, URL: "https://example.test/version", Kind: "version-metadata", SHA256: legacy.ParentSHA256, Size: 1}}}
	p.ReproducibilitySHA256, err = factoryDigest0271(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	putLegacyTestFile0278(t, root, ".launcher/install-plan.json", b)
	if err = verifyFactoryPlan0271(root, p); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestAuthlibClassloader0279ApplyLegacyRuntimeAndTampering(t *testing.T) {
	root := compatFixture0279(t)
	sourceDir := t.TempDir()
	extra := compatJarFixture0279(t, false)
	agent := compatJarFixture0279(t, true)
	putLegacyTestFile0278(t, sourceDir, "extra.jar", extra)
	putLegacyTestFile0278(t, sourceDir, "agent.jar", agent)
	config := compatRequest0279{SchemaVersion: compatSchema0279, AuthMode: "official", Classpath: []compatInputArtifact0279{{Path: ".launcher/compat/classpath/extra.jar", SHA256: sha256HexBytes(extra), SourceFile: "extra.jar"}}, JavaAgents: []compatInputAgent0279{{Path: ".launcher/compat/agents/agent.jar", SHA256: sha256HexBytes(agent), SourceFile: "agent.jar", Options: "https://auth.example.test"}}}
	b, _ := json.Marshal(config)
	putLegacyTestFile0278(t, sourceDir, "compat.json", b)
	if err := handleRuntimeCompat0279([]string{"compat-apply", "--client-dir", root, "--file", filepath.Join(sourceDir, "compat.json"), "--output", filepath.Join(t.TempDir(), "result.json")}); err != nil {
		t.Fatal(err)
	}
	p, err := readFactoryPlan0271(root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Compatibility == nil || p.Compatibility.JavaMajor != 8 || p.Compatibility.ParentInstallPlanSHA256 == p.ReproducibilitySHA256 {
		t.Fatalf("compatibility not bound to new digest: %+v", p.Compatibility)
	}
	if err = verifyFactoryPlan0271(root, p); err != nil {
		t.Fatal(err)
	}
	jvm, cp, err := compatJVMArgs0279(root, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(jvm) != 1 || !strings.Contains(jvm[0], "-javaagent:") || len(cp) != 1 {
		t.Fatalf("no executable classloader arguments: %v %v", jvm, cp)
	}
	if runtime.GOOS != "windows" {
		java := filepath.Join(t.TempDir(), "java8")
		log := filepath.Join(t.TempDir(), "argv.txt")
		script := `#!/bin/sh
if [ "$1" = "-version" ]; then echo 'openjdk version "1.8.0_442"' >&2; exit 0; fi
printf '%s\n' "$@" > "$LEGACY_CAPTURE_ARGV"
`
		if err = os.WriteFile(java, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("LEGACY_CAPTURE_ARGV", log)
		t.Setenv("LAUNCHER_MINECRAFT_ACCESS_TOKEN", "fixture-token")
		if err = runLegacyClient0278(context.Background(), root, java, "Agent User", "fixture-uuid"); err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{"-javaagent:", "agent.jar=https://auth.example.test", "extra.jar", "net.minecraft.client.main.Main", "fixture-token"} {
			if !strings.Contains(string(args), needle) {
				t.Fatalf("missing %s in argv:\n%s", needle, args)
			}
		}
		t.Setenv("LAUNCHER_MINECRAFT_ACCESS_TOKEN", "")
		if err = runLegacyClient0278(context.Background(), root, java, "Agent User", "fixture-uuid"); err == nil {
			t.Fatal("official mode accepted missing token")
		}
	}
	if err = handleRuntimeCompat0279([]string{"compat-apply", "--client-dir", root, "--file", filepath.Join(sourceDir, "compat.json")}); err == nil {
		t.Fatal("mutated compatible build without new project")
	}
	if err = os.WriteFile(filepath.Join(root, ".launcher/compat/agents/agent.jar"), []byte("tamper"), 0644); err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(root, p); err == nil {
		t.Fatal("tampered agent passed install plan")
	}
}
func TestAuthlibClassloader0279ModulepathAndUnsupportedRules(t *testing.T) {
	sha := sha256HexBytes([]byte("fixture"))
	base := compatLock0279{SchemaVersion: compatSchema0279, AuthMode: "offline", JavaMajor: 8, ParentInstallPlanSHA256: sha}
	if err := compatValidateLock0279(&base); err != nil {
		t.Fatal(err)
	}
	base.Modulepath = []compatArtifact0279{{Path: ".launcher/compat/modules/module.jar", SHA256: sha}}
	if err := compatValidateLock0279(&base); err == nil {
		t.Fatal("Java 8 modulepath accepted")
	}
	base.JavaMajor = 17
	base.AddOpens = []string{"java.base/java.lang=ALL-UNNAMED"}
	if err := compatValidateLock0279(&base); err != nil {
		t.Fatal(err)
	}
	base.AddOpens = []string{"java.base/java.lang=ALL-UNNAMED", "-Xmx8G=ALL-UNNAMED"}
	if err := compatValidateLock0279(&base); err == nil {
		t.Fatal("untrusted JVM option accepted")
	}
	base.AddOpens = nil
	base.Modulepath = nil
	base.AuthMode = "yggdrasil"
	if err := compatValidateLock0279(&base); err == nil {
		t.Fatal("unpinned auth agent accepted")
	}
	base.JavaAgents = []compatAgent0279{{Path: ".launcher/compat/agents/ygg.jar", SHA256: sha, Options: "${TOKEN}"}}
	if err := compatValidateLock0279(&base); err == nil {
		t.Fatal("secret placeholder accepted")
	}
	base.JavaAgents[0].Options = "https://auth.example.test"
	if err := compatValidateLock0279(&base); err != nil {
		t.Fatal(err)
	}
	if _, err := compatReadRequest0279(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing config accepted")
	}
}
func TestAuthlibClassloader0279AuthlibProvenanceAndRollback(t *testing.T) {
	root := mirrorMinimalClient0274(t)
	base := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "LICENSE"}, []string{"old", "license"})
	overlay := mirrorZip0274(t, []string{"com/mojang/authlib/A.class"}, []string{"new"})
	expected := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "LICENSE"}, []string{"new", "license"})
	src := filepath.Join(t.TempDir(), "auth.jar")
	patch := filepath.Join(t.TempDir(), "overlay.jar")
	os.WriteFile(src, base, 0600)
	os.WriteFile(patch, overlay, 0600)
	dest := "libraries/com/mojang/authlib/1.0/authlib-1.0.jar"
	_, err := mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorAddArtifacts0274(context.Background(), stage, []mirrorArtifact0274{{Path: dest, File: src, SHA256: sha256HexBytes(base)}}, "lwjgl-download")
	})
	if err != nil {
		t.Fatal(err)
	}
	pre, err := readFactoryPlan0271(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorPatchAuthlib0274(stage, dest, patch, sha256HexBytes(base), sha256HexBytes(overlay), strings.Repeat("f", 64))
	})
	if err == nil {
		t.Fatal("wrong expected archive accepted")
	}
	afterBad, err := readFactoryPlan0271(root)
	if err != nil || pre.ReproducibilitySHA256 != afterBad.ReproducibilitySHA256 {
		t.Fatal("failed transformation changed live client")
	}
	updated, err := mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		return mirrorPatchAuthlib0274(stage, dest, patch, sha256HexBytes(base), sha256HexBytes(overlay), sha256HexBytes(expected))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(root, updated); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, ".launcher/compat/patches", sha256HexBytes(overlay)+".jar")); err != nil {
		t.Fatal("overlay not retained", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, authlibProvenancePath0279))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), sha256HexBytes(base)) || !strings.Contains(string(raw), sha256HexBytes(expected)) {
		t.Fatal("provenance missing transformation hashes")
	}
	if err = os.WriteFile(filepath.Join(root, authlibProvenancePath0279), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(root, updated); err == nil {
		t.Fatal("tampered transformation history accepted")
	}
}

func TestAuthlibClassloader0279RejectInvalidAgentAndCustomModeRequiresOptIn(t *testing.T) {
	root := compatFixture0279(t)
	source := filepath.Join(t.TempDir(), "agent.jar")
	invalid := compatJarFixture0279(t, false) // valid ZIP but no Premain-Class
	if err := os.WriteFile(source, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	req := compatRequest0279{SchemaVersion: compatSchema0279, AuthMode: "yggdrasil", JavaAgents: []compatInputAgent0279{{Path: ".launcher/compat/agents/custom.jar", SHA256: sha256HexBytes(invalid), SourceFile: source}}}
	previous, _ := readFactoryPlan0271(root)
	_, err := mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		p, e := readFactoryPlan0271(stage)
		if e != nil {
			return nil, e
		}
		return compatApply0279(context.Background(), stage, p, req, false)
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-auth-agent") {
		t.Fatalf("missing auth agent opt-in accepted: %v", err)
	}
	_, err = mirrorTransactional0274(context.Background(), root, func(stage string) ([]mirrorAction0274, error) {
		p, e := readFactoryPlan0271(stage)
		if e != nil {
			return nil, e
		}
		return compatApply0279(context.Background(), stage, p, req, true)
	})
	if err == nil || !strings.Contains(err.Error(), "Premain-Class") {
		t.Fatalf("invalid Java agent accepted: %v", err)
	}
	after, _ := readFactoryPlan0271(root)
	if previous.ReproducibilitySHA256 != after.ReproducibilitySHA256 {
		t.Fatal("invalid compatibility request changed live build")
	}
}

func TestAuthlibClassloader0279RejectSignedAuthlib(t *testing.T) {
	stage := t.TempDir()
	signed := mirrorZip0274(t, []string{"com/mojang/authlib/A.class", "META-INF/A.SF"}, []string{"old", "signature"})
	overlay := mirrorZip0274(t, []string{"com/mojang/authlib/A.class"}, []string{"new"})
	source := filepath.Join(t.TempDir(), "overlay.jar")
	if err := os.WriteFile(source, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	target := "libraries/com/mojang/authlib/1.0/authlib-1.0.jar"
	putLegacyTestFile0278(t, stage, target, signed)
	if _, err := mirrorPatchAuthlib0274(stage, target, source, sha256HexBytes(signed), sha256HexBytes(overlay), strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "signed") {
		t.Fatalf("signed authlib accepted: %v", err)
	}
	if _, err := mirrorCheckedHash0274(filepath.Join(stage, filepath.FromSlash(target)), sha256HexBytes(signed)); err != nil {
		t.Fatal("signed source was mutated", err)
	}
}

func TestAuthlibClassloader0279ModuleArgumentsAndVerifiedHashes(t *testing.T) {
	root := t.TempDir()
	data := compatJarFixture0279(t, false)
	path := ".launcher/compat/modules/example.jar"
	putLegacyTestFile0278(t, root, path, data)
	lock := compatLock0279{
		SchemaVersion: compatSchema0279, AuthMode: "offline", JavaMajor: 17,
		ParentInstallPlanSHA256: sha256HexBytes([]byte("original-plan")),
		Modulepath:              []compatArtifact0279{{Path: path, SHA256: sha256HexBytes(data)}},
		AddOpens:                []string{"java.base/java.lang=ALL-UNNAMED"},
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	putLegacyTestFile0278(t, root, compatReceiptPath0279, raw)
	p := factoryPlan0271{Java: factoryJava0271{Major: 17}, Compatibility: &lock}
	flags, classpath, err := compatJVMArgs0279(root, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(classpath) != 0 || len(flags) != 4 || flags[0] != "--module-path" || flags[2] != "--add-opens" || flags[3] != "java.base/java.lang=ALL-UNNAMED" {
		t.Fatalf("wrong JVM flags: %v %v", flags, classpath)
	}
	if !strings.Contains(flags[1], "example.jar") {
		t.Fatalf("modulepath missing: %v", flags)
	}
	if err = os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = compatJVMArgs0279(root, p); err == nil {
		t.Fatal("corrupted module JAR accepted")
	}
}
