package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLegacy0406ChildOptionsOverrideWithoutDroppingParent(t *testing.T) {
	parent, err := splitLegacyArguments0278(`--username ${auth_player_name} --version ${version_name} --gameDir "${game_directory}" --accessToken ${auth_access_token} --demo`)
	if err != nil {
		t.Fatal(err)
	}
	child, err := splitLegacyArguments0278(`--username "Forge Player" --tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker`)
	if err != nil {
		t.Fatal(err)
	}
	combined := mergeLegacyArgumentTokens0278(parent, child)
	find := func(option, value string) bool {
		for i := 0; i+1 < len(combined); i++ {
			if combined[i] == option && combined[i+1] == value {
				return true
			}
		}
		return false
	}
	for _, pair := range [][2]string{{"--username", "Forge Player"}, {"--version", "${version_name}"}, {"--gameDir", "${game_directory}"}, {"--accessToken", "${auth_access_token}"}, {"--tweakClass", "net.minecraftforge.fml.common.launcher.FMLTweaker"}} {
		if !find(pair[0], pair[1]) {
			t.Fatalf("missing %q: %v", pair, combined)
		}
	}
	if count := strings.Count(strings.Join(combined, " "), "--username"); count != 1 {
		t.Fatalf("duplicate username flag %v", combined)
	}
	if !strings.Contains(strings.Join(combined, " "), "--demo") {
		t.Fatalf("lost valueless legacy flag: %v", combined)
	}
	if same := mergeLegacyArgumentTokens0278(parent, parent); strings.Join(same, "|") != strings.Join(parent, "|") {
		t.Fatalf("unexpected repeated options: %v", same)
	}
}

// Launch an actual JVM with Java-8-compatible bytecode and a controlled
// LaunchWrapper fixture. The Java 8 selector shim is explicit: this test
// verifies the execution path and classpath precedence, NOT an actual
// Mojang/Forge client or a Java 8 runtime installation.
func TestLegacy0406ExecutableForgeLaunchAndClasspathPrecedence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX Java selector fixture")
	}
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac unavailable")
	}
	jar, err := exec.LookPath("jar")
	if err != nil {
		t.Skip("jar unavailable")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("java unavailable")
	}
	root := filepath.Join(t.TempDir(), "legacy client with spaces")
	compile := func(classes, name, code string, cp string) {
		t.Helper()
		file := filepath.Join(t.TempDir(), filepath.FromSlash(name)+".java")
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(code), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(classes, 0755); err != nil {
			t.Fatal(err)
		}
		args := []string{"--release", "8", "-d", classes}
		if cp != "" {
			args = append(args, "-cp", cp)
		}
		args = append(args, file)
		out, err := exec.Command(javac, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("javac: %v: %s", err, out)
		}
	}
	packageJar := func(classes, rel string) string {
		t.Helper()
		dest := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(jar, "cf", dest, "-C", classes, ".").CombinedOutput(); err != nil {
			t.Fatalf("jar: %v: %s", err, out)
		}
		return dest
	}
	parentClasses := filepath.Join(t.TempDir(), "parent")
	childClasses := filepath.Join(t.TempDir(), "child")
	forgeClasses := filepath.Join(t.TempDir(), "forge")
	compile(parentClasses, "example/core/Ping", `package example.core; public class Ping { public static String value() { return "parent"; } }`, "")
	compile(childClasses, "example/core/Ping", `package example.core; public class Ping { public static String value() { return "child"; } }`, "")
	packageJar(parentClasses, "libraries/example/core/1.0/core-1.0.jar")
	childJar := packageJar(childClasses, "libraries/example/core/2.0/core-2.0.jar")
	compile(forgeClasses, "net/minecraft/launchwrapper/Launch", `package net.minecraft.launchwrapper;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import example.core.Ping;
public class Launch {
  static String arg(String[] args,String key) {
    for (int i=0;i<args.length-1;i++) if(args[i].equals(key)) return args[i+1];
    throw new IllegalStateException("missing "+key);
  }
  public static void main(String[] args) throws Exception {
    String directory=arg(args,"--gameDir");
    String value=Ping.value()+"|"+arg(args,"--username")+"|"+arg(args,"--version")+"|"+arg(args,"--tweakClass")+"|"+arg(args,"--accessToken");
    Files.write(Paths.get(directory,"forge-launch.fixture"),value.getBytes(StandardCharsets.UTF_8));
  }
}`, childJar)
	packageJar(forgeClasses, "libraries/net/minecraftforge/forge/1.0/forge-1.0.jar")
	target := currentVanillaTarget()
	putLegacyTestFile0278(t, root, "versions/1.12.2/1.12.2.json", []byte(`{"id":"1.12.2","mainClass":"net.minecraft.client.main.Main","minecraftArguments":"--username ${auth_player_name} --gameDir ${game_directory} --version ${version_name} --accessToken ${auth_access_token}","libraries":[{"name":"example:core:1.0"}]}`))
	putLegacyTestFile0278(t, root, "versions/1.12.2/1.12.2.jar", []byte("controlled Minecraft placeholder"))
	childRel := "versions/1.12.2-forge/1.12.2-forge.json"
	putLegacyTestFile0278(t, root, childRel, []byte(`{"id":"1.12.2-forge","inheritsFrom":"1.12.2","mainClass":"net.minecraft.launchwrapper.Launch","minecraftArguments":"--username ${auth_player_name} --tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker","libraries":[{"name":"net.minecraftforge:forge:1.0"},{"name":"example:core:2.0"}]}`))
	putLegacyTestFile0278(t, root, "natives/"+target.OS+"/"+target.Arch+"/fixture.so", []byte("native"))
	recipe, err := resolveLegacyLaunch0278(root, "forge", "1.12.2", childRel, 8, []vanillaTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLegacyLaunch0278(root, recipe); err != nil {
		t.Fatal(err)
	}
	loaderVersion := "14.23.5.2859"
	lock := loaderResolutionLock{
		SchemaVersion: loaderResolutionLockSchema, Loader: "forge", MinecraftVersion: "1.12.2",
		Selector: loaderVersion, ResolvedVersion: loaderVersion, ArtifactVersion: loaderVersion,
		ResolutionSourceURL: "https://fixture.invalid/forge/versions", ResolutionSourceSHA256: sha256HexBytes([]byte("fixture-source")),
		PayloadURL: "https://fixture.invalid/forge/installer.jar", PayloadSHA256: sha256HexBytes([]byte("fixture-installer")),
		RuntimeProfileSHA256: recipe.ChildSHA256, MaterializationSHA256: sha256HexBytes([]byte("fixture-materialization")),
	}
	_, lockHash, err := persistLoaderResolutionLock(defaultLoaderResolutionLockPath(root, "forge"), lock)
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := scanFactoryOutputs0271(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := factoryPlan0271{SchemaVersion: factoryPlanSchema0271, MinecraftVersion: "1.12.2", MinecraftReleaseType: "release", Loader: "forge", LoaderVersion: loaderVersion, LoaderResolutionSHA256: lockHash, Resolution: &factoryResolution0271{SourceSHA256: lock.ResolutionSourceSHA256, PayloadSHA256: lock.PayloadSHA256, ProfileSHA256: lock.RuntimeProfileSHA256, ResolvedVersion: loaderVersion}, Targets: []vanillaTarget{target}, Java: factoryJava0271{Major: 8}, Launch: factoryLaunch0271{ProfilePath: childRel, MainClass: recipe.MainClass, AssetIndex: "1.12", NativesDirectory: "natives"}, Legacy: recipe, Steps: factorySteps0271("forge"), Outputs: outputs, Sources: []factorySource0271{{Path: recipe.ParentProfile, URL: "https://example.test/parent.json", Kind: "version-metadata", SHA256: recipe.ParentSHA256, Size: 1}}}
	plan.ReproducibilitySHA256, err = factoryDigest0271(plan)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	putLegacyTestFile0278(t, root, ".neverlauncher/install-plan.json", b)
	shim := filepath.Join(t.TempDir(), "java8")
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = '-version' ]; then echo 'java version \"1.8.0_402\"' >&2; exit 0; fi\nexec %q \"$@\"\n", java)
	if err := os.WriteFile(shim, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEVERLAUNCHER_MINECRAFT_ACCESS_TOKEN", "fixture-token")
	if err := runLegacyClient0278(context.Background(), root, shim, "User With Spaces", "fixture-uuid"); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(filepath.Join(root, "forge-launch.fixture"))
	if err != nil {
		t.Fatal(err)
	}
	expected := "child|User With Spaces|1.12.2|net.minecraftforge.fml.common.launcher.FMLTweaker|fixture-token"
	if string(output) != expected {
		t.Fatalf("legacy JVM classpath or argv mismatch: got %q, expected %q", output, expected)
	}
	if err := os.WriteFile(childJar, []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runLegacyClient0278(context.Background(), root, shim, "User", "fixture-uuid"); err == nil {
		t.Fatal("tampered classpath JAR executed")
	}
}
