package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func putLegacyTestFile0278(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyAdapters0278ForgeInheritanceClasspathAndIntegrity(t *testing.T) {
	for _, tc := range []struct{ minecraft, tweaker string }{
		{"1.7.10", "cpw.mods.fml.common.launcher.FMLTweaker"},
		{"1.12.2", "net.minecraftforge.fml.common.launcher.FMLTweaker"},
	} {
		t.Run(tc.minecraft, func(t *testing.T) {
			root := t.TempDir()
			target := vanillaTarget{OS: "windows", Arch: "x86_64"}
			putLegacyTestFile0278(t, root, "versions/"+tc.minecraft+"/"+tc.minecraft+".json", []byte(`{"id":"`+tc.minecraft+`","mainClass":"net.minecraft.client.main.Main","minecraftArguments":"--username ${auth_player_name} --gameDir ${game_directory}","libraries":[{"name":"example:core:1.0"},{"name":"example:overridden:1.0"},{"name":"example:native:1.0:natives-windows","natives":{"windows":"natives-windows"}}]}`))
			putLegacyTestFile0278(t, root, "versions/"+tc.minecraft+"/"+tc.minecraft+".jar", []byte("client"))
			putLegacyTestFile0278(t, root, "libraries/example/core/1.0/core-1.0.jar", []byte("parent"))
			putLegacyTestFile0278(t, root, "libraries/example/overridden/2.0/overridden-2.0.jar", []byte("child-version"))
			putLegacyTestFile0278(t, root, "libraries/net/minecraftforge/forge/1.0/forge-1.0.jar", []byte("forge"))
			child := "versions/" + tc.minecraft + "-forge/" + tc.minecraft + "-forge.json"
			putLegacyTestFile0278(t, root, child, []byte(`{"id":"`+tc.minecraft+`-forge","inheritsFrom":"`+tc.minecraft+`","mainClass":"net.minecraft.launchwrapper.Launch","minecraftArguments":"--tweakClass `+tc.tweaker+`","libraries":[{"name":"net.minecraftforge:forge:1.0"},{"name":"example:overridden:2.0"},{"name":"example:server:1.0","clientreq":false}]}`))
			recipe, err := resolveLegacyLaunch0278(root, "forge", tc.minecraft, child, 8, []vanillaTarget{target})
			if err != nil {
				t.Fatal(err)
			}
			if recipe.MainClass != "net.minecraft.launchwrapper.Launch" || recipe.Tweaker != tc.tweaker {
				t.Fatalf("wrong launch details: %+v", recipe)
			}
			if len(recipe.Targets) != 1 || len(recipe.Targets[0].Classpath) != 4 {
				t.Fatalf("classpath did not inherit parent and override versions: %+v", recipe.Targets)
			}
			if !strings.Contains(strings.Join(recipe.GameArguments, " "), "--username ${auth_player_name}") {
				t.Fatal("parent game args were discarded")
			}
			if err := writeLegacyLaunch0278(root, recipe); err != nil {
				t.Fatal(err)
			}
			plan := factoryPlan0271{Loader: "forge", MinecraftVersion: tc.minecraft, Java: factoryJava0271{Major: 8}, Targets: []vanillaTarget{target}, Launch: factoryLaunch0271{ProfilePath: child}, Legacy: recipe}
			if err := verifyLegacyLaunch0278(root, plan); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "libraries/example/core/1.0/core-1.0.jar"), []byte("tamper"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := verifyLegacyLaunch0278(root, plan); err == nil {
				t.Fatal("tampered library passed legacy verification")
			}
		})
	}
}
func TestLegacyAdapters0278RejectUnknownTweakerAndUnpinnedLibrary(t *testing.T) {
	root := t.TempDir()
	mc := "1.12.2"
	putLegacyTestFile0278(t, root, "versions/1.12.2/1.12.2.json", []byte(`{"id":"1.12.2","mainClass":"net.minecraft.client.main.Main","minecraftArguments":"--username ${auth_player_name}"}`))
	putLegacyTestFile0278(t, root, "versions/1.12.2/1.12.2.jar", []byte("minecraft"))
	child := "versions/forge/forge.json"
	putLegacyTestFile0278(t, root, child, []byte(`{"id":"forge","inheritsFrom":"1.12.2","mainClass":"net.minecraft.launchwrapper.Launch","minecraftArguments":"--tweakClass unknown.Tweaker"}`))
	_, err := resolveLegacyLaunch0278(root, "forge", mc, child, 8, []vanillaTarget{currentVanillaTarget()})
	if err == nil || !strings.Contains(err.Error(), "tweaker") {
		t.Fatalf("unknown tweaker accepted: %v", err)
	}
	putLegacyTestFile0278(t, root, child, []byte(`{"id":"forge","inheritsFrom":"1.12.2","mainClass":"net.minecraft.launchwrapper.Launch","minecraftArguments":"--tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker","libraries":[{"name":"unknown:missing:1"}]}`))
	_, err = resolveLegacyLaunch0278(root, "forge", mc, child, 8, []vanillaTarget{currentVanillaTarget()})
	if err == nil || !strings.Contains(err.Error(), "missing classpath") {
		t.Fatalf("missing library accepted: %v", err)
	}
	if _, err = resolveLegacyLaunch0278(root, "forge", mc, child, 17, []vanillaTarget{currentVanillaTarget()}); err == nil {
		t.Fatal("unverified Java 17 bridge accepted for classic Forge")
	}
}
func TestLegacyAdapters0278ArgumentsAndSecrets(t *testing.T) {
	args, err := splitLegacyArguments0278(`--username "Test Player" --tweakClass test.Main`)
	if err != nil || len(args) != 4 || args[1] != "Test Player" {
		t.Fatalf("split %v %v", args, err)
	}
	if _, err = splitLegacyArguments0278(`--username "broken`); err == nil {
		t.Fatal("unterminated quote accepted")
	}
	expanded, err := expandLegacyArgs0278([]string{"--username", "${auth_player_name}", "${game_directory}"}, map[string]string{"auth_player_name": "Player One", "game_directory": "/tmp/directory with spaces"})
	if err != nil || expanded[1] != "Player One" || expanded[2] != "/tmp/directory with spaces" {
		t.Fatalf("safe argv replacement %v %v", expanded, err)
	}
	if _, err = expandLegacyArgs0278([]string{"${unknown_secret}"}, map[string]string{}); err == nil {
		t.Fatal("unknown placeholder accepted")
	}
}
func TestLegacyAdapters0278VanillaFactoryEndToEnd(t *testing.T) {
	client := []byte("legacy-client")
	asset := []byte("legacy-asset")
	assets := fixtureFactoryAssets0271(asset)
	assetHash := sha1hex(asset)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		version, _ := json.Marshal(map[string]any{
			"id": "1.12.2", "type": "release", "mainClass": "net.minecraft.client.main.Main",
			"assets": "1.12", "assetIndex": map[string]any{"id": "1.12", "url": base + "/assets-index", "sha1": sha1hex(assets), "size": len(assets)},
			"downloads":          map[string]any{"client": map[string]any{"url": base + "/client", "sha1": sha1hex(client), "size": len(client)}},
			"minecraftArguments": "--username ${auth_player_name} --gameDir ${game_directory}", "libraries": []any{},
		})
		switch r.URL.Path {
		case "/manifest":
			_ = json.NewEncoder(w).Encode(MojangVersionManifest{Latest: map[string]string{"release": "1.12.2"}, Versions: []MojangManifestVersion{{ID: "1.12.2", Type: "release", URL: base + "/version", SHA1: sha1hex(version)}}})
		case "/version":
			w.Write(version)
		case "/client":
			w.Write(client)
		case "/assets-index":
			w.Write(assets)
		case "/assets/" + assetHash[:2] + "/" + assetHash:
			w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := filepath.Join(t.TempDir(), "legacy-client")
	o := factoryBuildOptions0271{Loader: "vanilla", Minecraft: "1.12.2", ClientDir: root, VersionManifest: server.URL + "/manifest", AssetBaseURL: server.URL + "/assets", Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client()}
	a, err := executeFactoryBuild0271(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Legacy == nil || a.Legacy.JavaMajor != 8 || len(a.Legacy.Targets[0].Classpath) != 1 {
		t.Fatalf("legacy factory recipe missing: %+v", a.Legacy)
	}
	if err = verifyFactoryPlan0271(root, a); err != nil {
		t.Fatal(err)
	}
	b, err := executeFactoryBuild0271(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if a.ReproducibilitySHA256 != b.ReproducibilitySHA256 {
		t.Fatal("legacy lockfile is not reproducible")
	}
	raw, err := os.ReadFile(legacyLaunchFile0278(root))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(legacyLaunchFile0278(root), append(raw, []byte(" ")...), 0600); err != nil {
		t.Fatal(err)
	}
	// Semantically equivalent whitespace is accepted; modifying the content is not.
	raw = append([]byte{}, raw...)
	raw[0] = '!'
	if err = os.WriteFile(legacyLaunchFile0278(root), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(root, b); err == nil {
		t.Fatal("invalid legacy recipe passed verification")
	}
	if runtime.GOOS == "linux" {
		_ = runtime.GOARCH
	}
}

func TestLegacyAdapters0278RealJavaArgvExecutionAndGates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX Java shim fixture")
	}
	root := filepath.Join(t.TempDir(), "legacy directory with spaces")
	target := currentVanillaTarget()
	parent := "versions/1.12.2/1.12.2.json"
	putLegacyTestFile0278(t, root, parent, []byte(`{"id":"1.12.2","mainClass":"net.minecraft.client.main.Main","minecraftArguments":"--username ${auth_player_name} --accessToken ${auth_access_token} --gameDir ${game_directory} --assetsDir ${game_assets}"}`))
	putLegacyTestFile0278(t, root, "versions/1.12.2/1.12.2.jar", []byte("jar"))
	putLegacyTestFile0278(t, root, "natives/"+target.OS+"/"+target.Arch+"/sample.so", []byte("native"))
	recipe, err := resolveLegacyLaunch0278(root, "vanilla", "1.12.2", parent, 8, []vanillaTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLegacyLaunch0278(root, recipe); err != nil {
		t.Fatal(err)
	}
	outputs, err := scanFactoryOutputs0271(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := factoryPlan0271{
		SchemaVersion: factoryPlanSchema0271, MinecraftVersion: "1.12.2", MinecraftReleaseType: "release", Loader: "vanilla",
		Targets: []vanillaTarget{target}, Java: factoryJava0271{Major: 8}, Launch: factoryLaunch0271{ProfilePath: parent, MainClass: "net.minecraft.client.main.Main", AssetIndex: "1.12", NativesDirectory: "natives"},
		Legacy: recipe, Steps: factorySteps0271("vanilla"), Outputs: outputs,
		Sources: []factorySource0271{{Path: parent, URL: "https://example.test/version.json", Kind: "version-metadata", SHA256: recipe.ParentSHA256, Size: 1}},
	}
	plan.ReproducibilitySHA256, err = factoryDigest0271(plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(plan)
	putLegacyTestFile0278(t, root, ".launcher/install-plan.json", raw)
	java := filepath.Join(t.TempDir(), "java8")
	log := filepath.Join(t.TempDir(), "java.argv")
	javaScript := `#!/bin/sh
if [ "$1" = "-version" ]; then echo 'openjdk version "1.8.0_442"' >&2; exit 0; fi
printf '%s\n' "$@" > "$LEGACY_CAPTURE_ARGV"
`
	if err := os.WriteFile(java, []byte(javaScript), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGACY_CAPTURE_ARGV", log)
	t.Setenv("LAUNCHER_MINECRAFT_ACCESS_TOKEN", "test-token")
	if err := runLegacyClient0278(context.Background(), root, java, "Legacy User", "uuid-test"); err != nil {
		t.Fatal(err)
	}
	argv, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"-cp", "net.minecraft.client.main.Main", "Legacy User", "test-token", root, "1.12.2.jar"} {
		if !strings.Contains(string(argv), part) {
			t.Fatalf("missing argument %q in %s", part, argv)
		}
	}
	if err := runLegacyClient0278(context.Background(), root, java, "Legacy User", ""); err == nil {
		t.Fatal("missing uuid accepted for authenticated launch")
	}
	if err := os.WriteFile(java, []byte("#!/bin/sh\necho 'openjdk version \"21.0.1\"' >&2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := runLegacyClient0278(context.Background(), root, java, "Legacy User", "uuid-test"); err == nil {
		t.Fatal("Java 21 used for classic Java 8 target")
	}
	// Existing immutable 0.27.7 plans do not contain the new recipe.
	old := plan
	old.Legacy = nil
	old.ReproducibilitySHA256, err = factoryDigest0271(old)
	if err != nil {
		t.Fatal(err)
	}
	olderRaw, _ := json.Marshal(old)
	putLegacyTestFile0278(t, root, ".launcher/install-plan.json", olderRaw)
	if err := verifyFactoryPlan0271(root, old); err != nil {
		t.Fatalf("historical lock rejected: %v", err)
	}
}

func TestLegacyAdapters0278ForgeFactoryRealMaterializer(t *testing.T) {
	for _, tc := range []struct{ mc, loaderVersion, tweaker string }{
		{"1.7.10", "10.13.4.1614-1.7.10", "cpw.mods.fml.common.launcher.FMLTweaker"},
		{"1.12.2", "14.23.5.2859", "net.minecraftforge.fml.common.launcher.FMLTweaker"},
	} {
		t.Run(tc.mc, func(t *testing.T) {
			client := []byte("minecraft-client-jar")
			asset := []byte("minecraft-asset")
			assetIndex := fixtureFactoryAssets0271(asset)
			coordinate := "net.minecraftforge:forge:" + tc.mc + "-" + tc.loaderVersion
			universal := []byte("forge-universal-materialized-from-installer")
			profileID := tc.mc + "-forge-" + tc.loaderVersion
			versionInfo := map[string]any{"id": profileID, "inheritsFrom": tc.mc, "mainClass": "net.minecraft.launchwrapper.Launch", "minecraftArguments": "--tweakClass " + tc.tweaker, "libraries": []any{map[string]any{"name": coordinate, "checksums": []string{sha1hex(universal)}, "clientreq": true}}}
			var installer bytes.Buffer
			zw := zip.NewWriter(&installer)
			legacyProfile := map[string]any{"install": map[string]any{"path": coordinate, "filePath": "forge-universal.jar", "minecraft": tc.mc}, "versionInfo": versionInfo}
			rawProfile, _ := json.Marshal(legacyProfile)
			for name, b := range map[string][]byte{"install_profile.json": rawProfile, "forge-universal.jar": universal} {
				f, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.Write(b); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				base := "http://" + r.Host
				vanillaProfile, _ := json.Marshal(map[string]any{"id": tc.mc, "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": "assets-test", "assetIndex": map[string]any{"id": "assets-test", "url": base + "/index", "sha1": sha1hex(assetIndex), "size": len(assetIndex)}, "downloads": map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1hex(client), "size": len(client)}}, "minecraftArguments": "--username ${auth_player_name} --gameDir ${game_directory}", "libraries": []any{}})
				switch r.URL.Path {
				case "/manifest":
					_ = json.NewEncoder(w).Encode(MojangVersionManifest{Latest: map[string]string{"release": tc.mc}, Versions: []MojangManifestVersion{{ID: tc.mc, Type: "release", URL: base + "/version", SHA1: sha1hex(vanillaProfile)}}})
				case "/version":
					w.Write(vanillaProfile)
				case "/index":
					w.Write(assetIndex)
				case "/client.jar":
					w.Write(client)
				case "/installer.jar":
					w.Write(installer.Bytes())
				case "/installer.jar.sha1":
					w.Write([]byte(sha1hex(installer.Bytes())))
				case "/assets/" + sha1hex(asset)[:2] + "/" + sha1hex(asset):
					w.Write(asset)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			installDir := filepath.Join(t.TempDir(), "legacy-forge")
			java := filepath.Join(t.TempDir(), "java")
			if runtime.GOOS != "windows" {
				if err := os.WriteFile(java, []byte("#!/bin/sh\necho 'java version \"1.8.0_402\"' >&2\n"), 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Skip("fixture Java launcher is POSIX")
			}
			o := factoryBuildOptions0271{Loader: "forge", Minecraft: tc.mc, LoaderVersion: tc.loaderVersion, ClientDir: installDir,
				VersionManifest: server.URL + "/manifest", AssetBaseURL: server.URL + "/assets", InstallerURL: server.URL + "/installer.jar", InstallerSHA1: sha1hex(installer.Bytes()), JavaExecutable: java,
				HTTPClient: server.Client(), Workers: 2, StrictUpstream: true, Targets: []vanillaTarget{currentVanillaTarget()},
			}
			first, err := executeFactoryBuild0271(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if first.Legacy == nil || first.Legacy.Tweaker != tc.tweaker || len(first.Legacy.Targets[0].Classpath) < 2 {
				t.Fatalf("factory did not generate Forge launch classpath: %+v", first.Legacy)
			}
			if err = verifyFactoryPlan0271(installDir, first); err != nil {
				t.Fatal(err)
			}
			second, err := executeFactoryBuild0271(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if second.ReproducibilitySHA256 != first.ReproducibilitySHA256 {
				t.Fatal("Forge legacy replay changed identity")
			}
		})
	}
}

func TestLegacyAdapters0278ModernJava8NotMisclassified(t *testing.T) {
	if legacyFamily0278("vanilla", "1.16.5") || legacyFamily0278("fabric", "1.12.2") {
		t.Fatal("modern Java8 profile incorrectly treated as legacy LaunchWrapper")
	}
}
