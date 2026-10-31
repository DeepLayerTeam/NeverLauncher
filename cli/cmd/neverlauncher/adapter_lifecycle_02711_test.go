package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAdapterLifecycle02711RegistryFingerprintsAndOrder(t *testing.T) {
	for _, loader := range []string{"vanilla", "fabric", "quilt", "forge", "neoforge"} {
		pins := currentFactoryAdapterPins02711(loader)
		steps := factorySteps0271(loader)
		if len(pins) != len(steps) {
			t.Fatalf("%s: steps != pins", loader)
		}
		for i, pin := range pins {
			if pin.ID != steps[i].Adapter || pin.Version == "" || !isSHA256Hex0271(pin.ImplementationSHA256) {
				t.Fatalf("%s invalid pin %+v", loader, pin)
			}
		}
		if !reflect.DeepEqual(pins, currentFactoryAdapterPins02711(loader)) {
			t.Fatalf("%s unstable embedded fingerprint", loader)
		}
	}
	if currentFactoryAdapterPins02711("fabric")[1].ID != "fabric" || currentFactoryAdapterPins02711("quilt")[1].ID != "quilt" {
		t.Fatal("loader adapters lost identity")
	}
	if currentFactoryAdapterPins02711("fabric")[1].ImplementationSHA256 == currentFactoryAdapterPins02711("quilt")[1].ImplementationSHA256 {
		t.Fatal("different adapter IDs require distinct fingerprints")
	}
}

func TestAdapterLifecycle02711ValidationAndCompatibility(t *testing.T) {
	p := factoryPlan0271{Loader: "forge", MinecraftVersion: "1.12.2", Java: factoryJava0271{Major: 17}, Targets: []vanillaTarget{{OS: "linux", Arch: "x64"}}, Steps: factorySteps0271("forge"), AdapterPins: currentFactoryAdapterPins02711("forge")}
	if err := factoryAdapterTargetCheck02711(p); err == nil || !strings.Contains(err.Error(), "Java 8") {
		t.Fatalf("legacy incompatibility accepted: %v", err)
	}
	p.Java.Major = 8
	if err := factoryAdapterTargetCheck02711(p); err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryAdapterPins02711(p); err != nil {
		t.Fatal(err)
	}
	p.AdapterPins[1].ID = "fabric"
	if err := validateFactoryAdapterPins02711(p); err == nil {
		t.Fatal("mismatched adapter pin accepted")
	}
}

func TestAdapterLifecycle02711ExplicitUpgradeAndSourceIntegrity(t *testing.T) {
	client := []byte("locked-vanilla-jar")
	asset := []byte("locked-asset")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/manifest":
			meta := fixtureFactoryMetadata0271(base, "fixture-adapter", client, asset)
			_ = json.NewEncoder(w).Encode(MojangVersionManifest{Latest: map[string]string{"release": "fixture-adapter"}, Versions: []MojangManifestVersion{{ID: "fixture-adapter", Type: "release", URL: base + "/meta", SHA1: sha1hex(meta)}}})
		case "/meta":
			_, _ = w.Write(fixtureFactoryMetadata0271(base, "fixture-adapter", client, asset))
		case "/asset-index.json":
			_, _ = w.Write(fixtureFactoryAssets0271(asset))
		case "/client.jar":
			_, _ = w.Write(client)
		case "/assets/" + sha1hex(asset)[:2] + "/" + sha1hex(asset):
			_, _ = w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := filepath.Join(t.TempDir(), "client")
	opts := factoryBuildOptions0271{Loader: "vanilla", Minecraft: "latest-release", ClientDir: root, VersionManifest: server.URL + "/manifest", AssetBaseURL: server.URL + "/assets", HTTPClient: server.Client(), Workers: 2, StrictUpstream: true}
	built, err := executeFactoryBuild0271(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err = requireCurrentFactoryAdapters02711(built); err != nil {
		t.Fatal(err)
	}
	if _, err = executeFactoryBuild0271(context.Background(), opts); err != nil {
		t.Fatalf("current version replay failed: %v", err)
	}
	// Simulate a previously built client whose adapter was older, with an
	// internally consistent install-plan digest and unchanged on-disk files.
	built.AdapterPins[0].Version = "0.9.0"
	built.ReproducibilitySHA256, err = factoryDigest0271(built)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAtomicBytes(factoryPlanPath0271(root), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(root, built); err != nil {
		t.Fatalf("old plan hash verification should still work: %v", err)
	}
	if err = requireCurrentFactoryAdapters02711(built); err == nil {
		t.Fatal("obsolete adapter passed current-check")
	}
	if _, err = executeFactoryBuild0271(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "--upgrade-adapters") {
		t.Fatalf("silent upgrade accepted: %v", err)
	}
	oldBytes, err := os.ReadFile(factoryPlanPath0271(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(root + ".client-factory.lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock leaked: %v", err)
	}
	if after, err := os.ReadFile(factoryPlanPath0271(root)); err != nil || string(after) != string(oldBytes) {
		t.Fatal("refusal modified client")
	}
	opts.UpgradeAdapters = true
	upgraded, err := executeFactoryBuild0271(context.Background(), opts)
	if err != nil {
		t.Fatalf("explicit upgrade failed: %v", err)
	}
	if upgraded.ReproducibilitySHA256 == built.ReproducibilitySHA256 {
		t.Fatal("adapter upgrade did not change build identity")
	}
	if err = requireCurrentFactoryAdapters02711(upgraded); err != nil {
		t.Fatal(err)
	}
	if err = verifyFactoryPlan0271(root, upgraded); err != nil {
		t.Fatal(err)
	}
	if _, err = executeFactoryBuild0271(context.Background(), opts); err != nil {
		t.Fatalf("repeat explicit build failed: %v", err)
	}
}

func TestAdapterLifecycle02711SourceChangeBlocked(t *testing.T) {
	old := []factorySource0271{{Path: "mods/a.jar", SHA256: strings.Repeat("a", 64), Size: 10}}
	fresh := []factorySource0271{{Path: "mods/a.jar", SHA256: strings.Repeat("b", 64), Size: 10}}
	if err := checkAdapterUpgradeSources02711(old, fresh); err == nil {
		t.Fatal("upgraded adapter replaced pinned source")
	}
	fresh[0].SHA256 = old[0].SHA256
	if err := checkAdapterUpgradeSources02711(old, fresh); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterLifecycle02711ProcessorJournalInvalidation(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, ".launcher", "installers", "forge", "forge-1", "processor-journal.json")
	if err := os.MkdirAll(filepath.Dir(journal), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte(`{"state":"completed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(filepath.Dir(journal), "installer.jar")
	if err := os.WriteFile(keep, []byte("pinned-jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := invalidateFactoryProcessorRecovery02711(root, "quilt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("unrelated loader journal deleted:", err)
	}
	if err := invalidateFactoryProcessorRecovery02711(root, "forge"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete journal remains: %v", err)
	}
	if raw, err := os.ReadFile(keep); err != nil || string(raw) != "pinned-jar" {
		t.Fatal("installer deleted or modified")
	}
}
