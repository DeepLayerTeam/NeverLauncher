package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func TestForgeNeoForgeKinds0147(t *testing.T) {
	for _, kind := range []string{"forge", "neoforge"} {
		if !validBridgeServerKindV2(kind) {
			t.Fatalf("%s must be canonical ServerBridge kind", kind)
		}
	}
	for _, kind := range []string{"forge-server", "minecraftforge", "neo-forge", "neoforged"} {
		if validBridgeServerKindV2(kind) {
			t.Fatalf("non-canonical kind %s must be rejected", kind)
		}
	}
}

func TestForgeNeoForgeIntegrityNamespaces0147(t *testing.T) {
	forgeHash := strings.Repeat("a", 64)
	neoHash := strings.Repeat("b", 64)
	cfg := config.Config{Environment: "test", BridgeReleaseAllowlistJSON: `{"0.14.7":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"forgeSha256":["` + forgeHash + `"],"neoforgeSha256":["` + neoHash + `"]}}`}
	s := Server{Version: "0.14.7", Config: cfg}
	if d := s.validateBridgePluginMeasurement0135(bridgeServerRecord{ID: "forge-0147", Kind: "forge"}, "forge", "0.14.7", forgeHash); !d.Allowed {
		t.Fatalf("Forge release hash rejected: %+v", d)
	}
	if d := s.validateBridgePluginMeasurement0135(bridgeServerRecord{ID: "neo-0147", Kind: "neoforge"}, "neoforge", "0.14.7", neoHash); !d.Allowed {
		t.Fatalf("NeoForge release hash rejected: %+v", d)
	}
	if d := s.validateBridgePluginMeasurement0135(bridgeServerRecord{ID: "forge-0147", Kind: "forge"}, "forge", "0.14.7", neoHash); d.Allowed {
		t.Fatal("NeoForge hash must not authorize Forge")
	}
	if d := s.validateBridgePluginMeasurement0135(bridgeServerRecord{ID: "neo-0147", Kind: "neoforge"}, "neoforge", "0.14.7", forgeHash); d.Allowed {
		t.Fatal("Forge hash must not authorize NeoForge")
	}
}

func TestForgeNeoForgeManifest0147(t *testing.T) {
	artifacts := bridgePluginsManifest940("0.14.7")["artifacts"].([]map[string]any)
	seen := map[string]map[string]any{}
	for _, a := range artifacts {
		if id, _ := a["id"].(string); id != "" {
			seen[id] = a
		}
	}
	if seen["forge"]["descriptor"] != "META-INF/mods.toml" || seen["forge"]["mainClass"] != "ru.neverlauncher.bridge.forge.NeverLauncherForgeBridge" {
		t.Fatalf("bad Forge manifest: %+v", seen["forge"])
	}
	if seen["neoforge"]["descriptor"] != "META-INF/neoforge.mods.toml" || seen["neoforge"]["mainClass"] != "ru.neverlauncher.bridge.neoforge.NeverLauncherNeoForgeBridge" {
		t.Fatalf("bad NeoForge manifest: %+v", seen["neoforge"])
	}
}
