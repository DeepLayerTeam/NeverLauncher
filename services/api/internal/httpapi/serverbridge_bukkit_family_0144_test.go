package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func TestServerBridgeBukkitFamilyKinds0144(t *testing.T) {
	for _, kind := range []string{"bukkit", "spigot", "paper", "purpur", "folia"} {
		if !validBridgeServerKindV2(kind) {
			t.Fatalf("Bukkit-family kind %q rejected", kind)
		}
	}
	for _, kind := range []string{"", "forge", "neoforge", "paper-folia", "unknown"} {
		if validBridgeServerKindV2(kind) {
			t.Fatalf("unsupported ServerBridge kind %q accepted", kind)
		}
	}
}

func TestServerBridgeBukkitFamilyIntegrityAllowlist0144(t *testing.T) {
	hashes := map[string]string{
		"velocity": strings.Repeat("1", 64),
		"bukkit":   strings.Repeat("2", 64),
		"spigot":   strings.Repeat("3", 64),
		"paper":    strings.Repeat("4", 64),
		"purpur":   strings.Repeat("5", 64),
		"folia":    strings.Repeat("6", 64),
	}
	cfg := config.Config{Environment: "test", BridgeReleaseAllowlistJSON: `{"0.14.4":{"velocitySha256":["` + hashes["velocity"] + `"],"bukkitSha256":["` + hashes["bukkit"] + `"],"spigotSha256":["` + hashes["spigot"] + `"],"paperSha256":["` + hashes["paper"] + `"],"purpurSha256":["` + hashes["purpur"] + `"],"foliaSha256":["` + hashes["folia"] + `"]}}`}
	s := Server{Version: "0.14.4", Config: cfg}

	for _, kind := range []string{"velocity", "bukkit", "spigot", "paper", "purpur", "folia"} {
		server := bridgeServerRecord{ID: kind + "-0144", Kind: kind}
		decision := s.validateBridgePluginMeasurement0135(server, kind, "0.14.4", hashes[kind])
		if !decision.Allowed || !decision.Required || decision.Reason != "bridge_integrity_verified" {
			t.Fatalf("%s matching release hash rejected: %+v", kind, decision)
		}
		wrong := hashes["velocity"]
		if kind == "velocity" {
			wrong = hashes["paper"]
		}
		decision = s.validateBridgePluginMeasurement0135(server, kind, "0.14.4", wrong)
		if decision.Allowed || decision.Reason != "bridge_integrity_hash_rejected" {
			t.Fatalf("%s cross-platform artifact hash accepted: %+v", kind, decision)
		}
	}
}

func TestBridgePluginsManifestIncludesEntireBukkitFamily0144(t *testing.T) {
	manifest := bridgePluginsManifest940("0.14.4")
	artifacts, ok := manifest["artifacts"].([]map[string]any)
	if !ok {
		t.Fatalf("unexpected artifacts type: %T", manifest["artifacts"])
	}
	got := map[string]bool{}
	for _, artifact := range artifacts {
		if id, _ := artifact["id"].(string); id != "" {
			got[id] = true
		}
	}
	for _, id := range []string{"velocity", "bukkit", "spigot", "paper", "purpur", "folia"} {
		if !got[id] {
			t.Fatalf("bridge manifest missing %s artifact", id)
		}
	}
}
