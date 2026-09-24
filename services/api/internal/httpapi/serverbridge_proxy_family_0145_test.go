package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func TestServerBridgeProxyFamilyKinds0145(t *testing.T) {
	for _, kind := range []string{"velocity", "bungeecord", "waterfall"} {
		if !validBridgeServerKindV2(kind) {
			t.Fatalf("proxy-family kind %q rejected", kind)
		}
	}
	for _, kind := range []string{"bungee", "waterfallmc", "velocity-proxy"} {
		if validBridgeServerKindV2(kind) {
			t.Fatalf("ambiguous proxy kind %q accepted", kind)
		}
	}
}

func TestServerBridgeProxyFamilyIntegrityAllowlist0145(t *testing.T) {
	hashes := map[string]string{
		"velocity":   strings.Repeat("1", 64),
		"bungeecord": strings.Repeat("7", 64),
		"waterfall":  strings.Repeat("8", 64),
		"bukkit":     strings.Repeat("2", 64),
		"spigot":     strings.Repeat("3", 64),
		"paper":      strings.Repeat("4", 64),
		"purpur":     strings.Repeat("5", 64),
		"folia":      strings.Repeat("6", 64),
	}
	cfg := config.Config{Environment: "test", BridgeReleaseAllowlistJSON: `{"0.14.5":{"velocitySha256":["` + hashes["velocity"] + `"],"bungeeCordSha256":["` + hashes["bungeecord"] + `"],"waterfallSha256":["` + hashes["waterfall"] + `"],"bukkitSha256":["` + hashes["bukkit"] + `"],"spigotSha256":["` + hashes["spigot"] + `"],"paperSha256":["` + hashes["paper"] + `"],"purpurSha256":["` + hashes["purpur"] + `"],"foliaSha256":["` + hashes["folia"] + `"]}}`}
	s := Server{Version: "0.14.5", Config: cfg}

	for _, kind := range []string{"velocity", "bungeecord", "waterfall"} {
		server := bridgeServerRecord{ID: kind + "-0145", Kind: kind}
		decision := s.validateBridgePluginMeasurement0135(server, kind, "0.14.5", hashes[kind])
		if !decision.Allowed || !decision.Required || decision.Reason != "bridge_integrity_verified" {
			t.Fatalf("%s matching release hash rejected: %+v", kind, decision)
		}
		wrong := hashes["paper"]
		decision = s.validateBridgePluginMeasurement0135(server, kind, "0.14.5", wrong)
		if decision.Allowed || decision.Reason != "bridge_integrity_hash_rejected" {
			t.Fatalf("%s cross-platform artifact hash accepted: %+v", kind, decision)
		}
	}
}

func TestBridgePluginsManifestIncludesProxyFamily0145(t *testing.T) {
	manifest := bridgePluginsManifest940("0.14.5")
	artifacts, ok := manifest["artifacts"].([]map[string]any)
	if !ok {
		t.Fatalf("unexpected artifacts type: %T", manifest["artifacts"])
	}
	got := map[string]map[string]any{}
	for _, artifact := range artifacts {
		if id, _ := artifact["id"].(string); id != "" {
			got[id] = artifact
		}
	}
	for _, id := range []string{"velocity", "bungeecord", "waterfall"} {
		if got[id] == nil {
			t.Fatalf("bridge manifest missing %s artifact", id)
		}
	}
	if got["bungeecord"]["descriptor"] != "bungee.yml" || got["waterfall"]["descriptor"] != "bungee.yml" {
		t.Fatalf("Bungee-compatible artifacts must publish bungee.yml descriptors: %#v %#v", got["bungeecord"], got["waterfall"])
	}
}
