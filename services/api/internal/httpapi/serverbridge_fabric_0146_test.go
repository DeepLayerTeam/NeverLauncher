package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func TestServerBridgeFabricKind0146(t *testing.T) {
	if !validBridgeServerKindV2("fabric") {
		t.Fatal("fabric ServerBridge kind rejected")
	}
	for _, kind := range []string{"fabric-server", "fabricmc", "fabric_loader"} {
		if validBridgeServerKindV2(kind) {
			t.Fatalf("ambiguous Fabric kind %q accepted", kind)
		}
	}
}

func TestServerBridgeFabricIntegrityAllowlist0146(t *testing.T) {
	fabricHash := strings.Repeat("9", 64)
	cfg := config.Config{Environment: "test", BridgeReleaseAllowlistJSON: `{"0.14.6":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"],"fabricSha256":["` + fabricHash + `"]}}`}
	s := Server{Version: "0.14.6", Config: cfg}
	server := bridgeServerRecord{ID: "fabric-0146", Kind: "fabric"}
	decision := s.validateBridgePluginMeasurement0135(server, "fabric", "0.14.6", fabricHash)
	if !decision.Allowed || !decision.Required || decision.Reason != "bridge_integrity_verified" {
		t.Fatalf("Fabric matching release hash rejected: %+v", decision)
	}
	decision = s.validateBridgePluginMeasurement0135(server, "fabric", "0.14.6", strings.Repeat("4", 64))
	if decision.Allowed || decision.Reason != "bridge_integrity_hash_rejected" {
		t.Fatalf("Fabric accepted non-Fabric release hash: %+v", decision)
	}
}

func TestBridgePluginsManifestIncludesFabric0146(t *testing.T) {
	manifest := bridgePluginsManifest940("0.14.6")
	artifacts, ok := manifest["artifacts"].([]map[string]any)
	if !ok {
		t.Fatalf("unexpected artifacts type: %T", manifest["artifacts"])
	}
	var fabric map[string]any
	for _, artifact := range artifacts {
		if artifact["id"] == "fabric" {
			fabric = artifact
			break
		}
	}
	if fabric == nil {
		t.Fatal("bridge manifest missing Fabric artifact")
	}
	if fabric["descriptor"] != "fabric.mod.json" || fabric["serverType"] != "fabric" || fabric["mainClass"] != "ru.neverlauncher.bridge.fabric.NeverLauncherFabricBridge" {
		t.Fatalf("invalid Fabric manifest descriptor: %#v", fabric)
	}
	if required, ok := fabric["clientModRequired"].(bool); !ok || required {
		t.Fatalf("Fabric Server Bridge must be server-only without client mod requirement: %#v", fabric)
	}
}
