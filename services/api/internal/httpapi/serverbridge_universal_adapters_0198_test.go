package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func TestUniversalServerAdapterKinds0198(t *testing.T) {
	for _, kind := range []string{"velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia", "fabric", "quilt", "forge", "neoforge", "sponge", "vanilla"} {
		if !validBridgeServerKindV2(kind) {
			t.Fatalf("0.19.8 canonical adapter kind rejected: %s", kind)
		}
	}
	for _, kind := range []string{"mohist", "arclight", "magma", "catserver", "banner", "cardboard", "hybrid"} {
		if validBridgeServerKindV2(kind) {
			t.Fatalf("hybrid core leaked into universal cohort: %s", kind)
		}
	}
}

func TestUniversalAdapterIntegrityNamespaces0198(t *testing.T) {
	q := strings.Repeat("c", 64)
	s := strings.Repeat("d", 64)
	v := strings.Repeat("e", 64)
	cfg := config.Config{Environment: "test", BridgeReleaseAllowlistJSON: `{"0.19.8":{"velocitySha256":["` + strings.Repeat("1", 64) + `"],"paperSha256":["` + strings.Repeat("2", 64) + `"],"purpurSha256":["` + strings.Repeat("3", 64) + `"],"bukkitSha256":["` + strings.Repeat("4", 64) + `"],"spigotSha256":["` + strings.Repeat("5", 64) + `"],"foliaSha256":["` + strings.Repeat("6", 64) + `"],"bungeeCordSha256":["` + strings.Repeat("7", 64) + `"],"waterfallSha256":["` + strings.Repeat("8", 64) + `"],"fabricSha256":["` + strings.Repeat("9", 64) + `"],"forgeSha256":["` + strings.Repeat("a", 64) + `"],"neoforgeSha256":["` + strings.Repeat("b", 64) + `"],"quiltSha256":["` + q + `"],"spongeSha256":["` + s + `"],"vanillaSha256":["` + v + `"]}}`}
	srv := Server{Config: cfg}
	policies, err := srv.bridgeReleasePolicies0135()
	if err != nil {
		t.Fatal(err)
	}
	p := policies["0.19.8"]
	if got := bridgeHashesForKind0135(p, "quilt"); len(got) != 1 || got[0] != q {
		t.Fatalf("quilt integrity namespace mismatch: %v", got)
	}
	if got := bridgeHashesForKind0135(p, "sponge"); len(got) != 1 || got[0] != s {
		t.Fatalf("sponge integrity namespace mismatch: %v", got)
	}
	if got := bridgeHashesForKind0135(p, "vanilla"); len(got) != 1 || got[0] != v {
		t.Fatalf("vanilla integrity namespace mismatch: %v", got)
	}
}
