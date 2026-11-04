package httpapi

import (
	"fmt"
	"strings"
	"time"
)

// Это политика МАКСИМАЛЬНЫХ возможностей для подписанных заявлений узла, а не
// доказательство прохождения сертификации Runtime конкретной сборкой Minecraft.
// Отсутствующие возможности не превращаются в неявные разрешения. Wire-протокол
// ServerBridge v3 не меняется.
var serverBridgeFamilies0286 = map[string]string{
	"velocity": "proxy", "bungeecord": "proxy", "waterfall": "proxy",
	"bukkit": "bukkit", "spigot": "bukkit", "paper": "bukkit", "purpur": "bukkit", "folia": "bukkit",
	"fabric": "fabric", "quilt": "quilt", "forge": "modloader", "neoforge": "modloader",
	"sponge": "sponge", "vanilla": "vanilla-sidecar",
}

var serverBridgeControlCaps0286 = map[string]string{
	"player.kick": "adapter.control.kick", "message.broadcast": "adapter.control.broadcast",
	"whitelist.add": "adapter.control.whitelist", "whitelist.remove": "adapter.control.whitelist",
	"whitelist.enable": "adapter.control.whitelist", "whitelist.disable": "adapter.control.whitelist",
	"ban.add": "adapter.control.ban", "ban.remove": "adapter.control.ban",
	"server.save": "adapter.control.save", "server.maintenance": "adapter.control.maintenance",
	"server.drain": "adapter.control.drain", "server.shutdown": "adapter.control.shutdown",
	"server.console": "adapter.control.console",
}

var serverBridgeAdapterCaps0286 = map[string]bool{
	"adapter.auth.login-gate":                  true,
	"adapter.routing.proxy-handoff":            true,
	"adapter.events.player-lifecycle":          true,
	"adapter.events.world-lifecycle":           true,
	"adapter.events.proxy-lifecycle":           true,
	"adapter.telemetry.players":                true,
	"adapter.telemetry.tps":                    true,
	"adapter.telemetry.mspt":                   true,
	"adapter.telemetry.worlds":                 true,
	"adapter.telemetry.bounded-world-counters": true,
	"adapter.control.kick":                     true,
	"adapter.control.broadcast":                true,
	"adapter.control.whitelist":                true,
	"adapter.control.ban":                      true,
	"adapter.control.save":                     true,
	"adapter.control.maintenance":              true,
	"adapter.control.drain":                    true,
	"adapter.control.shutdown":                 true,
	"adapter.control.console":                  true,
	"adapter.api.paper-family":                 true,
	"adapter.scheduler.region-safe":            true,
	"adapter.scheduler.native-server-thread":   true,
	"adapter.sidecar.rcon":                     true,
	"adapter.sidecar.log-tail":                 true,
	"adapter.runtime.artifact-sha256":          true,
}

func verifyAdapterCapabilities0286(platform, serverBrand string, capabilities []string) error {
	family, known := serverBridgeFamilies0286[platform]
	if !known {
		return fmt.Errorf("serverbridge_adapter_platform_unknown")
	}
	brand := strings.ToLower(serverBrand)
	for _, marker := range []string{"mohist", "arclight", "magma", "catserver", "banner", "cardboard"} {
		if strings.Contains(brand, marker) {
			return fmt.Errorf("serverbridge_adapter_hybrid_uncertified")
		}
	}
	role := "backend"
	proxy := family == "proxy"
	if proxy {
		role = "proxy"
	}
	for _, c := range capabilities {
		if !strings.HasPrefix(c, "adapter.") {
			continue
		}
		switch c {
		case "adapter.universal-v1", "adapter.family." + family, "adapter.role." + role:
			continue
		}
		if !serverBridgeAdapterCaps0286[c] {
			return fmt.Errorf("serverbridge_adapter_capability_unknown")
		}
		// Адаптер может объявить подмножество возможностей, но никогда привилегию,
		// которую не реализует его фактический обработчик команд или hook.
		switch {
		case c == "adapter.auth.login-gate" && platform == "vanilla":
			return fmt.Errorf("serverbridge_adapter_login_gate_not_supported")
		case c == "adapter.routing.proxy-handoff" && !proxy,
			c == "adapter.events.proxy-lifecycle" && !proxy,
			c == "adapter.events.world-lifecycle" && (proxy || platform == "sponge"),
			c == "adapter.control.whitelist" && (proxy || platform == "sponge"),
			c == "adapter.control.ban" && (proxy || platform == "sponge"),
			c == "adapter.control.save" && (proxy || platform == "sponge"),
			c == "adapter.control.console" && platform == "sponge",
			c == "adapter.telemetry.tps" && (proxy || platform == "vanilla"),
			c == "adapter.telemetry.mspt" && (proxy || platform == "vanilla"),
			c == "adapter.telemetry.worlds" && (proxy || platform == "vanilla"),
			c == "adapter.telemetry.bounded-world-counters" && !(platform == "paper" || platform == "purpur" || platform == "fabric" || platform == "quilt" || platform == "forge" || platform == "neoforge"),
			c == "adapter.api.paper-family" && !(platform == "paper" || platform == "purpur" || platform == "folia"),
			c == "adapter.scheduler.region-safe" && platform != "folia",
			c == "adapter.scheduler.native-server-thread" && (proxy || platform == "sponge" || platform == "vanilla"),
			(c == "adapter.sidecar.rcon" || c == "adapter.sidecar.log-tail") && platform != "vanilla":
			return fmt.Errorf("serverbridge_adapter_capability_unsupported")
		}
	}
	return nil
}

// Разрешайте команду только по последней аутентифицированной подписанной
// идентичности Runtime текущего узла. Неизвестные и устаревшие Runtime без
// объявленных возможностей не считаются полнофункциональными адаптерами.
func serverBridgeNodeAllowsControl0286(node bridgeServerRecord, commandType string) bool {
	required, ok := serverBridgeControlCaps0286[commandType]
	if !ok || node.RuntimeEpoch < 1 || strings.TrimSpace(node.RuntimeID) == "" {
		return false
	}
	if node.RuntimeLastSeenAt.IsZero() || time.Since(node.RuntimeLastSeenAt) > 90*time.Second || time.Until(node.RuntimeLastSeenAt) > 2*time.Minute {
		return false
	}
	if err := verifyAdapterCapabilities0286(strings.ToLower(node.Kind), node.ServerBrand, node.RuntimeCapabilities); err != nil {
		return false
	}
	for _, capability := range node.RuntimeCapabilities {
		if capability == required {
			return true
		}
	}
	return false
}
