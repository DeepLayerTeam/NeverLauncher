package httpapi

import "net/http"

type serverBridgeMatrixPlatform0149 struct {
	ID                        string `json:"id"`
	Family                    string `json:"family"`
	Role                      string `json:"role"`
	MinVersion                string `json:"minVersion,omitempty"`
	MinMinecraft              string `json:"minMinecraft,omitempty"`
	Artifact                  string `json:"artifact"`
	Threading                 string `json:"threading,omitempty"`
	Installation              string `json:"installation"`
	Coverage                  string `json:"coverage"`
	Status                    string `json:"status"`
	ProtocolVersion           int    `json:"protocolVersion"`
	SupportedProtocolVersions []int  `json:"supportedProtocolVersions"`
	Java                      []int  `json:"java"`
	ClientModRequired         bool   `json:"clientModRequired"`
	CryptographicIdentity     bool   `json:"cryptographicNodeIdentity"`
	ArtifactIntegrity         bool   `json:"artifactIntegrity"`
	OneTimeJoin               bool   `json:"oneTimeJoin"`
	HandoffSource             bool   `json:"handoffSource"`
	HandoffTarget             bool   `json:"handoffTarget"`
}

func serverBridgeMatrixPlatforms0149(version string) []serverBridgeMatrixPlatform0149 {
	common := func(id, family, role, minVersion, minMinecraft, artifact, threading, coverage string) serverBridgeMatrixPlatform0149 {
		return serverBridgeMatrixPlatform0149{
			ID: id, Family: family, Role: role, MinVersion: minVersion, MinMinecraft: minMinecraft,
			Artifact: artifact, Threading: threading, Installation: "drop-in-zero-patch", Coverage: coverage,
			Status: "supported", ProtocolVersion: serverBridgeProtocolCurrent, SupportedProtocolVersions: append([]int(nil), serverBridgeSupportedProtocols0191...), Java: []int{21}, ClientModRequired: false,
			CryptographicIdentity: true, ArtifactIntegrity: true, OneTimeJoin: true,
			HandoffSource: role == "proxy", HandoffTarget: role == "backend",
		}
	}
	return []serverBridgeMatrixPlatform0149{
		common("velocity", "proxy", "proxy", "3.3.0", "", "launcher-velocity-bridge-"+version+".jar", "async EventTask + dedicated network executor", "runtime-e2e"),
		common("bungeecord", "proxy", "proxy", "1.21-R0.1", "", "launcher-bungeecord-bridge-"+version+".jar", "PreLogin intent + dedicated network executor", "runtime-e2e"),
		common("waterfall", "proxy", "proxy", "1.21", "", "launcher-waterfall-bridge-"+version+".jar", "PreLogin intent + dedicated network executor", "runtime-e2e"),
		common("bukkit", "bukkit", "backend", "", "1.21.1", "launcher-bukkit-bridge-"+version+".jar", "Bukkit-compatible listener + dedicated network executor", "build-compatibility"),
		common("spigot", "bukkit", "backend", "", "1.21.1", "launcher-spigot-bridge-"+version+".jar", "Bukkit-family listener + dedicated network executor", "runtime-e2e"),
		common("paper", "bukkit", "backend", "", "1.21.1", "launcher-paper-bridge-"+version+".jar", "Bukkit-family listener + dedicated network executor", "runtime-e2e"),
		common("purpur", "bukkit", "backend", "", "1.21.1", "launcher-purpur-bridge-"+version+".jar", "Bukkit-family listener + dedicated network executor", "runtime-e2e"),
		common("folia", "bukkit", "backend", "", "1.21.1", "launcher-folia-bridge-"+version+".jar", "Folia-safe dedicated network executor", "runtime-e2e"),
		common("fabric", "fabric", "backend", "", "1.21.1", "launcher-fabric-bridge-"+version+".jar", "Fabric login synchronizer + bounded validation executor", "runtime-e2e"),
		common("quilt", "quilt", "backend", "", "1.21.1", "launcher-quilt-bridge-"+version+".jar", "Quilt server lifecycle + bounded validation executor", "build-compatibility"),
		common("forge", "modloader", "backend", "", "1.21.1", "launcher-forge-bridge-"+version+".jar", "PlayerNegotiationEvent future + bounded validation executor", "runtime-e2e"),
		common("neoforge", "modloader", "backend", "", "1.21.1", "launcher-neoforge-bridge-"+version+".jar", "PlayerNegotiationEvent future + bounded validation executor", "runtime-e2e"),
		common("sponge", "sponge", "backend", "", "1.21.1", "launcher-sponge-bridge-"+version+".jar", "Sponge event lifecycle + bounded validation executor", "build-compatibility"),
		common("vanilla", "vanilla-sidecar", "backend", "", "1.21.1", "launcher-vanilla-bridge-"+version+".jar", "RCON sidecar + bounded polling executor", "sidecar-rcon-e2e"),
	}
}

func (s Server) serverBridgePublicMatrix0149(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": bridgePluginsSchema940,
		"data": map[string]any{
			"schemaVersion":             bridgePluginsSchema940,
			"toolVersion":               s.Version,
			"status":                    "supported",
			"release":                   serverBridgeGAVersion0200,
			"protocolVersion":           serverBridgeProtocolCurrent,
			"supportedProtocolVersions": serverBridgeSupportedProtocols0191,
			"protocolV3Status":          serverBridgeV3GAMode0200,
			"protocolV3Frozen":          serverBridgeV3Frozen0200(),
			"protocolV3FeatureDigest":   serverBridgeV3FrozenFeatureDigest0200,
			"protocolV2Mode":            serverBridgeV2CompatibilityMode0200,
			"protocolV2Deprecated":      true,
			"migrationCommand":          "nl server-bridge migrate-v3",
			"featureFlags":              bridgeFeatureFlags0191(serverBridgeV3Features0191),
			"platforms":                 serverBridgeMatrixPlatforms0149(s.Version),
			"ha": map[string]any{
				"sourceOfTruth":            "postgresql",
				"nodeAuthentication":       "ed25519-signed-requests",
				"replayProtection":         "postgresql-single-use-nonce",
				"maintenance":              "cross-instance-postgresql-advisory-lock",
				"rateLimit":                "distributed-redis-serverbridge-budget",
				"topologyFreshnessSeconds": 120,
			},
			"evidence": map[string]any{
				"policy":                  "exact-commit CI evidence; coverage field distinguishes runtime-e2e from build-compatibility",
				"runtimeEvidenceArtifact": "launcher-minecraft-client-e2e-evidence",
				"matrixSource":            "serverbridge/targets.json",
			},
		},
	})
}
