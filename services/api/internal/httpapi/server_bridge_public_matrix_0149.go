package httpapi

import "net/http"

type serverBridgeMatrixPlatform0149 struct {
	ID                    string `json:"id"`
	Family                string `json:"family"`
	Role                  string `json:"role"`
	MinVersion            string `json:"minVersion,omitempty"`
	MinMinecraft          string `json:"minMinecraft,omitempty"`
	Artifact              string `json:"artifact"`
	Threading             string `json:"threading,omitempty"`
	Installation          string `json:"installation"`
	Coverage              string `json:"coverage"`
	Status                string `json:"status"`
	ProtocolVersion       int    `json:"protocolVersion"`
	Java                  []int  `json:"java"`
	ClientModRequired     bool   `json:"clientModRequired"`
	CryptographicIdentity bool   `json:"cryptographicNodeIdentity"`
	ArtifactIntegrity     bool   `json:"artifactIntegrity"`
	OneTimeJoin           bool   `json:"oneTimeJoin"`
	HandoffSource         bool   `json:"handoffSource"`
	HandoffTarget         bool   `json:"handoffTarget"`
}

func serverBridgeMatrixPlatforms0149(version string) []serverBridgeMatrixPlatform0149 {
	common := func(id, family, role, minVersion, minMinecraft, artifact, threading, coverage string) serverBridgeMatrixPlatform0149 {
		return serverBridgeMatrixPlatform0149{
			ID: id, Family: family, Role: role, MinVersion: minVersion, MinMinecraft: minMinecraft,
			Artifact: artifact, Threading: threading, Installation: "drop-in-zero-patch", Coverage: coverage,
			Status: "supported", ProtocolVersion: serverBridgeProtocolV2, Java: []int{21}, ClientModRequired: false,
			CryptographicIdentity: true, ArtifactIntegrity: true, OneTimeJoin: true,
			HandoffSource: role == "proxy", HandoffTarget: role == "backend",
		}
	}
	return []serverBridgeMatrixPlatform0149{
		common("velocity", "proxy", "proxy", "3.3.0", "", "neverlauncher-velocity-bridge-"+version+".jar", "async EventTask + dedicated network executor", "runtime-e2e"),
		common("bungeecord", "proxy", "proxy", "1.21-R0.1", "", "neverlauncher-bungeecord-bridge-"+version+".jar", "PreLogin intent + dedicated network executor", "runtime-e2e"),
		common("waterfall", "proxy", "proxy", "1.21", "", "neverlauncher-waterfall-bridge-"+version+".jar", "PreLogin intent + dedicated network executor", "runtime-e2e"),
		common("bukkit", "bukkit", "backend", "", "1.21.1", "neverlauncher-bukkit-bridge-"+version+".jar", "Bukkit-compatible listener + dedicated network executor", "build-compatibility"),
		common("spigot", "bukkit", "backend", "", "1.21.1", "neverlauncher-spigot-bridge-"+version+".jar", "Bukkit-family listener + dedicated network executor", "runtime-e2e"),
		common("paper", "bukkit", "backend", "", "1.21.1", "neverlauncher-paper-bridge-"+version+".jar", "Bukkit-family listener + dedicated network executor", "runtime-e2e"),
		common("purpur", "bukkit", "backend", "", "1.21.1", "neverlauncher-purpur-bridge-"+version+".jar", "Bukkit-family listener + dedicated network executor", "runtime-e2e"),
		common("folia", "bukkit", "backend", "", "1.21.1", "neverlauncher-folia-bridge-"+version+".jar", "Folia-safe dedicated network executor", "runtime-e2e"),
		common("fabric", "fabric", "backend", "", "1.21.1", "neverlauncher-fabric-bridge-"+version+".jar", "Fabric login synchronizer + bounded validation executor", "runtime-e2e"),
		common("forge", "modloader", "backend", "", "1.21.1", "neverlauncher-forge-bridge-"+version+".jar", "PlayerNegotiationEvent future + bounded validation executor", "runtime-e2e"),
		common("neoforge", "modloader", "backend", "", "1.21.1", "neverlauncher-neoforge-bridge-"+version+".jar", "PlayerNegotiationEvent future + bounded validation executor", "runtime-e2e"),
	}
}

func (s Server) serverBridgePublicMatrix0149(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": bridgePluginsSchema940,
		"data": map[string]any{
			"schemaVersion":   bridgePluginsSchema940,
			"toolVersion":     s.Version,
			"status":          "supported",
			"protocolVersion": serverBridgeProtocolV2,
			"platforms":       serverBridgeMatrixPlatforms0149(s.Version),
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
				"runtimeEvidenceArtifact": "neverlauncher-minecraft-client-e2e-evidence",
				"matrixSource":            "serverbridge/targets.json",
			},
		},
	})
}
