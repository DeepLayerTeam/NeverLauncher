package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const (
	serverBridgeGAVersion0200             = "ServerBridge 3 GA"
	serverBridgeV3FrozenFeatureDigest0200 = "098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc"
	serverBridgeV2CompatibilityMode0200   = "compatibility-deprecated"
	serverBridgeV3GAMode0200              = "ga-frozen"
)

// serverBridgeV3FrozenFeatureSet0200 is the GA wire feature set. Protocol v3 is
// frozen in 0.20.0: later product capabilities must use a new protocol version
// instead of silently mutating the meaning of v3 negotiation.
func serverBridgeV3FrozenFeatureSet0200() []string {
	return []string{
		serverBridgeFeatureCapabilityNegotiation,
		serverBridgeFeatureFlags,
		serverBridgeFeatureRollingUpgrade,
		serverBridgeFeatureNodeSignatures,
		serverBridgeFeatureNonceReplay,
		serverBridgeFeatureArtifactIntegrity,
		serverBridgeFeatureOneTimeJoin,
		serverBridgeFeatureOneTimeHandoff,
		serverBridgeFeatureRuntimeTopology,
		serverBridgeFeatureRuntimeDiscovery,
		serverBridgeFeatureRuntimeIdentity,
		serverBridgeFeatureServerTelemetry,
		serverBridgeFeatureEventStream,
		serverBridgeFeatureControlAPI,
		serverBridgeFeatureHAControlPlane,
		serverBridgeFeatureRoutingV2,
		serverBridgeFeaturePlayerSessionV3,
		serverBridgeFeatureV3SigningDomain01912,
		serverBridgeFeatureDowngradeProtection01912,
		serverBridgeFeatureCommandSignatures01912,
		serverBridgeFeatureEventSignatures01912,
		serverBridgeFeatureRuntimeBinding01912,
		serverBridgeFeatureOnlineKeyRotation01912,
	}
}

func serverBridgeV3FeatureDigest0200(features []string) string {
	normalized := normalizeBridgeFeatures0191(features)
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

func serverBridgeV3Frozen0200() bool {
	return serverBridgeV3FeatureDigest0200(serverBridgeV3Features0191) == serverBridgeV3FrozenFeatureDigest0200
}

func serverBridgeProtocolMode0200(protocol int) string {
	if protocol == serverBridgeProtocolV3 {
		return serverBridgeV3GAMode0200
	}
	if protocol == serverBridgeProtocolV2 {
		return serverBridgeV2CompatibilityMode0200
	}
	return "unsupported"
}

func markServerBridgeProtocolResponse0200(w http.ResponseWriter, protocol int) {
	w.Header().Set("X-NeverLauncher-ServerBridge-Protocol", serverBridgeProtocolMode0200(protocol))
	if protocol == serverBridgeProtocolV2 {
		w.Header().Set("Deprecation", "true")
		w.Header().Set("X-NeverLauncher-ServerBridge-Migrate-To", "3")
	}
}

type serverBridgeOverviewNode0200 struct {
	ID                        string                       `json:"id"`
	Name                      string                       `json:"name"`
	Kind                      string                       `json:"kind"`
	ProjectID                 string                       `json:"projectId"`
	ProfileID                 string                       `json:"profileId,omitempty"`
	Status                    string                       `json:"status"`
	ProtocolVersion           int                          `json:"protocolVersion"`
	ProtocolMode              string                       `json:"protocolMode"`
	ProtocolMigrationRequired bool                         `json:"protocolMigrationRequired"`
	UpgradeRecommended        bool                         `json:"upgradeRecommended"`
	PluginVersion             string                       `json:"pluginVersion,omitempty"`
	IntegrityStatus           string                       `json:"integrityStatus,omitempty"`
	LastHeartbeatAt           time.Time                    `json:"lastHeartbeatAt,omitempty"`
	Fresh                     bool                         `json:"fresh"`
	RuntimeID                 string                       `json:"runtimeId,omitempty"`
	RuntimeEpoch              int64                        `json:"runtimeEpoch,omitempty"`
	RuntimeTransition         string                       `json:"runtimeTransition,omitempty"`
	Hostname                  string                       `json:"hostname,omitempty"`
	MinecraftVersion          string                       `json:"minecraftVersion,omitempty"`
	JavaVersion               string                       `json:"javaVersion,omitempty"`
	LoaderName                string                       `json:"loaderName,omitempty"`
	LoaderVersion             string                       `json:"loaderVersion,omitempty"`
	ServerBrand               string                       `json:"serverBrand,omitempty"`
	Telemetry                 *model.ServerBridgeTelemetry `json:"telemetry,omitempty"`
}

func (s Server) serverBridgeOverview0200(w http.ResponseWriter, r *http.Request) {
	if !serverBridgeV3Frozen0200() {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_protocol_v3_freeze_mismatch")
		return
	}
	now := time.Now().UTC()
	freshAfter := now.Add(-2 * time.Minute)
	servers := s.State.ServerBridge.listServers()
	nodes := make([]serverBridgeOverviewNode0200, 0, len(servers))
	protocolCounts := map[string]int{"v3Ga": 0, "v2Compatibility": 0, "unsupported": 0}
	freshCount := 0
	migrationCount := 0
	upgradeCount := 0
	for _, server := range servers {
		mode := serverBridgeProtocolMode0200(server.ProtocolVersion)
		switch mode {
		case serverBridgeV3GAMode0200:
			protocolCounts["v3Ga"]++
		case serverBridgeV2CompatibilityMode0200:
			protocolCounts["v2Compatibility"]++
		default:
			protocolCounts["unsupported"]++
		}
		fresh := !server.LastHeartbeatAt.IsZero() && server.LastHeartbeatAt.After(freshAfter)
		if fresh {
			freshCount++
		}
		migrationRequired := server.ProtocolVersion == serverBridgeProtocolV2
		if migrationRequired {
			migrationCount++
		}
		upgradeRecommended := strings.TrimSpace(server.PluginVersion) != "" && strings.TrimSpace(server.PluginVersion) != s.Version
		if upgradeRecommended {
			upgradeCount++
		}
		nodes = append(nodes, serverBridgeOverviewNode0200{
			ID: server.ID, Name: server.Name, Kind: server.Kind, ProjectID: server.ProjectID, ProfileID: server.ProfileID,
			Status: server.Status, ProtocolVersion: server.ProtocolVersion, ProtocolMode: mode,
			ProtocolMigrationRequired: migrationRequired, UpgradeRecommended: upgradeRecommended, PluginVersion: server.PluginVersion,
			IntegrityStatus: server.IntegrityStatus, LastHeartbeatAt: server.LastHeartbeatAt, Fresh: fresh,
			RuntimeID: server.RuntimeID, RuntimeEpoch: server.RuntimeEpoch, RuntimeTransition: server.RuntimeTransition,
			Hostname: server.Hostname, MinecraftVersion: server.MinecraftVersion, JavaVersion: server.JavaVersion,
			LoaderName: server.LoaderName, LoaderVersion: server.LoaderVersion, ServerBrand: server.ServerBrand, Telemetry: server.Telemetry,
		})
	}

	topology := []model.ServerBridgeTopologyEdge{}
	if backend := s.State.ServerBridge.backendV2(); backend != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		items, err := backend.ListServerBridgeTopology(ctx)
		cancel()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "ServerBridge topology unavailable")
			return
		}
		topology = items
	}

	controls, err := s.State.ServerBridge.recentControls0200(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "ServerBridge control history unavailable")
		return
	}
	controlCounts := map[string]int{}
	for _, item := range controls {
		controlCounts[item.Status]++
	}

	audit := make([]model.AuditEvent, 0, 100)
	for _, item := range s.Repo.ListAuditEvents() {
		if strings.HasPrefix(strings.ToLower(item.Action), "serverbridge:") {
			audit = append(audit, item)
		}
	}
	sort.Slice(audit, func(i, j int) bool { return audit[i].CreatedAt.After(audit[j].CreatedAt) })
	if len(audit) > 100 {
		audit = audit[:100]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": bridgePluginsSchema940,
		"data": map[string]any{
			"schemaVersion": "3.0-ga",
			"toolVersion":   s.Version,
			"release":       serverBridgeGAVersion0200,
			"protocol": map[string]any{
				"version":       3,
				"status":        serverBridgeV3GAMode0200,
				"frozen":        true,
				"featureDigest": serverBridgeV3FrozenFeatureDigest0200,
				"v2Mode":        serverBridgeV2CompatibilityMode0200,
			},
			"metrics": map[string]any{
				"nodesTotal": len(nodes), "nodesFresh": freshCount, "nodesStale": len(nodes) - freshCount,
				"protocol": protocolCounts, "protocolMigrationsRequired": migrationCount, "upgradesRecommended": upgradeCount,
				"topologyEdges": len(topology), "recentControlCommands": len(controls), "controlStatus": controlCounts, "recentAuditEvents": len(audit),
			},
			"nodes":       nodes,
			"topology":    topology,
			"control":     controls,
			"audit":       audit,
			"generatedAt": now.Format(time.RFC3339Nano),
		},
	})
}

func (b *serverBridgeStore) recentControls0200(parent context.Context, limit int) ([]model.ServerBridgeControlCommand, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		defer cancel()
		return backend.ListServerBridgeRecentControlCommands(ctx, limit)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	items := make([]model.ServerBridgeControlCommand, 0, len(b.controlCommands))
	for _, item := range b.controlCommands {
		item.LeaseToken = ""
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
