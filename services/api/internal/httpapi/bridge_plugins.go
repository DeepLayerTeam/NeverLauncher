package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const bridgePluginsSchema940 = apiContractVersion

type bridgePluginHeartbeatRequest940 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	ServerID        string `json:"serverId"`
	ServerType      string `json:"serverType"`
	PluginVersion   string `json:"pluginVersion"`
	PluginSHA256    string `json:"pluginSha256"`
	Hostname        string `json:"hostname,omitempty"`
	PlayersOnline   int    `json:"playersOnline,omitempty"`
}

type bridgeValidateJoinRequest940 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	ServerID        string `json:"serverId"`
	Username        string `json:"username"`
	UUID            string `json:"uuid,omitempty"`
	ServerHash      string `json:"serverHash,omitempty"`
	IP              string `json:"ip,omitempty"`
	ProjectID       string `json:"projectId"`
	ProfileID       string `json:"profileId"`
	Channel         string `json:"channel"`
	PluginVersion   string `json:"pluginVersion"`
	PluginSHA256    string `json:"pluginSha256"`
}

type bridgeAuditEventRequest940 struct {
	ServerID string         `json:"serverId"`
	Event    string         `json:"event"`
	Player   string         `json:"player,omitempty"`
	UUID     string         `json:"uuid,omitempty"`
	Reason   string         `json:"reason,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (s Server) ecosystemBridgePlugins(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": bridgePluginsStatus940(s.Version)})
}

func (s Server) serverBridgePluginManifest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": bridgePluginsManifest940(s.Version)})
}

func (s Server) serverBridgePluginCompatibility(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion":            bridgePluginsSchema940,
		"toolVersion":              s.Version,
		"protocolVersion":          serverBridgeProtocolV2,
		"status":                   "compatible",
		"platforms":                serverBridgeMatrixPlatforms0149(s.Version),
		"requiredBackendEndpoints": []string{"POST /api/v1/server-bridge/validate-join", "POST /api/v1/server-bridge/handoff", "GET /api/v1/server-bridge/topology", "POST /api/v1/server-bridge/servers/{serverId}/heartbeat", "POST /api/v1/server-bridge/audit-event"},
		"trustPolicy":              gameplayTrustPolicy0127,
		"trustEnforcement":         "required",
		"integrityPolicy":          serverBridgeIntegrityPolicy0135,
		"integrityEnforcement":     "release-allowlist-required-in-production",
	}})
}

func (s Server) serverBridgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	server, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-heartbeat-identity-denied"), Actor: "server", Action: "serverbridge:plugin:heartbeat-identity-denied", Target: strings.TrimSpace(r.PathValue("serverId")), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	var req bridgePluginHeartbeatRequest940
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	serverID := firstNonEmpty(strings.TrimSpace(r.PathValue("serverId")), strings.TrimSpace(req.ServerID))
	if serverID == "" {
		writeError(w, http.StatusBadRequest, "serverId обязателен")
		return
	}
	if server.ID != serverID {
		writeError(w, http.StatusForbidden, "serverbridge_node_server_id_mismatch")
		return
	}
	if req.ProtocolVersion != serverBridgeProtocolV2 {
		writeJSON(w, http.StatusUpgradeRequired, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "protocolVersion": serverBridgeProtocolV2, "status": "heartbeat-rejected", "reason": "serverbridge_protocol_unsupported"}})
		return
	}
	req.ServerType = strings.ToLower(strings.TrimSpace(req.ServerType))
	req.PluginVersion = strings.TrimSpace(req.PluginVersion)
	req.PluginSHA256 = strings.ToLower(strings.TrimSpace(req.PluginSHA256))
	if !validBridgeServerKindV2(req.ServerType) || req.PluginVersion == "" || !isSHA256Hex0134(req.PluginSHA256) {
		writeError(w, http.StatusBadRequest, "serverType, pluginVersion и валидный pluginSha256 обязательны для Protocol v2")
		return
	}
	if req.ServerType != strings.ToLower(strings.TrimSpace(server.Kind)) {
		writeError(w, http.StatusConflict, "serverType не совпадает с зарегистрированным типом ServerBridge node")
		return
	}
	decision := s.validateBridgePluginMeasurement0135(server, req.ServerType, req.PluginVersion, req.PluginSHA256)
	if err := s.State.ServerBridge.setIntegrityMeasurement0135(serverID, decision); err != nil {
		writeError(w, http.StatusServiceUnavailable, "ServerBridge PostgreSQL state недоступен")
		return
	}
	if !decision.Allowed {
		_ = s.flushPersistenceState950("server-bridge-plugin-integrity-rejected")
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-integrity-denied"), Actor: server.ID, Action: "serverbridge:plugin:integrity-denied", Target: server.ID + ":" + decision.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "status": "heartbeat-rejected", "serverId": server.ID, "integrity": decision}})
		return
	}
	if err := s.State.ServerBridge.markHeartbeat940(serverID, req.ServerType, req.PluginVersion); err != nil {
		writeError(w, http.StatusServiceUnavailable, "ServerBridge PostgreSQL heartbeat не сохранён")
		return
	}
	// Maintenance is opportunistic and never makes an otherwise valid heartbeat fail.
	// PostgreSQL serializes the actual cleanup across active/active API replicas.
	s.State.ServerBridge.maybeMaintain0149()
	_ = s.flushPersistenceState950("server-bridge-plugin-heartbeat")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-heartbeat"), Actor: server.ID, Action: "serverbridge:plugin:heartbeat", Target: server.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "protocolVersion": serverBridgeProtocolV2, "status": "heartbeat-accepted", "serverId": server.ID, "nodeKeyFingerprint": server.KeyFingerprint, "identityEpoch": server.IdentityEpoch, "serverType": firstNonEmpty(req.ServerType, server.Kind), "pluginVersion": req.PluginVersion, "pluginSha256": req.PluginSHA256, "integrity": decision, "receivedAt": time.Now().UTC().Format(time.RFC3339)}})
}

func (s Server) serverBridgeValidateJoin(w http.ResponseWriter, r *http.Request) {
	server, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	var req bridgeValidateJoinRequest940
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.ServerID = strings.TrimSpace(req.ServerID)
	req.Username = strings.TrimSpace(req.Username)
	if req.ServerID == "" || req.Username == "" {
		writeError(w, http.StatusBadRequest, "serverId и username обязательны")
		return
	}
	if req.ProtocolVersion != serverBridgeProtocolV2 {
		writeJSON(w, http.StatusUpgradeRequired, bridgeValidateResponse940(s.Version, false, "serverbridge_protocol_unsupported", req, bridgeJoinRecord{}))
		return
	}
	if server.ID != req.ServerID {
		writeJSON(w, http.StatusForbidden, bridgeValidateResponse940(s.Version, false, "serverbridge_node_server_id_mismatch", req, bridgeJoinRecord{}))
		return
	}
	bridgeIntegrity := s.evaluateRegisteredBridgeIntegrity0135(server)
	if !bridgeIntegrity.Allowed {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-bridge-integrity-denied"), Actor: server.ID, Action: "serverbridge:validate-join:bridge-integrity-denied", Target: req.Username + ":" + bridgeIntegrity.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		payload := bridgeValidateResponse940(s.Version, false, bridgeIntegrity.Reason, req, bridgeJoinRecord{})
		payload["data"].(map[string]any)["bridgeIntegrity"] = bridgeIntegrity
		writeJSON(w, http.StatusPreconditionFailed, payload)
		return
	}
	if bridgeIntegrity.Required && !validateBridgeRequestMeasurement0135(server, req) {
		bridgeIntegrity.Allowed = false
		bridgeIntegrity.Reason = "bridge_integrity_request_measurement_mismatch"
		payload := bridgeValidateResponse940(s.Version, false, bridgeIntegrity.Reason, req, bridgeJoinRecord{})
		payload["data"].(map[string]any)["bridgeIntegrity"] = bridgeIntegrity
		writeJSON(w, http.StatusPreconditionFailed, payload)
		return
	}
	join, ok := s.State.ServerBridge.hasJoined(req.Username, req.ServerID)
	var handoff model.ServerBridgeHandoff
	fromHandoff := false
	if !ok {
		if h, handoffOK := s.State.ServerBridge.activeHandoff0148(req.Username, req.ServerID); handoffOK {
			handoff = h
			join = bridgeJoinFromHandoff0148(h)
			ok = true
			fromHandoff = true
		}
	}
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-miss"), Actor: server.ID, Action: "serverbridge:validate-join:denied", Target: req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeJSON(w, http.StatusForbidden, bridgeValidateResponse940(s.Version, false, "launcher_session_or_handoff_missing_or_expired", req, bridgeJoinRecord{}))
		return
	}
	if req.ProjectID != "" && req.ProjectID != join.ProjectID {
		writeJSON(w, http.StatusForbidden, bridgeValidateResponse940(s.Version, false, "project_mismatch", req, join))
		return
	}
	if req.ProfileID != "" && req.ProfileID != join.ProfileID {
		writeJSON(w, http.StatusForbidden, bridgeValidateResponse940(s.Version, false, "profile_mismatch", req, join))
		return
	}
	if req.Channel != "" && req.Channel != join.Channel {
		writeJSON(w, http.StatusForbidden, bridgeValidateResponse940(s.Version, false, "channel_mismatch", req, join))
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, join.UserID, join.SessionID, join.TrustedDeviceID, join.BindingEpoch, true)
	if !trust.Allowed {
		if gameplayTrustPermanentFailure0127(trust.Reason) {
			if fromHandoff {
				s.State.ServerBridge.invalidateHandoff0148(handoff.ID)
			} else {
				s.State.ServerBridge.invalidateJoin(req.Username, req.ServerID)
				_ = s.flushPersistenceState950("server-bridge-trust-invalidate")
			}
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-trust-denied"), Actor: server.ID, Action: "serverbridge:validate-join:trust-denied", Target: req.Username + ":" + trust.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		payload := bridgeValidateResponse940(s.Version, false, trust.Reason, req, join)
		payload["data"].(map[string]any)["trust"] = trust
		payload["data"].(map[string]any)["bridgeIntegrity"] = bridgeIntegrity
		writeJSON(w, http.StatusForbidden, payload)
		return
	}
	_, minecraftIntegrity := s.evaluateServerBridgeJoinIntegrity0135(join)
	if !minecraftIntegrity.Allowed {
		if minecraftIntegrityPermanentFailure0135(minecraftIntegrity.Reason) || minecraftIntegrity.Reason == "minecraft_integrity_session_required" || minecraftIntegrity.Reason == "minecraft_integrity_binding_mismatch" {
			if fromHandoff {
				s.State.ServerBridge.invalidateHandoff0148(handoff.ID)
			} else {
				s.State.ServerBridge.invalidateJoin(req.Username, req.ServerID)
				_ = s.flushPersistenceState950("server-bridge-integrity-invalidate")
			}
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-minecraft-integrity-denied"), Actor: server.ID, Action: "serverbridge:validate-join:minecraft-integrity-denied", Target: req.Username + ":" + minecraftIntegrity.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		payload := bridgeValidateResponse940(s.Version, false, minecraftIntegrity.Reason, req, join)
		payload["data"].(map[string]any)["trust"] = trust
		payload["data"].(map[string]any)["integrity"] = minecraftIntegrity
		payload["data"].(map[string]any)["bridgeIntegrity"] = bridgeIntegrity
		writeJSON(w, http.StatusForbidden, payload)
		return
	}
	redemption, redemptionErr := bridgeJoinRedemption0143(r, server)
	if redemptionErr != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_join_redemption_proof_unavailable")
		return
	}
	if fromHandoff {
		consumedHandoff, consumedOK := s.State.ServerBridge.consumeHandoff0148(handoff.ID, redemption)
		if !consumedOK {
			s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-handoff-replay"), Actor: server.ID, Action: "serverbridge:handoff:replay-denied", Target: req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
			writeJSON(w, http.StatusConflict, bridgeValidateResponse940(s.Version, false, "handoff_already_consumed_or_identity_changed", req, bridgeJoinRecord{}))
			return
		}
		join = bridgeJoinFromHandoff0148(consumedHandoff)
	} else {
		consumed, consumedOK := s.State.ServerBridge.consumeJoinV2(join, redemption)
		if !consumedOK {
			s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-replay"), Actor: server.ID, Action: "serverbridge:validate-join:replay-denied", Target: req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
			writeJSON(w, http.StatusConflict, bridgeValidateResponse940(s.Version, false, "join_ticket_already_consumed", req, bridgeJoinRecord{}))
			return
		}
		join = consumed
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-allowed"), Actor: server.ID, Action: "serverbridge:validate-join:allowed", Target: req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	payload := bridgeValidateResponse940(s.Version, true, "session_valid", req, join)
	payload["data"].(map[string]any)["trust"] = trust
	payload["data"].(map[string]any)["integrity"] = minecraftIntegrity
	payload["data"].(map[string]any)["bridgeIntegrity"] = bridgeIntegrity
	payload["data"].(map[string]any)["nodeKeyFingerprint"] = server.KeyFingerprint
	payload["data"].(map[string]any)["identityEpoch"] = server.IdentityEpoch
	payload["data"].(map[string]any)["authorization"] = map[bool]string{true: "proxy-handoff", false: "direct-ticket"}[fromHandoff]
	if fromHandoff {
		payload["data"].(map[string]any)["sourceNodeId"] = handoff.SourceNodeID
		payload["data"].(map[string]any)["handoffId"] = handoff.ID
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s Server) serverBridgeAuditEvent(w http.ResponseWriter, r *http.Request) {
	server, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	var req bridgeAuditEventRequest940
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.ServerID == "" || req.Event == "" {
		writeError(w, http.StatusBadRequest, "serverId и event обязательны")
		return
	}
	if server.ID != strings.TrimSpace(req.ServerID) {
		writeError(w, http.StatusForbidden, "serverbridge_node_server_id_mismatch")
		return
	}
	action := "serverbridge:plugin:" + strings.TrimSpace(req.Event)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-audit"), Actor: server.ID, Action: action, Target: firstNonEmpty(req.Player, req.UUID, req.ServerID), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "status": "accepted", "action": action, "nodeKeyFingerprint": server.KeyFingerprint, "identityEpoch": server.IdentityEpoch}})
}

func (s Server) serverBridgeDiagnostics(w http.ResponseWriter, r *http.Request) {
	ha, haErr := s.State.ServerBridge.haStatus0149()
	maintenance, maintenanceErr := s.State.ServerBridge.maintenanceSnapshot0149()
	haPayload := any(ha)
	if haErr != nil {
		haPayload = map[string]any{"status": "unavailable", "error": haErr.Error()}
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion":   bridgePluginsSchema940,
		"toolVersion":     s.Version,
		"status":          "diagnostics-ready",
		"protocolVersion": serverBridgeProtocolV2,
		"summary":         s.State.ServerBridge.summary(),
		"ha":              haPayload,
		"maintenance":     map[string]any{"last": maintenance, "lastError": maintenanceErr, "coordination": "postgresql-advisory-lock"},
		"plugins":         bridgePluginsManifest940(s.Version)["artifacts"],
		"checks": []map[string]string{
			{"id": "plugin-manifest", "status": "implemented"},
			{"id": "protocol-v2-negotiation", "status": "implemented"},
			{"id": "postgresql-source-of-truth", "status": "implemented"},
			{"id": "ed25519-node-authentication", "status": "implemented"},
			{"id": "single-use-node-nonce", "status": "implemented"},
			{"id": "identity-bound-one-time-join-ticket", "status": "implemented"},
			{"id": "proxy-backend-one-time-handoff", "status": "implemented"},
			{"id": "runtime-learned-topology", "status": "implemented"},
			{"id": "ha-advisory-lock-maintenance", "status": "implemented"},
			{"id": "freshness-aware-topology", "status": "implemented"},
			{"id": "distributed-serverbridge-rate-limit", "status": "implemented"},
			{"id": "zero-patch-plugin-bootstrap", "status": "implemented"},
			{"id": "validate-join", "status": "implemented"},
			{"id": "gameplay-trust-enforcement", "status": "implemented"},
			{"id": "minecraft-integrity-enforcement", "status": "implemented"},
			{"id": "serverbridge-artifact-integrity", "status": "implemented"},
			{"id": "heartbeat", "status": "implemented"},
			{"id": "audit-event", "status": "implemented"},
		},
	}})
}

func bridgeValidateResponse940(version string, allowed bool, reason string, req bridgeValidateJoinRequest940, join bridgeJoinRecord) map[string]any {
	payload := map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion":   bridgePluginsSchema940,
		"toolVersion":     version,
		"protocolVersion": serverBridgeProtocolV2,
		"allowed":         allowed,
		"reason":          reason,
		"serverId":        req.ServerID,
		"username":        req.Username,
		"projectId":       firstNonEmpty(req.ProjectID, join.ProjectID),
		"profileId":       firstNonEmpty(req.ProfileID, join.ProfileID),
		"channel":         firstNonEmpty(req.Channel, join.Channel, "stable"),
		"checkedAt":       time.Now().UTC().Format(time.RFC3339),
	}}
	if allowed {
		payload["data"].(map[string]any)["player"] = map[string]any{"uuid": firstNonEmpty(req.UUID, join.UUID), "username": req.Username}
		payload["data"].(map[string]any)["session"] = sanitizeJoinRecord910(join)
	}
	return payload
}

func bridgePluginsStatus940(version string) map[string]any {
	return map[string]any{
		"schemaVersion":   bridgePluginsSchema940,
		"toolVersion":     version,
		"release":         "NeverLauncher 0.14.10 ServerBridge Migration + stabilization",
		"status":          "bridge-plugins-ready",
		"mode":            "serverbridge-protocol-v2",
		"protocolVersion": serverBridgeProtocolV2,
		"implemented":     []string{"Protocol v2 wire negotiation", "Ed25519 request signatures", "single-use node nonce replay protection", "identity-bound one-time join ticket redemption", "one-time proxy-to-backend handoff", "runtime-learned PostgreSQL topology", "HA advisory-lock maintenance", "freshness-aware topology", "distributed ServerBridge rate limiting", "public ServerBridge matrix", "zero-patch config bootstrap", "shared proxy-family runtime", "Velocity plugin source and jar", "BungeeCord plugin source and jar", "Waterfall plugin source and jar", "Bukkit plugin source and jar", "Spigot plugin source and jar", "Paper plugin source and jar", "Purpur plugin source and jar", "Folia plugin source and jar", "Fabric server-only mod source and jar", "Forge server-only mod source and jar", "NeoForge server-only mod source and jar", "shared modloader-family runtime", "pre-world PlayerNegotiationEvent login gating", "shared Bukkit-family runtime", "Folia-safe network scheduling", "runtime platform mismatch fail-closed", "plugin manifest", "validate-join endpoint", "live session/device/risk enforcement", "Minecraft Guard integrity enforcement", "ServerBridge JAR SHA-256 enforcement", "binding-epoch invalidation", "heartbeat endpoint", "audit-event endpoint", "plugin diagnostics"},
		"commands":        []string{"nl bridge-plugin status", "nl bridge-plugin build", "nl bridge-plugin smoke", "nl bridge-plugin generate-config velocity", "nl bridge-plugin compatibility"},
		"artifacts":       bridgePluginsManifest940(version)["artifacts"],
	}
}

func bridgePluginsManifest940(version string) map[string]any {
	return map[string]any{
		"schemaVersion":   bridgePluginsSchema940,
		"toolVersion":     version,
		"status":          "published",
		"protocolVersion": serverBridgeProtocolV2,
		"artifacts": []map[string]any{
			{"id": "velocity", "name": "NeverLauncher Velocity Bridge", "file": fmt.Sprintf("neverlauncher-velocity-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-velocity-bridge-%s.jar", version), "serverType": "velocity", "descriptor": "velocity-plugin.json", "mainClass": "ru.neverlauncher.bridge.velocity.NeverLauncherVelocityBridge"},
			{"id": "bungeecord", "name": "NeverLauncher BungeeCord Bridge", "file": fmt.Sprintf("neverlauncher-bungeecord-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-bungeecord-bridge-%s.jar", version), "serverType": "bungeecord", "descriptor": "bungee.yml", "mainClass": "ru.neverlauncher.bridge.bungeecord.NeverLauncherBungeeCordBridge"},
			{"id": "waterfall", "name": "NeverLauncher Waterfall Bridge", "file": fmt.Sprintf("neverlauncher-waterfall-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-waterfall-bridge-%s.jar", version), "serverType": "waterfall", "descriptor": "bungee.yml", "mainClass": "ru.neverlauncher.bridge.waterfall.NeverLauncherWaterfallBridge"},
			{"id": "bukkit", "name": "NeverLauncher Bukkit Bridge", "file": fmt.Sprintf("neverlauncher-bukkit-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-bukkit-bridge-%s.jar", version), "serverType": "bukkit", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.bukkit.NeverLauncherBukkitBridge"},
			{"id": "spigot", "name": "NeverLauncher Spigot Bridge", "file": fmt.Sprintf("neverlauncher-spigot-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-spigot-bridge-%s.jar", version), "serverType": "spigot", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.spigot.NeverLauncherSpigotBridge"},
			{"id": "paper", "name": "NeverLauncher Paper Bridge", "file": fmt.Sprintf("neverlauncher-paper-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-paper-bridge-%s.jar", version), "serverType": "paper", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.paper.NeverLauncherPaperBridge"},
			{"id": "purpur", "name": "NeverLauncher Purpur Bridge", "file": fmt.Sprintf("neverlauncher-purpur-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-purpur-bridge-%s.jar", version), "serverType": "purpur", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.purpur.NeverLauncherPurpurBridge"},
			{"id": "folia", "name": "NeverLauncher Folia Bridge", "file": fmt.Sprintf("neverlauncher-folia-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-folia-bridge-%s.jar", version), "serverType": "folia", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.folia.NeverLauncherFoliaBridge"},
			{"id": "fabric", "name": "NeverLauncher Fabric Server Bridge", "file": fmt.Sprintf("neverlauncher-fabric-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-fabric-bridge-%s.jar", version), "serverType": "fabric", "descriptor": "fabric.mod.json", "mainClass": "ru.neverlauncher.bridge.fabric.NeverLauncherFabricBridge", "clientModRequired": false},
			{"id": "forge", "name": "NeverLauncher Forge Server Bridge", "file": fmt.Sprintf("neverlauncher-forge-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-forge-bridge-%s.jar", version), "serverType": "forge", "descriptor": "META-INF/mods.toml", "mainClass": "ru.neverlauncher.bridge.forge.NeverLauncherForgeBridge", "clientModRequired": false},
			{"id": "neoforge", "name": "NeverLauncher NeoForge Server Bridge", "file": fmt.Sprintf("neverlauncher-neoforge-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-neoforge-bridge-%s.jar", version), "serverType": "neoforge", "descriptor": "META-INF/neoforge.mods.toml", "mainClass": "ru.neverlauncher.bridge.neoforge.NeverLauncherNeoForgeBridge", "clientModRequired": false},
		},
		"configExamples":   []string{"plugins/velocity-bridge/config.example.yml", "plugins/bungeecord-bridge/config.example.yml", "plugins/waterfall-bridge/config.example.yml", "plugins/bukkit-bridge/config.example.yml", "plugins/spigot-bridge/config.example.yml", "plugins/paper-bridge/config.example.yml", "plugins/purpur-bridge/config.example.yml", "plugins/folia-bridge/config.example.yml", "plugins/fabric-bridge/config.example.yml", "plugins/forge-bridge/config.example.yml", "plugins/neoforge-bridge/config.example.yml"},
		"releaseAllowlist": "artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json",
		"integrityPolicy":  serverBridgeIntegrityPolicy0135,
		"backendEndpoints": []string{"POST /api/v1/server-bridge/validate-join", "POST /api/v1/server-bridge/handoff", "GET /api/v1/server-bridge/topology", "POST /api/v1/server-bridge/servers/{serverId}/heartbeat", "POST /api/v1/server-bridge/audit-event", "GET /api/v1/server-bridge/plugin-compatibility"},
	}
}

func (b *serverBridgeStore) markHeartbeat940(serverID, serverType, pluginVersion string) error {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.TouchServerBridgeNodeHeartbeat(ctx, serverID, serverType, pluginVersion, time.Now().UTC())
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return fmt.Errorf("server bridge node not found")
	}
	if server.Status != "active" || strings.ToLower(strings.TrimSpace(serverType)) != strings.ToLower(strings.TrimSpace(server.Kind)) {
		return fmt.Errorf("server bridge node identity/type is not active")
	}
	server.ProtocolVersion = serverBridgeProtocolV2
	server.LastHeartbeatAt = time.Now().UTC()
	server.Fingerprint = firstNonEmpty(server.Fingerprint, "plugin:"+pluginVersion)
	b.servers[serverID] = server
	return nil
}
