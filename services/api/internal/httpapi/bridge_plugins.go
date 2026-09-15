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
	ServerID      string `json:"serverId"`
	ServerType    string `json:"serverType"`
	PluginVersion string `json:"pluginVersion"`
	Hostname      string `json:"hostname,omitempty"`
	PlayersOnline int    `json:"playersOnline,omitempty"`
}

type bridgeValidateJoinRequest940 struct {
	ServerID   string `json:"serverId"`
	Username   string `json:"username"`
	UUID       string `json:"uuid,omitempty"`
	ServerHash string `json:"serverHash,omitempty"`
	IP         string `json:"ip,omitempty"`
	ProjectID  string `json:"projectId"`
	ProfileID  string `json:"profileId"`
	Channel    string `json:"channel"`
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
		"schemaVersion": bridgePluginsSchema940,
		"toolVersion":   s.Version,
		"status":        "compatible",
		"platforms": []map[string]any{
			{"id": "velocity", "minVersion": "3.3.0", "java": []int{17, 21}, "artifact": "neverlauncher-velocity-bridge-" + s.Version + ".jar"},
			{"id": "paper", "minMinecraft": "1.20.1", "recommendedMinecraft": "1.21.x", "java": []int{17, 21}, "artifact": "neverlauncher-paper-bridge-" + s.Version + ".jar"},
			{"id": "purpur", "minMinecraft": "1.20.1", "recommendedMinecraft": "1.21.x", "java": []int{17, 21}, "artifact": "neverlauncher-purpur-bridge-" + s.Version + ".jar"},
		},
		"requiredBackendEndpoints": []string{"POST /api/v1/server-bridge/validate-join", "POST /api/v1/server-bridge/servers/{serverId}/heartbeat", "POST /api/v1/server-bridge/audit-event"},
	}})
}

func (s Server) serverBridgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req bridgePluginHeartbeatRequest940
	_ = json.NewDecoder(r.Body).Decode(&req)
	serverID := firstNonEmpty(strings.TrimSpace(r.PathValue("serverId")), strings.TrimSpace(req.ServerID))
	if serverID == "" {
		writeError(w, http.StatusBadRequest, "serverId обязателен")
		return
	}
	server, ok := s.State.ServerBridge.verifyServerToken(serverID, bridgeServerTokenFromRequest910(r))
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-heartbeat-denied"), Actor: "server", Action: "serverbridge:plugin:heartbeat-denied", Target: serverID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusUnauthorized, "server token недействителен")
		return
	}
	s.State.ServerBridge.markHeartbeat940(serverID, req.ServerType, req.PluginVersion)
	_ = s.flushPersistenceState950("server-bridge-plugin-heartbeat")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-heartbeat"), Actor: server.ID, Action: "serverbridge:plugin:heartbeat", Target: server.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "status": "heartbeat-accepted", "serverId": server.ID, "serverType": firstNonEmpty(req.ServerType, server.Kind), "pluginVersion": req.PluginVersion, "receivedAt": time.Now().UTC().Format(time.RFC3339)}})
}

func (s Server) serverBridgeValidateJoin(w http.ResponseWriter, r *http.Request) {
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
	server, ok := s.State.ServerBridge.verifyServerToken(req.ServerID, bridgeServerTokenFromRequest910(r))
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-denied-token"), Actor: "server", Action: "serverbridge:validate-join:denied", Target: req.ServerID + "/" + req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeJSON(w, http.StatusUnauthorized, bridgeValidateResponse940(s.Version, false, "server_token_invalid", req, bridgeJoinRecord{}))
		return
	}
	join, ok := s.State.ServerBridge.hasJoined(req.Username, req.ServerID)
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-miss"), Actor: server.ID, Action: "serverbridge:validate-join:denied", Target: req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeJSON(w, http.StatusForbidden, bridgeValidateResponse940(s.Version, false, "launcher_session_missing_or_expired", req, bridgeJoinRecord{}))
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
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("validate-join-allowed"), Actor: server.ID, Action: "serverbridge:validate-join:allowed", Target: req.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, bridgeValidateResponse940(s.Version, true, "session_valid", req, join))
}

func (s Server) serverBridgeAuditEvent(w http.ResponseWriter, r *http.Request) {
	var req bridgeAuditEventRequest940
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.ServerID == "" || req.Event == "" {
		writeError(w, http.StatusBadRequest, "serverId и event обязательны")
		return
	}
	server, ok := s.State.ServerBridge.verifyServerToken(req.ServerID, bridgeServerTokenFromRequest910(r))
	if !ok {
		writeError(w, http.StatusUnauthorized, "server token недействителен")
		return
	}
	action := "serverbridge:plugin:" + strings.TrimSpace(req.Event)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("plugin-audit"), Actor: server.ID, Action: action, Target: firstNonEmpty(req.Player, req.UUID, req.ServerID), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "status": "accepted", "action": action}})
}

func (s Server) serverBridgeDiagnostics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion": bridgePluginsSchema940,
		"toolVersion":   s.Version,
		"status":        "diagnostics-ready",
		"summary":       s.State.ServerBridge.summary(),
		"plugins":       bridgePluginsManifest940(s.Version)["artifacts"],
		"checks": []map[string]string{
			{"id": "plugin-manifest", "status": "implemented"},
			{"id": "validate-join", "status": "implemented"},
			{"id": "heartbeat", "status": "implemented"},
			{"id": "audit-event", "status": "implemented"},
		},
	}})
}

func bridgeValidateResponse940(version string, allowed bool, reason string, req bridgeValidateJoinRequest940, join bridgeJoinRecord) map[string]any {
	payload := map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion": bridgePluginsSchema940,
		"toolVersion":   version,
		"allowed":       allowed,
		"reason":        reason,
		"serverId":      req.ServerID,
		"username":      req.Username,
		"projectId":     firstNonEmpty(req.ProjectID, join.ProjectID),
		"profileId":     firstNonEmpty(req.ProfileID, join.ProfileID),
		"channel":       firstNonEmpty(req.Channel, join.Channel, "stable"),
		"checkedAt":     time.Now().UTC().Format(time.RFC3339),
	}}
	if allowed {
		payload["data"].(map[string]any)["player"] = map[string]any{"uuid": firstNonEmpty(req.UUID, join.UUID), "username": req.Username}
		payload["data"].(map[string]any)["session"] = sanitizeJoinRecord910(join)
	}
	return payload
}

func bridgePluginsStatus940(version string) map[string]any {
	return map[string]any{
		"schemaVersion": bridgePluginsSchema940,
		"toolVersion":   version,
		"release":       "NeverLauncher 0.10.0 Real Bridge Plugins",
		"status":        "bridge-plugins-ready",
		"mode":          "velocity-paper-purpur-server-integration",
		"implemented":   []string{"Velocity plugin source and jar", "Paper plugin source and jar", "Purpur plugin source and jar", "real Velocity/Paper platform APIs", "plugin manifest", "validate-join endpoint", "heartbeat endpoint", "audit-event endpoint", "plugin diagnostics"},
		"commands":      []string{"nl bridge-plugin status", "nl bridge-plugin build", "nl bridge-plugin smoke", "nl bridge-plugin generate-config velocity", "nl bridge-plugin compatibility"},
		"artifacts":     bridgePluginsManifest940(version)["artifacts"],
	}
}

func bridgePluginsManifest940(version string) map[string]any {
	return map[string]any{
		"schemaVersion": bridgePluginsSchema940,
		"toolVersion":   version,
		"status":        "published",
		"artifacts": []map[string]any{
			{"id": "velocity", "name": "NeverLauncher Velocity Bridge", "file": fmt.Sprintf("neverlauncher-velocity-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-velocity-bridge-%s.jar", version), "serverType": "velocity", "descriptor": "velocity-plugin.json", "mainClass": "ru.neverlauncher.bridge.velocity.NeverLauncherVelocityBridge"},
			{"id": "paper", "name": "NeverLauncher Paper Bridge", "file": fmt.Sprintf("neverlauncher-paper-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-paper-bridge-%s.jar", version), "serverType": "paper", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.paper.NeverLauncherPaperBridge"},
			{"id": "purpur", "name": "NeverLauncher Purpur Bridge", "file": fmt.Sprintf("neverlauncher-purpur-bridge-%s.jar", version), "path": fmt.Sprintf("artifacts/plugins/neverlauncher-purpur-bridge-%s.jar", version), "serverType": "purpur", "descriptor": "plugin.yml", "mainClass": "ru.neverlauncher.bridge.purpur.NeverLauncherPurpurBridge"},
		},
		"configExamples":   []string{"plugins/velocity-bridge/config.example.yml", "plugins/paper-bridge/config.example.yml", "plugins/purpur-bridge/config.example.yml"},
		"backendEndpoints": []string{"POST /api/v1/server-bridge/validate-join", "POST /api/v1/server-bridge/servers/{serverId}/heartbeat", "POST /api/v1/server-bridge/audit-event", "GET /api/v1/server-bridge/plugin-compatibility"},
	}
}

func (b *serverBridgeStore) markHeartbeat940(serverID, serverType, pluginVersion string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return
	}
	if serverType != "" {
		server.Kind = strings.ToLower(strings.TrimSpace(serverType))
	}
	server.Status = "active"
	server.Fingerprint = firstNonEmpty(server.Fingerprint, "plugin:"+pluginVersion)
	b.servers[serverID] = server
}
