package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type networkCapacityUpdate0288 struct {
	CapacityLimit    json.RawMessage `json:"capacityLimit"`
	RuntimeID        string          `json:"runtimeId"`
	RuntimeEpoch     int64           `json:"runtimeEpoch"`
	ExpectedRevision *int64          `json:"expectedRevision"`
}

// An operator limit is not a command to the Minecraft plugin. It is an
// independently-enforced, PostgreSQL-backed ceiling in the actual admission
// paths. Client-supplied runtime and revision prevent stale Admin writes.
func (s Server) serverBridgeNetworkCapacity0288(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("serverId"))
	node, err := s.State.ServerBridge.getNode0142(nodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid admin session")
		return
	}
	if !s.authorizeClaims(r, claims, "project:read", node.ProjectID, "server", nodeID).Allowed {
		writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
		return
	}
	if !s.authorizeClaims(r, claims, "gameserver:traffic", node.ProjectID, "server", nodeID).Allowed {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("network-capacity-denied"), Actor: firstNonEmpty(claims.Email, claims.Sub), Action: "authorization:denied", Target: "game-server:" + nodeID + ":network-capacity", ReasonCode: "missing:gameserver:traffic", CorrelationID: correlationID02111(r), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusForbidden, "game_server_command_permission_required:gameserver:traffic")
		return
	}
	var req networkCapacityUpdate0288
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "network_capacity_request_invalid")
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "network_capacity_request_invalid")
		return
	}
	limit, err := parseNetworkCapacity0288(req.CapacityLimit)
	if err != nil || req.ExpectedRevision == nil || *req.ExpectedRevision < 0 || !strings.EqualFold(req.RuntimeID, node.RuntimeID) || req.RuntimeEpoch != node.RuntimeEpoch || node.RuntimeEpoch < 1 {
		writeError(w, http.StatusConflict, "network_capacity_stale_or_invalid")
		return
	}
	backend := s.State.ServerBridge.backendV2()
	if backend == nil {
		writeError(w, http.StatusServiceUnavailable, "network_capacity_postgresql_required")
		return
	}
	ctx, cancel := bridgeContextV2()
	defer cancel()
	actor := firstNonEmpty(claims.Email, claims.Sub)
	revision, err := backend.SetServerBridgeNetworkCapacity(ctx, nodeID, node.ProjectID, strings.ToLower(node.RuntimeID), req.RuntimeEpoch, *req.ExpectedRevision, limit, actor, time.Now().UTC())
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
			return
		}
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "network_capacity_revision_conflict")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "network_capacity_storage_unavailable")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("network-capacity-changed"), Actor: actor, Action: "serverbridge:network:capacity-changed", Target: nodeID, CorrelationID: correlationID02111(r), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"nodeId": nodeID, "operatorCapacityMax": limit, "operatorCapacityRevision": revision, "status": "applied"}})
}
