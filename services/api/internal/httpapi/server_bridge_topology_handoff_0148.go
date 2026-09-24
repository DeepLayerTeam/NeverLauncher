package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const serverBridgeHandoffTTL0148 = 30 * time.Second

type bridgeHandoffRequest0148 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Username        string `json:"username"`
	TargetServer    string `json:"targetServer"`
}

func newServerBridgeHandoffID0148() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secure handoff entropy unavailable: %w", err)
	}
	return "ho_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func bridgeProxyKind0148(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "velocity", "bungeecord", "waterfall":
		return true
	default:
		return false
	}
}

func (s Server) serverBridgeCreateHandoff0148(w http.ResponseWriter, r *http.Request) {
	source, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	if !bridgeProxyKind0148(source.Kind) {
		writeError(w, http.StatusForbidden, "serverbridge_handoff_source_must_be_proxy")
		return
	}
	bridgeIntegrity := s.evaluateRegisteredBridgeIntegrity0135(source)
	if !bridgeIntegrity.Allowed {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("handoff-source-integrity-denied"), Actor: source.ID, Action: "serverbridge:handoff:source-integrity-denied", Target: bridgeIntegrity.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"status": "handoff-denied", "reason": bridgeIntegrity.Reason, "bridgeIntegrity": bridgeIntegrity}})
		return
	}
	var req bridgeHandoffRequest0148
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.TargetServer = strings.TrimSpace(req.TargetServer)
	if req.ProtocolVersion != serverBridgeProtocolV2 {
		writeError(w, http.StatusUpgradeRequired, "serverbridge_protocol_unsupported")
		return
	}
	if req.Username == "" || req.TargetServer == "" {
		writeError(w, http.StatusBadRequest, "username и targetServer обязательны")
		return
	}
	id, err := newServerBridgeHandoffID0148()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "handoff_entropy_unavailable")
		return
	}
	handoff, err := s.State.ServerBridge.createHandoff0148(model.ServerBridgeHandoff{
		ID:           id,
		Username:     req.Username,
		SourceNodeID: source.ID,
		TargetNodeID: req.TargetServer,
		ExpiresAt:    time.Now().UTC().Add(serverBridgeHandoffTTL0148),
	})
	if err != nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("handoff-denied"), Actor: source.ID, Action: "serverbridge:handoff:denied", Target: req.Username + ":" + req.TargetServer, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusConflict, "handoff_denied: "+err.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("handoff-created"), Actor: source.ID, Action: "serverbridge:handoff:created", Target: handoff.TargetNodeID + ":" + handoff.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion":       bridgePluginsSchema940,
		"toolVersion":         s.Version,
		"protocolVersion":     serverBridgeProtocolV2,
		"status":              "handoff-created",
		"oneTime":             true,
		"handoffId":           handoff.ID,
		"sourceNodeId":        handoff.SourceNodeID,
		"targetNodeId":        handoff.TargetNodeID,
		"backendName":         handoff.BackendName,
		"username":            handoff.Username,
		"expiresAt":           handoff.ExpiresAt,
		"sourceIdentityEpoch": handoff.SourceIdentityEpoch,
		"targetIdentityEpoch": handoff.TargetIdentityEpoch,
	}})
}

func (s Server) serverBridgeTopology0148(w http.ResponseWriter, r *http.Request) {
	items, err := s.State.ServerBridge.topology0148()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "ServerBridge PostgreSQL topology недоступна")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion": bridgePluginsSchema940,
		"toolVersion":   s.Version,
		"sourceOfTruth": "postgresql",
		"mode":          "runtime-learned-zero-patch",
		"items":         items,
	}})
}

func (b *serverBridgeStore) createHandoff0148(h model.ServerBridgeHandoff) (model.ServerBridgeHandoff, error) {
	backend := b.backendV2()
	if backend == nil {
		return model.ServerBridgeHandoff{}, fmt.Errorf("PostgreSQL ServerBridge source of truth is required for handoff")
	}
	ctx, cancel := bridgeContextV2()
	defer cancel()
	return backend.CreateServerBridgeHandoff(ctx, h, time.Now().UTC())
}

func (b *serverBridgeStore) activeHandoff0148(username, targetNodeID string) (model.ServerBridgeHandoff, bool) {
	backend := b.backendV2()
	if backend == nil {
		return model.ServerBridgeHandoff{}, false
	}
	ctx, cancel := bridgeContextV2()
	defer cancel()
	h, err := backend.GetActiveServerBridgeHandoff(ctx, username, targetNodeID, time.Now().UTC())
	return h, err == nil
}

func (b *serverBridgeStore) consumeHandoff0148(id string, redemption model.ServerBridgeJoinRedemption) (model.ServerBridgeHandoff, bool) {
	backend := b.backendV2()
	if backend == nil {
		return model.ServerBridgeHandoff{}, false
	}
	ctx, cancel := bridgeContextV2()
	defer cancel()
	h, err := backend.ConsumeServerBridgeHandoff(ctx, id, redemption, time.Now().UTC())
	return h, err == nil
}

func (b *serverBridgeStore) invalidateHandoff0148(id string) bool {
	backend := b.backendV2()
	if backend == nil {
		return false
	}
	ctx, cancel := bridgeContextV2()
	defer cancel()
	ok, err := backend.InvalidateServerBridgeHandoff(ctx, id, time.Now().UTC())
	return err == nil && ok
}

func (b *serverBridgeStore) topology0148() ([]model.ServerBridgeTopologyEdge, error) {
	backend := b.backendV2()
	if backend == nil {
		return nil, fmt.Errorf("PostgreSQL ServerBridge source of truth is required for topology")
	}
	ctx, cancel := bridgeContextV2()
	defer cancel()
	return backend.ListServerBridgeTopology(ctx)
}

func bridgeJoinFromHandoff0148(h model.ServerBridgeHandoff) bridgeJoinRecord {
	return bridgeJoinRecord{
		ID:                   h.ID,
		TicketVersion:        serverBridgeJoinTicketVersion0143,
		Username:             h.Username,
		UUID:                 h.UUID,
		UserID:               h.UserID,
		SessionID:            h.SessionID,
		ServerID:             h.TargetNodeID,
		ProjectID:            h.ProjectID,
		ProfileID:            h.ProfileID,
		Channel:              h.Channel,
		TrustedDeviceID:      h.TrustedDeviceID,
		BindingEpoch:         h.BindingEpoch,
		MinecraftSessionID:   h.MinecraftSessionID,
		ProtocolVersion:      serverBridgeProtocolV2,
		IssuedIdentityEpoch:  h.TargetIdentityEpoch,
		IssuedKeyFingerprint: h.TargetKeyFingerprint,
		Status:               h.Status,
		CreatedAt:            h.CreatedAt,
		ExpiresAt:            h.ExpiresAt,
		ConsumedAt:           h.ConsumedAt,
		RedeemedNonceHash:    h.RedeemedNonceHash,
		RedeemedByIP:         h.RedeemedByIP,
	}
}
