package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const serverBridgeHandoffTTL0148 = 30 * time.Second

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

func validPlayerSessionCorrelation0197(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func bridgeFeatureContains0196(features []string, wanted string) bool {
	for _, feature := range normalizeBridgeFeatures0191(features) {
		if feature == wanted {
			return true
		}
	}
	return false
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
	req, err := decodeBridgeHandoff0191(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "некорректный ServerBridge protocol payload")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.TargetServer = strings.TrimSpace(req.TargetServer)
	req.SessionCorrelationID = strings.ToLower(strings.TrimSpace(req.SessionCorrelationID))
	if ok, reason := validateBridgeProtocolFeatures0191(req.ProtocolVersion, req.Features); !ok {
		writeError(w, http.StatusUpgradeRequired, reason)
		return
	}
	if req.Username == "" || req.TargetServer == "" {
		writeError(w, http.StatusBadRequest, "username и targetServer обязательны")
		return
	}
	playerSessionV3 := req.ProtocolVersion >= serverBridgeProtocolV3 && bridgeFeatureContains0196(req.Features, serverBridgeFeaturePlayerSessionV3)
	if playerSessionV3 && !validPlayerSessionCorrelation0197(req.SessionCorrelationID) {
		writeError(w, http.StatusBadRequest, "serverbridge_session_correlation_required")
		return
	}
	id, err := newServerBridgeHandoffID0148()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "handoff_entropy_unavailable")
		return
	}
	handoff, err := s.State.ServerBridge.createHandoff0148(model.ServerBridgeHandoff{
		ID:                   id,
		Username:             req.Username,
		SourceNodeID:         source.ID,
		TargetNodeID:         req.TargetServer,
		SessionCorrelationID: req.SessionCorrelationID,
		RequireRoutingProof:  req.ProtocolVersion >= serverBridgeProtocolV3 && bridgeFeatureContains0196(req.Features, serverBridgeFeatureRoutingV2),
		ExpiresAt:            time.Now().UTC().Add(serverBridgeHandoffTTL0148),
	})
	if err != nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("handoff-denied"), Actor: source.ID, Action: "serverbridge:handoff:denied", Target: req.Username + ":" + req.TargetServer, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusConflict, "handoff_denied: "+err.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("handoff-created"), Actor: source.ID, Action: "serverbridge:handoff:created", Target: handoff.TargetNodeID + ":" + handoff.Username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion":         bridgePluginsSchema940,
		"toolVersion":           s.Version,
		"protocolVersion":       req.ProtocolVersion,
		"features":              bridgeNegotiatedFeatures0191(req.ProtocolVersion, req.Features, req.ProtocolVersion == serverBridgeProtocolV2),
		"status":                "handoff-created",
		"oneTime":               true,
		"handoffId":             handoff.ID,
		"sourceNodeId":          handoff.SourceNodeID,
		"targetNodeId":          handoff.TargetNodeID,
		"backendName":           handoff.BackendName,
		"username":              handoff.Username,
		"sessionCorrelationId":  handoff.SessionCorrelationID,
		"transferSequence":      handoff.TransferSequence,
		"expiresAt":             handoff.ExpiresAt,
		"sourceIdentityEpoch":   handoff.SourceIdentityEpoch,
		"targetIdentityEpoch":   handoff.TargetIdentityEpoch,
		"sourceRuntimeId":       handoff.SourceRuntimeID,
		"sourceRuntimeEpoch":    handoff.SourceRuntimeEpoch,
		"sourceRoutingRevision": handoff.SourceRoutingRevision,
		"sourceRoutingDigest":   handoff.SourceRoutingDigest,
		"sourceRoutingProof":    handoff.SourceRoutingSignature,
		"targetRuntimeId":       handoff.TargetRuntimeID,
		"targetRuntimeEpoch":    handoff.TargetRuntimeEpoch,
		"targetRoutingRevision": handoff.TargetRoutingRevision,
		"targetRoutingDigest":   handoff.TargetRoutingDigest,
		"targetRoutingProof":    handoff.TargetRoutingSignature,
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
		SessionCorrelationID: h.SessionCorrelationID,
		ProtocolVersion:      h.ProtocolVersion,
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
