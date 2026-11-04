package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/authorization"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/serverbridgeha"
)

const (
	serverBridgeControlSignatureScheme0195 = "Launcher-ServerBridge-Control-v1"
	serverBridgeControlLease0195           = 30 * time.Second
	serverBridgeControlPayloadMax0195      = 4096
)

var serverBridgeControlTypes0195 = map[string]struct{}{
	"player.kick": {}, "message.broadcast": {},
	"whitelist.add": {}, "whitelist.remove": {}, "whitelist.enable": {}, "whitelist.disable": {},
	"ban.add": {}, "ban.remove": {}, "server.save": {}, "server.maintenance": {}, "server.drain": {},
	"server.shutdown": {}, "server.console": {},
}
var serverBridgeConsoleAllowlist0195 = map[string]struct{}{
	"say": {}, "list": {}, "whitelist": {}, "ban": {}, "ban-ip": {}, "pardon": {}, "pardon-ip": {},
	"save-all": {}, "save-off": {}, "save-on": {}, "kick": {}, "time": {}, "weather": {}, "difficulty": {},
	"gamerule": {}, "title": {}, "tellraw": {},
}

type serverBridgeControlCreateRequest0195 struct {
	Type             string            `json:"type"`
	Payload          map[string]string `json:"payload"`
	IdempotencyKey   string            `json:"idempotencyKey,omitempty"`
	ExpiresInSeconds int               `json:"expiresInSeconds,omitempty"`
}

type serverBridgeControlAckRequest0195 struct {
	ProtocolVersion  int      `json:"protocolVersion"`
	Features         []string `json:"features"`
	ServerID         string   `json:"serverId"`
	RuntimeID        string   `json:"runtimeId"`
	CommandID        string   `json:"commandId"`
	DeliverySequence int64    `json:"deliverySequence"`
	ChannelID        string   `json:"channelId"`
	LeaseToken       string   `json:"leaseToken"`
	Status           string   `json:"status"`
	Result           string   `json:"result"` // Канонический объект JSON типа object<string,string> в кодировке base64url.
	Error            string   `json:"error,omitempty"`
}

func canonicalControlPayload0195(payload map[string]string) ([]byte, error) {
	if payload == nil {
		payload = map[string]string{}
	}
	return json.Marshal(payload) // encoding/json сортирует строковые ключи карт.
}

func validateServerBridgeControlRequest0195(kind string, payload map[string]string) (map[string]string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if _, ok := serverBridgeControlTypes0195[kind]; !ok {
		return nil, fmt.Errorf("serverbridge_control_type_unsupported")
	}
	if payload == nil {
		payload = map[string]string{}
	}
	if len(payload) > 16 {
		return nil, fmt.Errorf("serverbridge_control_payload_invalid")
	}
	clean := make(map[string]string, len(payload))
	for k, v := range payload {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || len(k) > 64 || len(v) > 1024 || strings.ContainsAny(k, "\r\n\x00") || strings.ContainsRune(v, '\x00') {
			return nil, fmt.Errorf("serverbridge_control_payload_invalid")
		}
		clean[k] = v
	}
	require := func(key string) error {
		if strings.TrimSpace(clean[key]) == "" {
			return fmt.Errorf("serverbridge_control_payload_%s_required", strings.ReplaceAll(key, ".", "_"))
		}
		return nil
	}
	noExtra := func(keys ...string) error {
		allowed := map[string]bool{}
		for _, k := range keys {
			allowed[k] = true
		}
		for k := range clean {
			if !allowed[k] {
				return fmt.Errorf("serverbridge_control_payload_invalid")
			}
		}
		return nil
	}
	switch kind {
	case "player.kick":
		if err := require("username"); err != nil {
			return nil, err
		}
		if err := noExtra("username", "reason", "sessionCorrelationId"); err != nil {
			return nil, err
		}
		if correlation := clean["sessionCorrelationId"]; correlation != "" {
			if len(correlation) != 64 {
				return nil, fmt.Errorf("serverbridge_control_session_correlation_invalid")
			}
			for _, c := range correlation {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return nil, fmt.Errorf("serverbridge_control_session_correlation_invalid")
				}
			}
		}
	case "message.broadcast":
		if err := require("message"); err != nil {
			return nil, err
		}
		if err := noExtra("message"); err != nil {
			return nil, err
		}
	case "whitelist.add", "whitelist.remove", "ban.add", "ban.remove":
		if err := require("username"); err != nil {
			return nil, err
		}
		if err := noExtra("username", "reason"); err != nil {
			return nil, err
		}
	case "whitelist.enable", "whitelist.disable", "server.save":
		if len(clean) != 0 {
			return nil, fmt.Errorf("serverbridge_control_payload_invalid")
		}
	case "server.maintenance", "server.drain":
		v := strings.ToLower(clean["enabled"])
		if v != "true" && v != "false" {
			return nil, fmt.Errorf("serverbridge_control_payload_enabled_required")
		}
		if err := noExtra("enabled", "reason"); err != nil {
			return nil, err
		}
	case "server.shutdown":
		if err := noExtra("reason"); err != nil {
			return nil, err
		}
	case "server.console":
		if err := require("command"); err != nil {
			return nil, err
		}
		if err := noExtra("command"); err != nil {
			return nil, err
		}
		command := strings.TrimSpace(clean["command"])
		if len(command) > 512 || strings.ContainsAny(command, "\r\n\x00") {
			return nil, fmt.Errorf("serverbridge_control_console_invalid")
		}
		fields := strings.Fields(strings.TrimPrefix(command, "/"))
		if len(fields) == 0 {
			return nil, fmt.Errorf("serverbridge_control_console_invalid")
		}
		root := strings.ToLower(fields[0])
		if _, ok := serverBridgeConsoleAllowlist0195[root]; !ok {
			return nil, fmt.Errorf("serverbridge_control_console_not_allowlisted")
		}
	}
	encoded, err := canonicalControlPayload0195(clean)
	if err != nil || len(encoded) > serverBridgeControlPayloadMax0195 {
		return nil, fmt.Errorf("serverbridge_control_payload_invalid")
	}
	return clean, nil
}

func (s Server) serverBridgeControlSigningPrivateKey0195() (ed25519.PrivateKey, error) {
	seedHex := strings.TrimSpace(s.Config.ServerBridgeControlSigningPrivateKey)
	if seedHex == "" {
		return s.manifestSigningPrivateKey()
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("serverbridge control signing key must be a 32-byte Ed25519 seed in hex")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func serverBridgeControlCanonical0195(serverID, commandID, runtimeID, kind, payloadSHA, channelID, leaseToken string, runtimeEpoch, deliverySequence int64, attempt int, issuedAt, expiresAt int64) string {
	enc := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(v))) }
	return strings.Join([]string{serverBridgeControlSignatureScheme0195, enc(serverID), enc(commandID), strconv.FormatInt(runtimeEpoch, 10), strings.ToLower(runtimeID), enc(kind), strings.ToLower(payloadSHA), strconv.FormatInt(deliverySequence, 10), enc(channelID), enc(leaseToken), strconv.Itoa(attempt), strconv.FormatInt(issuedAt, 10), strconv.FormatInt(expiresAt, 10)}, "\n")
}

func (s Server) serverBridgeControlCreate0195(w http.ResponseWriter, r *http.Request) {
	serverID := strings.TrimSpace(r.PathValue("serverId"))
	node, err := s.State.ServerBridge.getNode0142(serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid admin session")
		return
	}
	var req serverBridgeControlCreateRequest0195
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "serverbridge_control_request_invalid")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Type))
	permission, known := authorization.GameCommandPermission(kind)
	if !known {
		writeError(w, http.StatusBadRequest, "serverbridge_control_type_unsupported")
		return
	}
	// First establish project visibility; do not disclose cross-project node IDs.
	if !s.authorizeClaims(r, claims, "project:read", node.ProjectID, "server", serverID).Allowed {
		writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
		return
	}
	if !s.authorizeClaims(r, claims, permission, node.ProjectID, "server", serverID).Allowed {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("control-domain-denied"), Actor: firstNonEmpty(claims.Email, claims.Sub), Action: "authorization:denied", Target: "game-server:" + serverID + ":" + kind, ReasonCode: "missing:" + permission, CorrelationID: correlationID02111(r), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusForbidden, "game_server_command_permission_required:"+permission)
		return
	}
	payload, err := validateServerBridgeControlRequest0195(kind, req.Payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if node.Status != "active" || node.ProtocolVersion != serverBridgeProtocolV3 || node.RuntimeEpoch < 1 || len(strings.TrimSpace(node.RuntimeID)) != 64 {
		writeError(w, http.StatusConflict, "serverbridge_control_runtime_not_active")
		return
	}
	if !serverBridgeNodeAllowsControl0286(node, kind) {
		writeError(w, http.StatusConflict, "serverbridge_control_capability_not_advertised")
		return
	}
	headerIdempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	bodyIdempotency := strings.TrimSpace(req.IdempotencyKey)
	if headerIdempotency != "" && bodyIdempotency != "" && headerIdempotency != bodyIdempotency {
		writeError(w, http.StatusBadRequest, "serverbridge_control_idempotency_key_mismatch")
		return
	}
	idempotency := headerIdempotency
	if idempotency == "" {
		idempotency = bodyIdempotency
	}
	if len(idempotency) < 8 || len(idempotency) > 128 || strings.ContainsAny(idempotency, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "serverbridge_control_idempotency_key_required")
		return
	}
	expires := req.ExpiresInSeconds
	if expires == 0 {
		expires = 120
	}
	if expires < 10 || expires > 600 {
		writeError(w, http.StatusBadRequest, "serverbridge_control_expiry_invalid")
		return
	}
	payloadBytes, _ := canonicalControlPayload0195(payload)
	payloadHash := sha256.Sum256(payloadBytes)
	payloadSHA := hex.EncodeToString(payloadHash[:])
	actor := firstNonEmpty(claims.Email, claims.Sub)
	requestCanonical := strings.Join([]string{serverID, strconv.FormatInt(node.RuntimeEpoch, 10), strings.ToLower(node.RuntimeID), kind, payloadSHA, actor, idempotency}, "\n")
	requestSum := sha256.Sum256([]byte(requestCanonical))
	commandID, err := randomToken("ctl")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "serverbridge_control_id_generation_failed")
		return
	}
	now := time.Now().UTC()
	cmd := model.ServerBridgeControlCommand{ID: commandID, ServerID: serverID, RuntimeEpoch: node.RuntimeEpoch, RuntimeID: strings.ToLower(node.RuntimeID), Type: kind, Payload: payload, PayloadSHA256: payloadSHA, RequestDigest: hex.EncodeToString(requestSum[:]), RequestedBy: actor, IdempotencyKey: idempotency, Status: "pending", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Duration(expires) * time.Second)}
	stored, reused, err := s.State.ServerBridge.createControl0195(cmd, now)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "serverbridge_control_idempotency_conflict")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	if s.State.ServerBridge.backendV2() == nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "serverbridge-control-queued-" + stored.ID, Actor: stored.RequestedBy, Action: "serverbridge:control:queued:" + stored.Type, Target: stored.ServerID + ":" + stored.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	}
	status := http.StatusCreated
	if reused {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"status": stored.Status, "command": stored, "idempotentReplay": reused, "controlDomain": "game-server", "requiredPermission": permission}})
}

func (s Server) serverBridgeControlGet0195(w http.ResponseWriter, r *http.Request) {
	serverID := strings.TrimSpace(r.PathValue("serverId"))
	commandID := strings.TrimSpace(r.PathValue("commandId"))
	if serverID == "" || commandID == "" {
		writeError(w, http.StatusBadRequest, "serverbridge_control_command_invalid")
		return
	}
	cmd, err := s.State.ServerBridge.getControl0195(serverID, commandID)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "serverbridge_control_command_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	node, err := s.State.ServerBridge.getNode0142(serverID)
	if err != nil || strings.TrimSpace(cmd.ServerID) != serverID {
		writeError(w, http.StatusNotFound, "serverbridge_control_command_not_found")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid admin session")
		return
	}
	permission, known := authorization.GameCommandPermission(cmd.Type)
	if !known || !s.authorizeClaims(r, claims, "project:read", node.ProjectID, "server", serverID).Allowed || !s.authorizeClaims(r, claims, permission, node.ProjectID, "server", serverID).Allowed {
		writeError(w, http.StatusNotFound, "serverbridge_control_command_not_found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"command": cmd}})
}

func (s Server) serverBridgeControlPoll0195(w http.ResponseWriter, r *http.Request) {
	node, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	if strings.TrimSpace(r.PathValue("serverId")) != node.ID {
		writeError(w, http.StatusForbidden, "serverbridge_node_server_id_mismatch")
		return
	}
	runtimeID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("runtimeId")))
	channelID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("channelId")))
	resumeAfter, parseErr := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("resumeAfter")), 10, 64)
	if parseErr != nil || resumeAfter < 0 || len(channelID) != 32 {
		writeError(w, http.StatusBadRequest, "serverbridge_control_resume_invalid")
		return
	}
	for _, ch := range channelID {
		if !((ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9')) {
			writeError(w, http.StatusBadRequest, "serverbridge_control_channel_invalid")
			return
		}
	}
	if node.ProtocolVersion != serverBridgeProtocolV3 || node.RuntimeEpoch < 1 || runtimeID == "" || !strings.EqualFold(runtimeID, node.RuntimeID) {
		writeError(w, http.StatusConflict, "serverbridge_control_runtime_not_active")
		return
	}
	if s.State.ServerBridgeHARequired && s.State.ServerBridgeCoordinator == nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_ha_coordinator_unavailable")
		return
	}
	leaseToken, err := randomToken("lease")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_lease_generation_failed")
		return
	}
	now := time.Now().UTC()
	cmd, err := s.State.ServerBridge.leaseControl0195(node.ID, node.RuntimeEpoch, runtimeID, channelID, leaseToken, resumeAfter, now, serverBridgeControlLease0195)
	if errors.Is(err, repository.ErrNotFound) {
		if coord := s.State.ServerBridgeCoordinator; coord != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 1200*time.Millisecond)
			_ = coord.TouchChannel(ctx, serverbridgeha.ChannelPresence{ReplicaID: s.State.ServerBridgeReplicaID, ServerID: node.ID, RuntimeID: runtimeID, ChannelID: channelID, ResumeAfter: resumeAfter, BackendAddress: r.Host}, 3*serverBridgeControlLease0195)
			cancel()
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	if coord := s.State.ServerBridgeCoordinator; coord != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		_ = coord.TouchChannel(ctx, serverbridgeha.ChannelPresence{ReplicaID: s.State.ServerBridgeReplicaID, ServerID: node.ID, RuntimeID: runtimeID, ChannelID: channelID, ResumeAfter: resumeAfter, BackendAddress: r.Host}, 3*serverBridgeControlLease0195)
		acquired, coordErr := coord.AcquireCommandLease(ctx, node.ID, cmd.ID, cmd.LeaseOwner, cmd.LeaseToken, serverBridgeControlLease0195)
		cancel()
		if coordErr != nil {
			writeError(w, http.StatusServiceUnavailable, "serverbridge_ha_coordinator_unavailable")
			return
		}
		if !acquired {
			writeError(w, http.StatusConflict, "serverbridge_control_lease_fenced")
			return
		}
	} else if s.State.ServerBridgeHARequired {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_ha_coordinator_unavailable")
		return
	}
	// A runtime may have been replaced or its capabilities revoked after command creation.
	// Never sign delivery to a node that no longer advertises this operation.
	if !serverBridgeNodeAllowsControl0286(node, cmd.Type) {
		writeError(w, http.StatusConflict, "serverbridge_control_capability_revoked")
		return
	}
	activeKey, previousKey, err := s.serverBridgeSigningKeys01912()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_signing_unavailable")
		return
	}
	payloadBytes, _ := canonicalControlPayload0195(cmd.Payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	issued := now.UnixMilli()
	// Bound the SIGNED execution authorization to the active fenced lease.
	// A delayed HTTP response must not authorize an external side effect after
	// PostgreSQL/Redis has moved ownership away from this delivery.
	expires := controlWireExpiry0285(cmd)
	if expires <= issued {
		writeError(w, http.StatusConflict, "serverbridge_control_delivery_lease_expired")
		return
	}
	capabilityDigest := serverBridgeExpectedSecurityCapabilityDigest01912()

	activeCanonical := serverBridgeControlCanonical01912(cmd.ServerID, cmd.ID, cmd.RuntimeID, cmd.Type, cmd.PayloadSHA256, cmd.LeaseOwner, cmd.LeaseToken, capabilityDigest, activeKey.Fingerprint, node.IdentityEpoch, cmd.RuntimeEpoch, cmd.DeliverySequence, cmd.Attempt, issued, expires)
	activeSignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(activeKey.PrivateKey, []byte(activeCanonical)))
	previousPublicKey, previousFingerprint, previousSignature := "", "", ""
	legacyKey := activeKey
	if previousKey != nil {
		previousPublicKey = previousKey.PublicB64
		previousFingerprint = previousKey.Fingerprint
		previousCanonical := serverBridgeControlCanonical01912(cmd.ServerID, cmd.ID, cmd.RuntimeID, cmd.Type, cmd.PayloadSHA256, cmd.LeaseOwner, cmd.LeaseToken, capabilityDigest, previousKey.Fingerprint, node.IdentityEpoch, cmd.RuntimeEpoch, cmd.DeliverySequence, cmd.Attempt, issued, expires)
		previousSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(previousKey.PrivateKey, []byte(previousCanonical)))
		// Во время перекрытия мосты до 0.19.12 доверяют прежнему ключу. Сохраняйте
		// старую подпись этим ключом, пока клиенты v3 аутентифицируют активный набор.
		legacyKey = *previousKey
	}
	legacyCanonical := serverBridgeControlCanonical0195(cmd.ServerID, cmd.ID, cmd.RuntimeID, cmd.Type, cmd.PayloadSHA256, cmd.LeaseOwner, cmd.LeaseToken, cmd.RuntimeEpoch, cmd.DeliverySequence, cmd.Attempt, issued, expires)
	legacySignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(legacyKey.PrivateKey, []byte(legacyCanonical)))

	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"status": "command", "protocolVersion": serverBridgeProtocolV3, "feature": serverBridgeFeatureHAControlPlane, "controlFeature": serverBridgeFeatureControlAPI,
		"serverId": cmd.ServerID, "runtimeId": cmd.RuntimeID, "runtimeEpoch": cmd.RuntimeEpoch, "identityEpoch": node.IdentityEpoch, "commandId": cmd.ID,
		"deliverySequence": cmd.DeliverySequence, "channelId": cmd.LeaseOwner, "leaseToken": cmd.LeaseToken,
		"type": cmd.Type, "payload": payloadB64, "payloadSha256": cmd.PayloadSHA256, "attempt": cmd.Attempt,
		"issuedAtUnixMillis": issued, "expiresAtUnixMillis": expires,
		"securityProfile": serverBridgeSecurityProfile01912, "securityCapabilityDigest": capabilityDigest,
		"v3SigningPublicKey": activeKey.PublicB64, "v3SigningKeyFingerprint": activeKey.Fingerprint, "v3Signature": activeSignature,
		"previousV3SigningPublicKey": previousPublicKey, "previousV3SigningKeyFingerprint": previousFingerprint, "previousV3Signature": previousSignature,
		"signingPublicKey": legacyKey.PublicB64, "signingKeyFingerprint": legacyKey.Fingerprint, "signature": legacySignature,
	}})
}

// classifyBridgeControlOutcome0411 enforces the difference between a platform
// acknowledgement, an invoked operation, and an observed postcondition.
// Old agents' "succeeded" receipts are never grandfathered into verified success.
// A verification claim is an attestation by the enrolled game agent, NOT an
// independent observation by the Backend. Only explicitly observable operations
// and a result matching the original command can claim the stronger status.
func classifyBridgeControlOutcome0411(command model.ServerBridgeControlCommand, status string, result map[string]string) string {
	if status != "succeeded" && status != "executed" && status != "accepted" {
		return status
	}
	if command.Type == "server.shutdown" {
		return "accepted"
	}
	if status != "succeeded" {
		return status
	}
	// PlayerQuitEvent is observed by the agent's registered Bukkit/Folia event
	// listener. It proves departure, not merely a kickPlayer() invocation.
	if command.Type == "player.kick" && result["verification"] == "player-quit-event" {
		if command.Payload["username"] != "" && result["username"] == command.Payload["username"] &&
			result["online"] == "false" && result["uuid"] != "" {
			return "succeeded"
		}
		return "executed"
	}
	if result["verification"] != "platform-state-read" {
		return "executed"
	}
	switch command.Type {
	case "server.maintenance", "server.drain":
		mode := strings.TrimPrefix(command.Type, "server.")
		expected := strings.ToLower(command.Payload["enabled"])
		if (expected == "true" || expected == "false") && result["enabled"] == expected && result["mode"] == mode {
			return "succeeded"
		}
	case "whitelist.enable", "whitelist.disable":
		expected := strconv.FormatBool(command.Type == "whitelist.enable")
		if result["enabled"] == expected {
			return "succeeded"
		}
	case "whitelist.add", "whitelist.remove":
		expected := strconv.FormatBool(command.Type == "whitelist.add")
		if command.Payload["username"] != "" && result["username"] == command.Payload["username"] && result["whitelisted"] == expected {
			return "succeeded"
		}
	case "ban.add", "ban.remove":
		expected := strconv.FormatBool(command.Type == "ban.add")
		if command.Payload["username"] != "" && result["username"] == command.Payload["username"] && result["banned"] == expected {
			return "succeeded"
		}
	}
	return "executed"
}

func (s Server) serverBridgeControlAck0195(w http.ResponseWriter, r *http.Request) {
	node, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	var req serverBridgeControlAckRequest0195
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "serverbridge_control_ack_invalid")
		return
	}
	features := normalizeBridgeFeatures0191(req.Features)
	if _, reason := validateServerBridgeSecurityEnvelope01912(r, req.ProtocolVersion, features); reason != "" {
		writeError(w, http.StatusUpgradeRequired, reason)
		return
	}
	hasControlFeature, hasHAFeature := false, false
	for _, feature := range features {
		if feature == serverBridgeFeatureControlAPI {
			hasControlFeature = true
		}
		if feature == serverBridgeFeatureHAControlPlane {
			hasHAFeature = true
		}
	}
	if req.ProtocolVersion != serverBridgeProtocolV3 || !hasControlFeature || !hasHAFeature || strings.TrimSpace(req.ServerID) != node.ID || !strings.EqualFold(strings.TrimSpace(req.RuntimeID), node.RuntimeID) || node.RuntimeEpoch < 1 {
		writeError(w, http.StatusConflict, "serverbridge_control_ack_runtime_mismatch")
		return
	}
	channelID := strings.ToLower(strings.TrimSpace(req.ChannelID))
	leaseToken := strings.TrimSpace(req.LeaseToken)
	commandID := strings.TrimSpace(req.CommandID)
	if len(channelID) != 32 || len(leaseToken) < 16 || req.DeliverySequence < 1 || commandID == "" {
		writeError(w, http.StatusBadRequest, "serverbridge_control_ack_lease_invalid")
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != "accepted" && status != "executed" && status != "succeeded" && status != "failed" && status != "unsupported" && status != "indeterminate" {
		writeError(w, http.StatusBadRequest, "serverbridge_control_ack_status_invalid")
		return
	}
	result := map[string]string{}
	if strings.TrimSpace(req.Result) != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.Result))
		if err != nil || len(raw) > serverBridgeControlPayloadMax0195 || json.Unmarshal(raw, &result) != nil {
			writeError(w, http.StatusBadRequest, "serverbridge_control_ack_result_invalid")
			return
		}
	}
	if len(result) > 16 || len(req.Error) > 1024 {
		writeError(w, http.StatusBadRequest, "serverbridge_control_ack_result_invalid")
		return
	}
	current, err := s.State.ServerBridge.getControl0195(node.ID, commandID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "serverbridge_control_command_not_found")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	leaseMatches := current.DeliverySequence == req.DeliverySequence && current.LeaseOwner == channelID && current.LeaseToken == leaseToken
	if !leaseMatches {
		writeError(w, http.StatusConflict, "serverbridge_control_ack_lease_mismatch")
		return
	}
	// Normalize against the persisted signed command, never the claimed payload.
	// Both the first ACK and an idempotent retry get the same classification.
	status = classifyBridgeControlOutcome0411(current, status, result)
	terminal := current.Status == "accepted" || current.Status == "executed" || current.Status == "succeeded" || current.Status == "failed" || current.Status == "unsupported" || current.Status == "indeterminate"
	if !terminal {
		if s.State.ServerBridgeHARequired && s.State.ServerBridgeCoordinator == nil {
			writeError(w, http.StatusServiceUnavailable, "serverbridge_ha_coordinator_unavailable")
			return
		}
		if coord := s.State.ServerBridgeCoordinator; coord != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
			valid, coordErr := coord.VerifyCommandLease(ctx, node.ID, commandID, channelID, leaseToken)
			cancel()
			if coordErr != nil {
				writeError(w, http.StatusServiceUnavailable, "serverbridge_ha_coordinator_unavailable")
				return
			}
			if !valid {
				writeError(w, http.StatusConflict, "serverbridge_control_lease_fenced")
				return
			}
		}
	}
	completed, err := s.State.ServerBridge.completeControl0195(node.ID, node.RuntimeEpoch, node.RuntimeID, commandID, channelID, leaseToken, req.DeliverySequence, status, result, strings.TrimSpace(req.Error), time.Now().UTC())
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "serverbridge_control_ack_conflict")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	if coord := s.State.ServerBridgeCoordinator; coord != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		_ = coord.ReleaseCommandLease(ctx, node.ID, commandID, channelID, leaseToken)
		_ = coord.TouchChannel(ctx, serverbridgeha.ChannelPresence{ReplicaID: s.State.ServerBridgeReplicaID, ServerID: node.ID, RuntimeID: node.RuntimeID, ChannelID: channelID, ResumeAfter: req.DeliverySequence, BackendAddress: r.Host}, 3*serverBridgeControlLease0195)
		cancel()
	}
	if s.State.ServerBridge.backendV2() == nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "serverbridge-control-complete-" + completed.ID, Actor: node.ID, Action: "serverbridge:control:" + completed.Status, Target: completed.Type + ":" + completed.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"status": "acknowledged", "commandId": completed.ID, "commandStatus": completed.Status, "deliverySequence": completed.DeliverySequence}})
}

// A signed ServerBridge command cannot remain executable after its specific
// PostgreSQL delivery lease ends, even if the logical command expiry is later.
func controlWireExpiry0285(cmd model.ServerBridgeControlCommand) int64 {
	expires := cmd.ExpiresAt.UnixMilli()
	if cmd.LeaseUntil.IsZero() {
		return 0 // fail closed if a repository returned no lease timestamp
	}
	if leaseExpiry := cmd.LeaseUntil.UnixMilli(); leaseExpiry < expires {
		return leaseExpiry
	}
	return expires
}

func serverBridgeControlStringMapEqual0195(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func (b *serverBridgeStore) createControl0195(c model.ServerBridgeControlCommand, now time.Time) (model.ServerBridgeControlCommand, bool, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.CreateServerBridgeControlCommand(ctx, c, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.controlCommands == nil {
		b.controlCommands = map[string]model.ServerBridgeControlCommand{}
	}
	if b.controlIdempotency == nil {
		b.controlIdempotency = map[string]string{}
	}
	key := c.ServerID + "\x00" + c.RequestedBy + "\x00" + c.IdempotencyKey
	if id := b.controlIdempotency[key]; id != "" {
		existing := b.controlCommands[id]
		if !strings.EqualFold(existing.RequestDigest, c.RequestDigest) {
			return model.ServerBridgeControlCommand{}, false, repository.ErrConflict
		}
		return existing, true, nil
	}
	b.controlSequence++
	c.DeliverySequence = b.controlSequence
	b.controlCommands[c.ID] = c
	b.controlIdempotency[key] = c.ID
	return c, false, nil
}

// A lost ACK does not prove the game command was not applied. In particular,
// never re-lease work that has already been delivered to any runtime/channel.
func reconcileControlInMemory0285(c model.ServerBridgeControlCommand, now time.Time) model.ServerBridgeControlCommand {
	if c.Status == "leased" && (!c.LeaseUntil.After(now) || !c.ExpiresAt.After(now)) {
		c.Status = "indeterminate"
		c.Error = "delivered command lost lease without proof of completion"
	} else if c.Status == "pending" && !c.ExpiresAt.After(now) {
		c.Status = "expired"
		c.Error = "expired before delivery"
	} else {
		return c
	}
	c.CompletedAt, c.UpdatedAt, c.LeaseUntil = now, now, time.Time{}
	return c
}

func (b *serverBridgeStore) getControl0195(serverID, commandID string) (model.ServerBridgeControlCommand, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.GetServerBridgeControlCommand(ctx, serverID, commandID)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.controlCommands[commandID]
	if !ok || c.ServerID != serverID {
		return model.ServerBridgeControlCommand{}, repository.ErrNotFound
	}
	c = reconcileControlInMemory0285(c, time.Now().UTC())
	b.controlCommands[commandID] = c
	return c, nil
}

func (b *serverBridgeStore) leaseControl0195(serverID string, epoch int64, runtimeID, leaseOwner, leaseToken string, resumeAfter int64, now time.Time, lease time.Duration) (model.ServerBridgeControlCommand, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.LeaseServerBridgeControlCommand(ctx, serverID, epoch, runtimeID, leaseOwner, leaseToken, resumeAfter, now, lease)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var chosen model.ServerBridgeControlCommand
	for id, c := range b.controlCommands {
		if c.ServerID != serverID {
			continue
		}
		if c.Status == "leased" && (c.RuntimeEpoch != epoch || !strings.EqualFold(c.RuntimeID, runtimeID)) {
			c.Status, c.Error = "indeterminate", "delivery belongs to a superseded runtime identity"
			c.CompletedAt, c.UpdatedAt, c.LeaseUntil = now, now, time.Time{}
			b.controlCommands[id] = c
		}
		if c.RuntimeEpoch != epoch || !strings.EqualFold(c.RuntimeID, runtimeID) || c.DeliverySequence <= resumeAfter {
			continue
		}
		updated := reconcileControlInMemory0285(c, now)
		if updated.Status != c.Status {
			b.controlCommands[id] = updated
			continue
		}
		if c.Status == "leased" && c.LeaseOwner == leaseOwner && c.LeaseUntil.After(now) {
			if chosen.ID == "" || c.DeliverySequence < chosen.DeliverySequence {
				chosen = c
			}
			continue
		}
		eligible := c.Status == "pending"
		if !eligible {
			continue
		}
		if chosen.ID == "" || c.DeliverySequence < chosen.DeliverySequence {
			chosen = c
		}
	}
	if chosen.ID == "" {
		return model.ServerBridgeControlCommand{}, repository.ErrNotFound
	}
	if chosen.Status == "leased" && chosen.LeaseOwner == leaseOwner && chosen.LeaseUntil.After(now) {
		return chosen, nil
	}
	chosen.Status = "leased"
	chosen.Attempt++
	chosen.LeaseOwner = leaseOwner
	chosen.LeaseToken = leaseToken
	chosen.LeaseUntil = now.Add(lease)
	chosen.UpdatedAt = now
	b.controlCommands[chosen.ID] = chosen
	return chosen, nil
}

func (b *serverBridgeStore) completeControl0195(serverID string, epoch int64, runtimeID, commandID, leaseOwner, leaseToken string, deliverySequence int64, status string, result map[string]string, failure string, now time.Time) (model.ServerBridgeControlCommand, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.CompleteServerBridgeControlCommand(ctx, serverID, epoch, runtimeID, commandID, leaseOwner, leaseToken, deliverySequence, status, result, failure, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.controlCommands[commandID]
	if !ok {
		return model.ServerBridgeControlCommand{}, repository.ErrNotFound
	}
	if c.ServerID != serverID || c.RuntimeEpoch != epoch || !strings.EqualFold(c.RuntimeID, runtimeID) || c.DeliverySequence != deliverySequence || c.LeaseOwner != leaseOwner || c.LeaseToken != leaseToken {
		return model.ServerBridgeControlCommand{}, repository.ErrConflict
	}
	if recoverableControlLease0412(c) {
		c.Status, c.Result, c.Error = status, result, failure
		c.CompletedAt, c.UpdatedAt, c.LeaseUntil = now, now, time.Time{}
		b.controlCommands[commandID] = c
		return c, nil
	}
	if c.Status == "accepted" || c.Status == "executed" || c.Status == "succeeded" || c.Status == "failed" || c.Status == "unsupported" || c.Status == "indeterminate" {
		if c.Status != status || !serverBridgeControlStringMapEqual0195(c.Result, result) || c.Error != failure {
			return model.ServerBridgeControlCommand{}, repository.ErrConflict
		}
		return c, nil
	}
	if c.Status != "leased" {
		return model.ServerBridgeControlCommand{}, repository.ErrConflict
	}
	c.Status = status
	c.Result = result
	c.Error = failure
	c.CompletedAt = now
	c.UpdatedAt = now
	c.LeaseUntil = time.Time{}
	b.controlCommands[commandID] = c
	return c, nil
}

// In-memory mode follows the same late-receipt policy as PostgreSQL.
// Only a synthetic lease-loss transition is reversible; an actual agent
// indeterminate result is immutable.
func recoverableControlLease0412(c model.ServerBridgeControlCommand) bool {
	if c.Status != "indeterminate" || len(c.Result) != 0 || c.LeaseOwner == "" || c.LeaseToken == "" {
		return false
	}
	switch c.Error {
	case "delivered command lost lease without proof of completion",
		"delivery belongs to a superseded runtime identity":
		return true
	}
	return false
}
