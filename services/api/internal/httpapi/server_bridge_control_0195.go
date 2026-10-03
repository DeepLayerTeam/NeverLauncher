package httpapi

import (
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

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	serverBridgeControlSignatureScheme0195 = "NeverLauncher-ServerBridge-Control-v1"
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
	ProtocolVersion int      `json:"protocolVersion"`
	Features        []string `json:"features"`
	ServerID        string   `json:"serverId"`
	RuntimeID       string   `json:"runtimeId"`
	CommandID       string   `json:"commandId"`
	Status          string   `json:"status"`
	Result          string   `json:"result"` // base64url canonical JSON object<string,string>
	Error           string   `json:"error,omitempty"`
}

func canonicalControlPayload0195(payload map[string]string) ([]byte, error) {
	if payload == nil {
		payload = map[string]string{}
	}
	return json.Marshal(payload) // encoding/json sorts string map keys
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
		if err := noExtra("username", "reason"); err != nil {
			return nil, err
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

func serverBridgeControlCanonical0195(serverID, commandID, runtimeID, kind, payloadSHA string, runtimeEpoch int64, attempt int, issuedAt, expiresAt int64) string {
	enc := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(v))) }
	return strings.Join([]string{serverBridgeControlSignatureScheme0195, enc(serverID), enc(commandID), strconv.FormatInt(runtimeEpoch, 10), strings.ToLower(runtimeID), enc(kind), strings.ToLower(payloadSHA), strconv.Itoa(attempt), strconv.FormatInt(issuedAt, 10), strconv.FormatInt(expiresAt, 10)}, "\n")
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
	if kind == "server.console" && !claims.HasPermission("serverbridge:console") {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("control-console-denied"), Actor: claims.Email, Action: "serverbridge:control:denied", Target: serverID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusForbidden, "serverbridge_console_permission_required")
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
	writeJSON(w, status, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"status": stored.Status, "command": stored, "idempotentReplay": reused}})
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
	if node.ProtocolVersion != serverBridgeProtocolV3 || node.RuntimeEpoch < 1 || runtimeID == "" || !strings.EqualFold(runtimeID, node.RuntimeID) {
		writeError(w, http.StatusConflict, "serverbridge_control_runtime_not_active")
		return
	}
	now := time.Now().UTC()
	cmd, err := s.State.ServerBridge.leaseControl0195(node.ID, node.RuntimeEpoch, runtimeID, now, serverBridgeControlLease0195)
	if errors.Is(err, repository.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	privateKey, err := s.serverBridgeControlSigningPrivateKey0195()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_signing_unavailable")
		return
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	finger := sha256.Sum256(publicKey)
	payloadBytes, _ := canonicalControlPayload0195(cmd.Payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	issued := now.UnixMilli()
	expires := cmd.ExpiresAt.UnixMilli()
	canonical := serverBridgeControlCanonical0195(cmd.ServerID, cmd.ID, cmd.RuntimeID, cmd.Type, cmd.PayloadSHA256, cmd.RuntimeEpoch, cmd.Attempt, issued, expires)
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(canonical)))
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"status": "command", "protocolVersion": serverBridgeProtocolV3, "feature": serverBridgeFeatureControlAPI, "serverId": cmd.ServerID, "runtimeId": cmd.RuntimeID, "runtimeEpoch": cmd.RuntimeEpoch, "commandId": cmd.ID, "type": cmd.Type, "payload": payloadB64, "payloadSha256": cmd.PayloadSHA256, "attempt": cmd.Attempt, "issuedAtUnixMillis": issued, "expiresAtUnixMillis": expires, "signingPublicKey": base64.RawURLEncoding.EncodeToString(publicKey), "signingKeyFingerprint": hex.EncodeToString(finger[:]), "signature": signature}})
}

func (s Server) serverBridgeControlAck0195(w http.ResponseWriter, r *http.Request) {
	node, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	var req serverBridgeControlAckRequest0195
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "serverbridge_control_ack_invalid")
		return
	}
	features := normalizeBridgeFeatures0191(req.Features)
	hasControlFeature := false
	for _, feature := range features {
		if feature == serverBridgeFeatureControlAPI {
			hasControlFeature = true
			break
		}
	}
	if req.ProtocolVersion != serverBridgeProtocolV3 || !hasControlFeature || strings.TrimSpace(req.ServerID) != node.ID || !strings.EqualFold(strings.TrimSpace(req.RuntimeID), node.RuntimeID) || node.RuntimeEpoch < 1 {
		writeError(w, http.StatusConflict, "serverbridge_control_ack_runtime_mismatch")
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != "succeeded" && status != "failed" && status != "unsupported" && status != "indeterminate" {
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
	completed, err := s.State.ServerBridge.completeControl0195(node.ID, node.RuntimeEpoch, node.RuntimeID, strings.TrimSpace(req.CommandID), status, result, strings.TrimSpace(req.Error), time.Now().UTC())
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "serverbridge_control_ack_conflict")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "serverbridge_control_storage_unavailable")
		return
	}
	if s.State.ServerBridge.backendV2() == nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "serverbridge-control-complete-" + completed.ID, Actor: node.ID, Action: "serverbridge:control:" + completed.Status, Target: completed.Type + ":" + completed.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{"status": "acknowledged", "commandId": completed.ID, "commandStatus": completed.Status}})
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
	b.controlCommands[c.ID] = c
	b.controlIdempotency[key] = c.ID
	return c, false, nil
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
	return c, nil
}

func (b *serverBridgeStore) leaseControl0195(serverID string, epoch int64, runtimeID string, now time.Time, lease time.Duration) (model.ServerBridgeControlCommand, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.LeaseServerBridgeControlCommand(ctx, serverID, epoch, runtimeID, now, lease)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var chosen model.ServerBridgeControlCommand
	for id, c := range b.controlCommands {
		if c.ServerID != serverID || c.RuntimeEpoch != epoch || !strings.EqualFold(c.RuntimeID, runtimeID) {
			continue
		}
		if !c.ExpiresAt.After(now) {
			if c.Status == "pending" || c.Status == "leased" {
				c.Status = "expired"
				c.CompletedAt = now
				b.controlCommands[id] = c
			}
			continue
		}
		eligible := c.Status == "pending" || (c.Status == "leased" && !c.LeaseUntil.After(now))
		if !eligible {
			continue
		}
		if chosen.ID == "" || c.CreatedAt.Before(chosen.CreatedAt) {
			chosen = c
		}
	}
	if chosen.ID == "" {
		return model.ServerBridgeControlCommand{}, repository.ErrNotFound
	}
	chosen.Status = "leased"
	chosen.Attempt++
	chosen.LeaseUntil = now.Add(lease)
	chosen.UpdatedAt = now
	b.controlCommands[chosen.ID] = chosen
	return chosen, nil
}
func (b *serverBridgeStore) completeControl0195(serverID string, epoch int64, runtimeID, commandID, status string, result map[string]string, failure string, now time.Time) (model.ServerBridgeControlCommand, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.CompleteServerBridgeControlCommand(ctx, serverID, epoch, runtimeID, commandID, status, result, failure, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.controlCommands[commandID]
	if !ok {
		return model.ServerBridgeControlCommand{}, repository.ErrNotFound
	}
	if c.ServerID != serverID || c.RuntimeEpoch != epoch || !strings.EqualFold(c.RuntimeID, runtimeID) {
		return model.ServerBridgeControlCommand{}, repository.ErrConflict
	}
	if c.Status == "succeeded" || c.Status == "failed" || c.Status == "unsupported" || c.Status == "indeterminate" {
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
