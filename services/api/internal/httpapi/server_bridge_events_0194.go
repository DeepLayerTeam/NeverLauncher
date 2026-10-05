package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	serverBridgeEventSignatureScheme0194 = "NeverLauncher-ServerBridge-Event-v1"
	serverBridgeEventBatchMax0194        = 64
	serverBridgeEventPayloadMax0194      = 4096
	serverBridgeNodeEventMaxBody0194     = 512 << 10
)

var serverBridgeEventID0194 = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var serverBridgeEventTypes0194 = map[string]struct{}{
	"server.startup": {}, "server.ready": {}, "server.shutdown": {}, "server.crash": {}, "server.error": {},
	"player.login": {}, "player.join": {}, "player.quit": {}, "player.kick": {},
	"world.load": {}, "world.unload": {},
	"proxy.connect": {}, "proxy.switch": {},
}

type bridgeEventContract0194 struct {
	Sequence             int64             `json:"sequence"`
	EventID              string            `json:"eventId"`
	RuntimeID            string            `json:"runtimeId"`
	Type                 string            `json:"type"`
	OccurredAtUnixMillis int64             `json:"occurredAtUnixMillis"`
	Payload              map[string]string `json:"payload"`
	PayloadSHA256        string            `json:"payloadSha256"`
	SecurityProfile      string            `json:"securityProfile,omitempty"`
	CapabilityDigest     string            `json:"securityCapabilityDigest,omitempty"`
	NodeKeyFingerprint   string            `json:"nodeKeyFingerprint,omitempty"`
	Signature            string            `json:"signature"`
}

type bridgeEventBatchContract0194 struct {
	ProtocolVersion int                       `json:"protocolVersion"`
	Features        []string                  `json:"features"`
	ServerID        string                    `json:"serverId"`
	RuntimeID       string                    `json:"runtimeId"`
	Events          []bridgeEventContract0194 `json:"events"`
}

func bridgeEventFeatureMode0194(features []string) (bool, string) {
	set := map[string]struct{}{}
	for _, feature := range normalizeBridgeFeatures0191(features) {
		set[feature] = struct{}{}
	}
	if _, ok := set[serverBridgeFeatureEventStream]; !ok {
		return false, ""
	}
	if _, ok := set[serverBridgeFeatureRuntimeDiscovery]; !ok {
		return false, "serverbridge_event_stream_requires_runtime_identity"
	}
	if _, ok := set[serverBridgeFeatureRuntimeIdentity]; !ok {
		return false, "serverbridge_event_stream_requires_runtime_identity"
	}
	return true, ""
}

func (s Server) serverBridgeEventStream0194(w http.ResponseWriter, r *http.Request) {
	server, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req bridgeEventBatchContract0194
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "serverbridge_event_batch_invalid")
		return
	}
	if req.ProtocolVersion != serverBridgeProtocolV3 {
		writeError(w, http.StatusUpgradeRequired, "serverbridge_event_stream_requires_protocol_v3")
		return
	}
	if ok, reason := validateBridgeProtocolFeatures0191(req.ProtocolVersion, req.Features); !ok {
		writeError(w, http.StatusUpgradeRequired, reason)
		return
	}
	securityV3, securityReason := validateServerBridgeSecurityEnvelope01912(r, req.ProtocolVersion, req.Features)
	if securityReason != "" {
		writeError(w, http.StatusUpgradeRequired, securityReason)
		return
	}
	enabled, reason := bridgeEventFeatureMode0194(req.Features)
	if reason != "" {
		writeError(w, http.StatusUpgradeRequired, reason)
		return
	}
	if !enabled {
		writeError(w, http.StatusBadRequest, "serverbridge_event_stream_not_negotiated")
		return
	}
	if strings.TrimSpace(req.ServerID) != server.ID {
		writeError(w, http.StatusForbidden, "serverbridge_node_server_id_mismatch")
		return
	}
	runtimeID := strings.ToLower(strings.TrimSpace(req.RuntimeID))
	if server.RuntimeEpoch < 1 || len(runtimeID) != 64 || !strings.EqualFold(runtimeID, server.RuntimeID) {
		writeError(w, http.StatusConflict, "serverbridge_event_runtime_not_active")
		return
	}
	if len(req.Events) < 1 || len(req.Events) > serverBridgeEventBatchMax0194 {
		writeError(w, http.StatusBadRequest, "serverbridge_event_batch_size_invalid")
		return
	}

	publicKeyRaw, err := base64.RawURLEncoding.DecodeString(server.PublicKey)
	if err != nil || len(publicKeyRaw) != ed25519.PublicKeySize {
		writeError(w, http.StatusUnauthorized, "serverbridge_node_identity_invalid")
		return
	}
	publicKey := ed25519.PublicKey(publicKeyRaw)
	now := time.Now().UTC()
	events := make([]model.ServerBridgeEvent, 0, len(req.Events))
	var previous int64
	for i, raw := range req.Events {
		event, eventErr := validateBridgeEvent0194(server.ID, runtimeID, server.KeyFingerprint, raw, publicKey, now, securityV3)
		if eventErr != nil {
			s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("event-stream-denied"), Actor: server.ID, Action: "serverbridge:event-stream:denied", Target: eventErr.Error(), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
			writeError(w, http.StatusBadRequest, eventErr.Error())
			return
		}
		if i > 0 && event.Sequence != previous+1 {
			writeError(w, http.StatusConflict, "serverbridge_event_batch_sequence_gap")
			return
		}
		previous = event.Sequence
		events = append(events, event)
	}

	result, err := s.State.ServerBridge.appendEvents0194(server, events, now)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("event-stream-replay-denied"), Actor: server.ID, Action: "serverbridge:event-stream:replay-denied", Target: err.Error(), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
			writeError(w, http.StatusConflict, "serverbridge_event_stream_conflict")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "serverbridge_event_stream_storage_unavailable")
		return
	}
	if s.State.ServerBridge.backendV2() == nil {
		for _, event := range events {
			s.Repo.AddAuditEvent(model.AuditEvent{ID: fmt.Sprintf("serverbridge-event-%s-%d-%d", server.ID, server.RuntimeEpoch, event.Sequence), Actor: server.ID, Action: "serverbridge:event:" + event.Type, Target: event.EventID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion":   bridgePluginsSchema940,
		"toolVersion":     s.Version,
		"protocolVersion": serverBridgeProtocolV3,
		"status":          "events-acknowledged",
		"serverId":        server.ID,
		"runtimeId":       runtimeID,
		"runtimeEpoch":    server.RuntimeEpoch,
		"ackSequence":     result.AckSequence,
		"inserted":        result.Inserted,
	}})
}

func validateBridgeEvent0194(serverID, runtimeID, keyFingerprint string, raw bridgeEventContract0194, publicKey ed25519.PublicKey, now time.Time, securityV3 bool) (model.ServerBridgeEvent, error) {
	raw.EventID = strings.TrimSpace(raw.EventID)
	raw.RuntimeID = strings.ToLower(strings.TrimSpace(raw.RuntimeID))
	raw.Type = strings.ToLower(strings.TrimSpace(raw.Type))
	raw.PayloadSHA256 = strings.ToLower(strings.TrimSpace(raw.PayloadSHA256))
	raw.Signature = strings.TrimSpace(raw.Signature)
	if raw.Sequence < 1 || !serverBridgeEventID0194.MatchString(raw.EventID) {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_identity_invalid")
	}
	if !strings.EqualFold(raw.RuntimeID, runtimeID) {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_runtime_mismatch")
	}
	if _, ok := serverBridgeEventTypes0194[raw.Type]; !ok {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_type_unsupported")
	}
	if raw.OccurredAtUnixMillis <= 0 {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_timestamp_invalid")
	}
	occurred := time.UnixMilli(raw.OccurredAtUnixMillis).UTC()
	if occurred.After(now.Add(2*time.Minute)) || occurred.Before(now.Add(-30*24*time.Hour)) {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_timestamp_out_of_window")
	}
	if len(raw.Payload) > 32 {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_payload_invalid")
	}
	for key, value := range raw.Payload {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || len(key) > 64 || len(value) > 1024 || strings.ContainsAny(key, "\r\n\x00") || strings.ContainsRune(value, '\x00') {
			return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_payload_invalid")
		}
	}
	payloadBytes, err := canonicalBridgeEventPayload0194(raw.Payload)
	if err != nil || len(payloadBytes) > serverBridgeEventPayloadMax0194 {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_payload_invalid")
	}
	digest := sha256.Sum256(payloadBytes)
	digestHex := hex.EncodeToString(digest[:])
	if len(raw.PayloadSHA256) != 64 || subtle.ConstantTimeCompare([]byte(raw.PayloadSHA256), []byte(digestHex)) != 1 {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_payload_digest_invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(raw.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_signature_invalid")
	}
	canonical := ""
	if securityV3 {
		raw.SecurityProfile = strings.TrimSpace(raw.SecurityProfile)
		raw.CapabilityDigest = strings.ToLower(strings.TrimSpace(raw.CapabilityDigest))
		raw.NodeKeyFingerprint = strings.ToLower(strings.TrimSpace(raw.NodeKeyFingerprint))
		if raw.SecurityProfile != serverBridgeSecurityProfile01912 ||
			subtle.ConstantTimeCompare([]byte(raw.CapabilityDigest), []byte(serverBridgeExpectedSecurityCapabilityDigest01912())) != 1 ||
			subtle.ConstantTimeCompare([]byte(raw.NodeKeyFingerprint), []byte(strings.ToLower(strings.TrimSpace(keyFingerprint)))) != 1 {
			return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_security_binding_invalid")
		}
		canonical = serverBridgeEventCanonical01912(serverID, raw.EventID, runtimeID, raw.NodeKeyFingerprint, raw.CapabilityDigest, raw.Sequence, raw.Type, raw.OccurredAtUnixMillis, digestHex)
	} else {
		canonical = bridgeEventCanonical0194(serverID, raw.EventID, runtimeID, raw.Sequence, raw.Type, raw.OccurredAtUnixMillis, digestHex)
	}
	if !ed25519.Verify(publicKey, []byte(canonical), signature) {
		return model.ServerBridgeEvent{}, fmt.Errorf("serverbridge_event_signature_invalid")
	}
	return model.ServerBridgeEvent{Sequence: raw.Sequence, EventID: raw.EventID, RuntimeID: runtimeID, Type: raw.Type, OccurredAtUnixMillis: raw.OccurredAtUnixMillis, Payload: raw.Payload, PayloadSHA256: digestHex, Signature: raw.Signature}, nil
}

func canonicalBridgeEventPayload0194(payload map[string]string) ([]byte, error) {
	// encoding/json sorts string map keys, matching BridgeEventRecord's TreeMap encoding.
	if payload == nil {
		payload = map[string]string{}
	}
	return json.Marshal(payload)
}

func bridgeEventCanonical0194(serverID, eventID, runtimeID string, sequence int64, eventType string, occurredAt int64, payloadSHA string) string {
	return strings.Join([]string{
		serverBridgeEventSignatureScheme0194,
		base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(serverID))),
		strings.TrimSpace(eventID),
		strings.ToLower(strings.TrimSpace(runtimeID)),
		fmt.Sprintf("%d", sequence),
		fmt.Sprintf("%d", occurredAt),
		base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(eventType))),
		strings.ToLower(strings.TrimSpace(payloadSHA)),
	}, "\n")
}

func (b *serverBridgeStore) appendEvents0194(server bridgeServerRecord, events []model.ServerBridgeEvent, now time.Time) (model.ServerBridgeEventAppendResult, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.AppendServerBridgeEvents(ctx, server.ID, server.RuntimeEpoch, server.RuntimeID, events, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current, ok := b.servers[server.ID]
	if !ok || current.Status != "active" || current.RuntimeEpoch != server.RuntimeEpoch || !strings.EqualFold(current.RuntimeID, server.RuntimeID) {
		return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: event runtime not active", repository.ErrConflict)
	}
	if b.eventAck == nil {
		b.eventAck = map[string]int64{}
	}
	if b.eventDigests == nil {
		b.eventDigests = map[string]string{}
	}
	if b.eventIDs == nil {
		b.eventIDs = map[string]string{}
	}
	cursorKey := fmt.Sprintf("%s:%d", server.ID, server.RuntimeEpoch)
	ack := b.eventAck[cursorKey]
	inserted := 0
	for _, event := range events {
		rowKey := fmt.Sprintf("%s:%d", cursorKey, event.Sequence)
		fingerprint := strings.ToLower(event.PayloadSHA256) + "|" + event.Type + "|" + event.Signature
		if event.Sequence <= ack {
			if b.eventDigests[rowKey] != fingerprint || b.eventIDs[rowKey] != event.EventID {
				return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: conflicting event replay", repository.ErrConflict)
			}
			continue
		}
		if event.Sequence != ack+1 {
			return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: event sequence gap", repository.ErrConflict)
		}
		b.eventDigests[rowKey] = fingerprint
		b.eventIDs[rowKey] = event.EventID
		ack = event.Sequence
		inserted++
	}
	b.eventAck[cursorKey] = ack
	return model.ServerBridgeEventAppendResult{AckSequence: ack, Inserted: inserted}, nil
}

// deterministic helper used by tests/certification to keep the declared event types stable.
func serverBridgeEventTypesSorted0194() []string {
	out := make([]string, 0, len(serverBridgeEventTypes0194))
	for eventType := range serverBridgeEventTypes0194 {
		out = append(out, eventType)
	}
	sort.Strings(out)
	return out
}
