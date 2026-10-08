package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	serverBridgeRoutingSignatureScheme0196 = "NeverLauncher-ServerBridge-Routing-v2"
	serverBridgeRoutingMaxClockSkew0196    = 2 * time.Minute
	serverBridgeRoutingFreshnessHTTP0196   = 90 * time.Second
)

type bridgeRoutingV3Contract0196 struct {
	RuntimeID            string `json:"runtimeId"`
	ObservedAtUnixMillis int64  `json:"observedAtUnixMillis"`
	State                string `json:"state"`
	AcceptingConnections bool   `json:"acceptingConnections"`
	PlayersOnline        int    `json:"playersOnline"`
	CapacityMax          int    `json:"capacityMax"`
	Health               string `json:"health"`
	Signature            string `json:"signature"`
}

func bridgeRoutingFeatureMode0196(features []string) bool {
	for _, feature := range normalizeBridgeFeatures0191(features) {
		if feature == serverBridgeFeatureRoutingV2 {
			return true
		}
	}
	return false
}

func bridgeRoutingCanonical0196(serverID string, r bridgeRoutingV3Contract0196) string {
	enc := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(v))) }
	return strings.Join([]string{
		serverBridgeRoutingSignatureScheme0196,
		enc(serverID),
		strings.ToLower(strings.TrimSpace(r.RuntimeID)),
		strconv.FormatInt(r.ObservedAtUnixMillis, 10),
		strings.ToLower(strings.TrimSpace(r.State)),
		strconv.FormatBool(r.AcceptingConnections),
		strconv.Itoa(r.PlayersOnline),
		strconv.Itoa(r.CapacityMax),
		strings.ToLower(strings.TrimSpace(r.Health)),
	}, "\n")
}

func validateAndVerifyBridgeRouting0196(server bridgeServerRecord, raw *bridgeRoutingV3Contract0196, runtime model.ServerBridgeRuntimeIdentity, now time.Time) (model.ServerBridgeRoutingSnapshot, error) {
	if raw == nil {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_snapshot_required")
	}
	r := *raw
	r.RuntimeID = strings.ToLower(strings.TrimSpace(r.RuntimeID))
	r.State = strings.ToLower(strings.TrimSpace(r.State))
	r.Health = strings.ToLower(strings.TrimSpace(r.Health))
	r.Signature = strings.TrimSpace(r.Signature)
	if !isSHA256Hex0134(r.RuntimeID) || !strings.EqualFold(r.RuntimeID, runtime.RuntimeID) {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_runtime_mismatch")
	}
	if r.ObservedAtUnixMillis <= 0 {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_observed_at_invalid")
	}
	observed := time.UnixMilli(r.ObservedAtUnixMillis).UTC()
	if observed.Before(now.Add(-serverBridgeRoutingMaxClockSkew0196)) || observed.After(now.Add(serverBridgeRoutingMaxClockSkew0196)) {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_observed_at_stale")
	}
	switch r.State {
	case "ready", "maintenance", "draining":
	default:
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_state_invalid")
	}
	switch r.Health {
	case "healthy", "degraded", "unhealthy":
	default:
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_health_invalid")
	}
	if r.PlayersOnline < 0 || r.PlayersOnline > 1_000_000 || r.CapacityMax < 0 || r.CapacityMax > 1_000_000 || (r.CapacityMax > 0 && r.PlayersOnline > r.CapacityMax) {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_capacity_invalid")
	}
	// The wire flags must be internally consistent. Maintenance/drain never accept
	// new routes, unhealthy nodes never accept routes, and full finite-capacity
	// targets never advertise acceptance.
	expectedAccepting := r.State == "ready" && r.Health != "unhealthy" && (r.CapacityMax == 0 || r.PlayersOnline < r.CapacityMax)
	if r.AcceptingConnections != expectedAccepting {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_accepting_inconsistent")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(server.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_public_key_invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_signature_invalid")
	}
	canonical := bridgeRoutingCanonical0196(server.ID, r)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(canonical), signature) {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("serverbridge_routing_signature_invalid")
	}
	sum := sha256.Sum256([]byte(canonical))
	return model.ServerBridgeRoutingSnapshot{
		RuntimeID: r.RuntimeID, ObservedAtUnixMillis: r.ObservedAtUnixMillis, State: r.State,
		AcceptingConnections: r.AcceptingConnections, PlayersOnline: r.PlayersOnline, CapacityMax: r.CapacityMax,
		Health: r.Health, Digest: hex.EncodeToString(sum[:]), Signature: r.Signature, ObservedAt: observed,
	}, nil
}

func (b *serverBridgeStore) saveRouting0196(serverID string, runtimeEpoch int64, routing model.ServerBridgeRoutingSnapshot) (model.ServerBridgeRoutingSnapshot, error) {
	now := time.Now().UTC()
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.SaveServerBridgeRoutingState(ctx, serverID, runtimeEpoch, routing, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return model.ServerBridgeRoutingSnapshot{}, repository.ErrNotFound
	}
	if server.Status != "active" || server.RuntimeEpoch != runtimeEpoch || !strings.EqualFold(server.RuntimeID, routing.RuntimeID) {
		return model.ServerBridgeRoutingSnapshot{}, repository.ErrConflict
	}
	if b.routing == nil {
		b.routing = map[string]model.ServerBridgeRoutingSnapshot{}
	}
	prev := b.routing[serverID]
	if !prev.ObservedAt.IsZero() && routing.ObservedAt.Before(prev.ObservedAt) {
		return model.ServerBridgeRoutingSnapshot{}, repository.ErrConflict
	}
	if !prev.ObservedAt.IsZero() && routing.ObservedAt.Equal(prev.ObservedAt) {
		if strings.EqualFold(prev.Digest, routing.Digest) {
			return prev, nil
		}
		return model.ServerBridgeRoutingSnapshot{}, repository.ErrConflict
	}
	routing.Revision = prev.Revision + 1
	if routing.Revision < 1 {
		routing.Revision = 1
	}
	b.routing[serverID] = routing
	return routing, nil
}

func (b *serverBridgeStore) allowedBackends0196(sourceID string) ([]model.ServerBridgeRouteTarget, error) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.ListServerBridgeAllowedBackends(ctx, sourceID, time.Now().UTC())
	}
	return []model.ServerBridgeRouteTarget{}, nil
}

func (b *serverBridgeStore) ensureRoutable0196(server bridgeServerRecord) error {
	now := time.Now().UTC()
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.EnsureServerBridgeNodeRoutable(ctx, server.ID, server.RuntimeEpoch, server.RuntimeID, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	routing, ok := b.routing[server.ID]
	if !ok || server.Status != "active" || server.RuntimeEpoch < 1 || !strings.EqualFold(server.RuntimeID, routing.RuntimeID) ||
		routing.ObservedAt.IsZero() || routing.ObservedAt.Before(now.Add(-serverBridgeRoutingFreshnessHTTP0196)) ||
		routing.State != "ready" || !routing.AcceptingConnections || (routing.Health != "healthy" && routing.Health != "degraded") ||
		(routing.CapacityMax > 0 && routing.PlayersOnline >= routing.CapacityMax) {
		return repository.ErrConflict
	}
	return nil
}

func (s Server) serverBridgeAllowedRoutes0196(w http.ResponseWriter, r *http.Request) {
	source, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
	if strings.TrimSpace(r.PathValue("serverId")) != source.ID {
		writeError(w, http.StatusForbidden, "serverbridge_node_server_id_mismatch")
		return
	}
	if !bridgeProxyKind0148(source.Kind) {
		writeError(w, http.StatusForbidden, "serverbridge_routes_source_must_be_proxy")
		return
	}
	routes, err := s.State.ServerBridge.allowedBackends0196(source.ID)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "serverbridge_source_not_routable")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "serverbridge_routes_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": bridgePluginsSchema940, "data": map[string]any{
		"schemaVersion": bridgePluginsSchema940, "toolVersion": s.Version, "sourceNodeId": source.ID,
		"freshnessSeconds": 90, "items": routes,
	}})
}
