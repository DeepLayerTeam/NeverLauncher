package httpapi

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

const serverBridgeIntegrityPolicy0135 = "serverbridge-artifact-sha256-v1"

type bridgeReleasePolicy0135 struct {
	VelocitySHA256 []string `json:"velocitySha256"`
	PaperSHA256    []string `json:"paperSha256"`
	PurpurSHA256   []string `json:"purpurSha256"`
}

type bridgePluginIntegrityDecision0135 struct {
	Allowed       bool      `json:"allowed"`
	Required      bool      `json:"required"`
	Reason        string    `json:"reason"`
	Policy        string    `json:"policy"`
	ServerType    string    `json:"serverType,omitempty"`
	PluginVersion string    `json:"pluginVersion,omitempty"`
	PluginSHA256  string    `json:"pluginSha256,omitempty"`
	VerifiedAt    time.Time `json:"verifiedAt,omitempty"`
}

func (s Server) bridgeIntegrityRequired0135() bool {
	return config.IsProductionEnvironment(s.Config.Environment) || strings.TrimSpace(s.Config.BridgeReleaseAllowlistJSON) != ""
}

func (s Server) bridgeReleasePolicies0135() (map[string]bridgeReleasePolicy0135, error) {
	raw := strings.TrimSpace(s.Config.BridgeReleaseAllowlistJSON)
	if raw == "" {
		return nil, errors.New("NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON is not configured")
	}
	policies := map[string]bridgeReleasePolicy0135{}
	if err := json.Unmarshal([]byte(raw), &policies); err != nil {
		return nil, fmt.Errorf("invalid ServerBridge release allowlist: %w", err)
	}
	if len(policies) == 0 {
		return nil, errors.New("ServerBridge release allowlist is empty")
	}
	out := make(map[string]bridgeReleasePolicy0135, len(policies))
	for version, policy := range policies {
		version = strings.TrimSpace(version)
		if version == "" || len(version) > 64 {
			return nil, errors.New("ServerBridge release allowlist contains invalid version")
		}
		velocity, err := normalizeHashList0134(policy.VelocitySHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge velocity release %s: %w", version, err)
		}
		paper, err := normalizeHashList0134(policy.PaperSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge paper release %s: %w", version, err)
		}
		purpur, err := normalizeHashList0134(policy.PurpurSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge purpur release %s: %w", version, err)
		}
		policy.VelocitySHA256 = velocity
		policy.PaperSHA256 = paper
		policy.PurpurSHA256 = purpur
		out[version] = policy
	}
	return out, nil
}

func bridgeHashesForKind0135(policy bridgeReleasePolicy0135, kind string) []string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "velocity":
		return policy.VelocitySHA256
	case "paper":
		return policy.PaperSHA256
	case "purpur":
		return policy.PurpurSHA256
	default:
		return nil
	}
}

func bridgeIntegrityDecisionFromServer0135(required, allowed bool, reason string, server bridgeServerRecord) bridgePluginIntegrityDecision0135 {
	return bridgePluginIntegrityDecision0135{
		Allowed:       allowed,
		Required:      required,
		Reason:        reason,
		Policy:        serverBridgeIntegrityPolicy0135,
		ServerType:    strings.ToLower(strings.TrimSpace(server.Kind)),
		PluginVersion: strings.TrimSpace(server.PluginVersion),
		PluginSHA256:  strings.ToLower(strings.TrimSpace(server.PluginSHA256)),
		VerifiedAt:    server.IntegrityVerifiedAt,
	}
}

func (s Server) validateBridgePluginMeasurement0135(server bridgeServerRecord, serverType, pluginVersion, pluginSHA256 string) bridgePluginIntegrityDecision0135 {
	required := s.bridgeIntegrityRequired0135()
	serverType = strings.ToLower(strings.TrimSpace(serverType))
	pluginVersion = strings.TrimSpace(pluginVersion)
	pluginSHA256 = strings.ToLower(strings.TrimSpace(pluginSHA256))
	if !required {
		return bridgePluginIntegrityDecision0135{Allowed: true, Required: false, Reason: "bridge_integrity_not_required", Policy: serverBridgeIntegrityPolicy0135, ServerType: firstNonEmpty(serverType, server.Kind), PluginVersion: pluginVersion, PluginSHA256: pluginSHA256}
	}
	if serverType == "" || pluginVersion == "" || !isSHA256Hex0134(pluginSHA256) {
		return bridgePluginIntegrityDecision0135{Allowed: false, Required: true, Reason: "bridge_integrity_measurement_missing", Policy: serverBridgeIntegrityPolicy0135, ServerType: serverType, PluginVersion: pluginVersion, PluginSHA256: pluginSHA256}
	}
	if serverType != strings.ToLower(strings.TrimSpace(server.Kind)) {
		return bridgePluginIntegrityDecision0135{Allowed: false, Required: true, Reason: "bridge_integrity_server_type_mismatch", Policy: serverBridgeIntegrityPolicy0135, ServerType: serverType, PluginVersion: pluginVersion, PluginSHA256: pluginSHA256}
	}
	policies, err := s.bridgeReleasePolicies0135()
	if err != nil {
		return bridgePluginIntegrityDecision0135{Allowed: false, Required: true, Reason: "bridge_integrity_policy_unavailable", Policy: serverBridgeIntegrityPolicy0135, ServerType: serverType, PluginVersion: pluginVersion, PluginSHA256: pluginSHA256}
	}
	policy, ok := policies[pluginVersion]
	if !ok {
		return bridgePluginIntegrityDecision0135{Allowed: false, Required: true, Reason: "bridge_integrity_release_revoked", Policy: serverBridgeIntegrityPolicy0135, ServerType: serverType, PluginVersion: pluginVersion, PluginSHA256: pluginSHA256}
	}
	if !containsHash0134(bridgeHashesForKind0135(policy, serverType), pluginSHA256) {
		return bridgePluginIntegrityDecision0135{Allowed: false, Required: true, Reason: "bridge_integrity_hash_rejected", Policy: serverBridgeIntegrityPolicy0135, ServerType: serverType, PluginVersion: pluginVersion, PluginSHA256: pluginSHA256}
	}
	return bridgePluginIntegrityDecision0135{Allowed: true, Required: true, Reason: "bridge_integrity_verified", Policy: serverBridgeIntegrityPolicy0135, ServerType: serverType, PluginVersion: pluginVersion, PluginSHA256: pluginSHA256, VerifiedAt: time.Now().UTC()}
}

func (s Server) evaluateRegisteredBridgeIntegrity0135(server bridgeServerRecord) bridgePluginIntegrityDecision0135 {
	required := s.bridgeIntegrityRequired0135()
	if !required {
		return bridgeIntegrityDecisionFromServer0135(false, true, "bridge_integrity_not_required", server)
	}
	if server.IntegrityStatus != "verified" || server.IntegrityVerifiedAt.IsZero() || strings.TrimSpace(server.PluginVersion) == "" || !isSHA256Hex0134(strings.ToLower(strings.TrimSpace(server.PluginSHA256))) {
		return bridgeIntegrityDecisionFromServer0135(true, false, "bridge_integrity_heartbeat_required", server)
	}
	decision := s.validateBridgePluginMeasurement0135(server, server.Kind, server.PluginVersion, server.PluginSHA256)
	decision.VerifiedAt = server.IntegrityVerifiedAt
	return decision
}

func validateBridgeRequestMeasurement0135(server bridgeServerRecord, req bridgeValidateJoinRequest940) bool {
	version := strings.TrimSpace(req.PluginVersion)
	hash := strings.ToLower(strings.TrimSpace(req.PluginSHA256))
	if version == "" || hash == "" {
		return false
	}
	return hmac.Equal([]byte(strings.TrimSpace(server.PluginVersion)), []byte(version)) && hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(server.PluginSHA256))), []byte(hash))
}

func (b *serverBridgeStore) setIntegrityMeasurement0135(serverID string, decision bridgePluginIntegrityDecision0135) {
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return
	}
	server.PluginVersion = strings.TrimSpace(decision.PluginVersion)
	server.PluginSHA256 = strings.ToLower(strings.TrimSpace(decision.PluginSHA256))
	if decision.Allowed {
		server.IntegrityStatus = "verified"
		server.IntegrityVerifiedAt = decision.VerifiedAt.UTC()
	} else {
		server.IntegrityStatus = "rejected:" + strings.TrimSpace(decision.Reason)
		server.IntegrityVerifiedAt = time.Time{}
	}
	b.servers[serverID] = server
}

func (b *serverBridgeStore) serverRecord0135(serverID string) (bridgeServerRecord, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[strings.TrimSpace(serverID)]
	return server, ok
}
