package httpapi

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const serverBridgeIntegrityPolicy0135 = "serverbridge-artifact-sha256-v1"

type bridgeReleasePolicy0135 struct {
	VelocitySHA256   []string `json:"velocitySha256"`
	BungeeCordSHA256 []string `json:"bungeeCordSha256"`
	WaterfallSHA256  []string `json:"waterfallSha256"`
	BukkitSHA256     []string `json:"bukkitSha256"`
	SpigotSHA256     []string `json:"spigotSha256"`
	PaperSHA256      []string `json:"paperSha256"`
	PurpurSHA256     []string `json:"purpurSha256"`
	FoliaSHA256      []string `json:"foliaSha256"`
	FabricSHA256     []string `json:"fabricSha256"`
	ForgeSHA256      []string `json:"forgeSha256"`
	NeoForgeSHA256   []string `json:"neoforgeSha256"`
	QuiltSHA256      []string `json:"quiltSha256"`
	SpongeSHA256     []string `json:"spongeSha256"`
	VanillaSHA256    []string `json:"vanillaSha256"`
}

type bridgeReleaseAllowlistDocument01912 struct {
	SchemaVersion            string                             `json:"schemaVersion"`
	Release                  string                             `json:"release"`
	ProtocolVersion          int                                `json:"protocolVersion"`
	MinimumProtocolVersion   int                                `json:"minimumProtocolVersion"`
	SecurityProfile          string                             `json:"securityProfile"`
	SecurityCapabilityDigest string                             `json:"securityCapabilityDigest"`
	RequiredFeatures         []string                           `json:"requiredFeatures"`
	Releases                 map[string]bridgeReleasePolicy0135 `json:"releases"`
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
		return nil, errors.New("NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON является не настраивать")
	}
	policies := map[string]bridgeReleasePolicy0135{}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return nil, fmt.Errorf("недопустимый ServerBridge релиз список разрешений: %w", err)
	}
	if _, v3 := probe["schemaVersion"]; v3 {
		var document bridgeReleaseAllowlistDocument01912
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			return nil, fmt.Errorf("недопустимый ServerBridge 3 релиз список разрешений: %w", err)
		}
		if document.SchemaVersion != "3.0" || document.Release != "ServerBridge 3" || document.ProtocolVersion != serverBridgeProtocolV3 || document.MinimumProtocolVersion != serverBridgeProtocolV3 ||
			document.SecurityProfile != serverBridgeSecurityProfile01912 || !strings.EqualFold(document.SecurityCapabilityDigest, serverBridgeExpectedSecurityCapabilityDigest01912()) ||
			!serverBridgeSecurityFeaturesExact01912(document.RequiredFeatures) {
			return nil, errors.New("ServerBridge 3 релиз список разрешений безопасность сертификация метаданные является недопустимый")
		}
		policies = document.Releases
	} else if err := json.Unmarshal([]byte(raw), &policies); err != nil {
		return nil, fmt.Errorf("недопустимый устаревший ServerBridge релиз список разрешений: %w", err)
	}
	if len(policies) == 0 {
		return nil, errors.New("ServerBridge релиз список разрешений является пустой")
	}
	out := make(map[string]bridgeReleasePolicy0135, len(policies))
	for version, policy := range policies {
		version = strings.TrimSpace(version)
		if version == "" || len(version) > 64 {
			return nil, errors.New("ServerBridge релиз список разрешений содержит недопустимый версия")
		}
		velocity, err := normalizeHashList0134(policy.VelocitySHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Velocity релиз %s: %w", version, err)
		}
		bungeecord, err := normalizeOptionalBridgeHashes0144(policy.BungeeCordSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge BungeeCord релиз %s: %w", version, err)
		}
		waterfall, err := normalizeOptionalBridgeHashes0144(policy.WaterfallSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Waterfall релиз %s: %w", version, err)
		}
		paper, err := normalizeHashList0134(policy.PaperSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Paper релиз %s: %w", version, err)
		}
		purpur, err := normalizeHashList0134(policy.PurpurSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Purpur релиз %s: %w", version, err)
		}
		bukkit, err := normalizeOptionalBridgeHashes0144(policy.BukkitSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Bukkit релиз %s: %w", version, err)
		}
		spigot, err := normalizeOptionalBridgeHashes0144(policy.SpigotSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Spigot релиз %s: %w", version, err)
		}
		folia, err := normalizeOptionalBridgeHashes0144(policy.FoliaSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Folia релиз %s: %w", version, err)
		}
		fabric, err := normalizeOptionalBridgeHashes0144(policy.FabricSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Fabric релиз %s: %w", version, err)
		}
		forge, err := normalizeOptionalBridgeHashes0144(policy.ForgeSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Forge релиз %s: %w", version, err)
		}
		neoforge, err := normalizeOptionalBridgeHashes0144(policy.NeoForgeSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge NeoForge релиз %s: %w", version, err)
		}
		quilt, err := normalizeOptionalBridgeHashes0144(policy.QuiltSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Quilt релиз %s: %w", version, err)
		}
		sponge, err := normalizeOptionalBridgeHashes0144(policy.SpongeSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge sponge релиз %s: %w", version, err)
		}
		vanilla, err := normalizeOptionalBridgeHashes0144(policy.VanillaSHA256)
		if err != nil {
			return nil, fmt.Errorf("ServerBridge Vanilla релиз %s: %w", version, err)
		}
		policy.VelocitySHA256 = velocity
		policy.BungeeCordSHA256 = bungeecord
		policy.WaterfallSHA256 = waterfall
		policy.BukkitSHA256 = bukkit
		policy.SpigotSHA256 = spigot
		policy.PaperSHA256 = paper
		policy.PurpurSHA256 = purpur
		policy.FoliaSHA256 = folia
		policy.FabricSHA256 = fabric
		policy.ForgeSHA256 = forge
		policy.NeoForgeSHA256 = neoforge
		policy.QuiltSHA256 = quilt
		policy.SpongeSHA256 = sponge
		policy.VanillaSHA256 = vanilla
		out[version] = policy
	}
	return out, nil
}

func normalizeOptionalBridgeHashes0144(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return normalizeHashList0134(values)
}

func bridgeHashesForKind0135(policy bridgeReleasePolicy0135, kind string) []string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "velocity":
		return policy.VelocitySHA256
	case "bungeecord":
		return policy.BungeeCordSHA256
	case "waterfall":
		return policy.WaterfallSHA256
	case "bukkit":
		return policy.BukkitSHA256
	case "spigot":
		return policy.SpigotSHA256
	case "paper":
		return policy.PaperSHA256
	case "purpur":
		return policy.PurpurSHA256
	case "folia":
		return policy.FoliaSHA256
	case "fabric":
		return policy.FabricSHA256
	case "forge":
		return policy.ForgeSHA256
	case "neoforge":
		return policy.NeoForgeSHA256
	case "quilt":
		return policy.QuiltSHA256
	case "sponge":
		return policy.SpongeSHA256
	case "vanilla":
		return policy.VanillaSHA256
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

func (b *serverBridgeStore) setIntegrityMeasurement0135(serverID string, decision bridgePluginIntegrityDecision0135) error {
	status := "rejected:" + strings.TrimSpace(decision.Reason)
	verifiedAt := time.Time{}
	if decision.Allowed {
		status = "verified"
		verifiedAt = decision.VerifiedAt.UTC()
	}
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.SetServerBridgeNodeIntegrity(ctx, serverID, strings.TrimSpace(decision.PluginVersion), strings.ToLower(strings.TrimSpace(decision.PluginSHA256)), status, verifiedAt)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return repository.ErrNotFound
	}
	server.PluginVersion = strings.TrimSpace(decision.PluginVersion)
	server.PluginSHA256 = strings.ToLower(strings.TrimSpace(decision.PluginSHA256))
	server.IntegrityStatus = status
	server.IntegrityVerifiedAt = verifiedAt
	b.servers[serverID] = server
	return nil
}

func (b *serverBridgeStore) serverRecord0135(serverID string) (bridgeServerRecord, bool) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		server, err := backend.GetServerBridgeNode(ctx, strings.TrimSpace(serverID))
		if err != nil {
			return bridgeServerRecord{}, false
		}
		return bridgeServerFromModelV2(server), true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[strings.TrimSpace(serverID)]
	return server, ok
}
