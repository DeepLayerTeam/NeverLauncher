package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	serverBridgeRuntimeIdentityScheme0192 = "NeverLauncher-ServerBridge-RuntimeIdentity-v1"
	serverBridgeRuntimeIDScheme0192       = "NeverLauncher-ServerBridge-RuntimeId-v1"
)

type bridgeRuntimeIdentityV3Contract0192 struct {
	RuntimeID           string   `json:"runtimeId"`
	StartedAt           string   `json:"startedAt"`
	StartedAtUnixMillis int64    `json:"startedAtUnixMillis"`
	UptimeSeconds       int64    `json:"uptimeSeconds"`
	ProcessID           int64    `json:"processId"`
	Hostname            string   `json:"hostname"`
	NodeName            string   `json:"nodeName"`
	MinecraftVersion    string   `json:"minecraftVersion"`
	JavaVersion         string   `json:"javaVersion"`
	JavaVendor          string   `json:"javaVendor"`
	JavaVMName          string   `json:"javaVmName"`
	Platform            string   `json:"platform"`
	LoaderName          string   `json:"loaderName"`
	LoaderVersion       string   `json:"loaderVersion"`
	ServerBrand         string   `json:"serverBrand"`
	Capabilities        []string `json:"capabilities"`
	NodeKeyFingerprint  string   `json:"nodeKeyFingerprint"`
	IdentitySignature   string   `json:"identitySignature"`
}

func bridgeRuntimeFeatureMode0192(features []string) (bool, string) {
	set := map[string]struct{}{}
	for _, feature := range normalizeBridgeFeatures0191(features) {
		set[feature] = struct{}{}
	}
	_, discovery := set[serverBridgeFeatureRuntimeDiscovery]
	_, identity := set[serverBridgeFeatureRuntimeIdentity]
	if discovery != identity {
		return false, "serverbridge_runtime_feature_pair_incomplete"
	}
	return discovery && identity, ""
}

func validateAndVerifyBridgeRuntime0192(server bridgeServerRecord, req bridgePluginHeartbeatRequest940, now time.Time) (model.ServerBridgeRuntimeIdentity, error) {
	if req.Runtime == nil {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_identity_required")
	}
	r := *req.Runtime
	r.RuntimeID = strings.ToLower(strings.TrimSpace(r.RuntimeID))
	r.Hostname = cleanRuntimeText0192(r.Hostname, 255)
	r.NodeName = cleanRuntimeText0192(r.NodeName, 255)
	r.MinecraftVersion = cleanRuntimeText0192(r.MinecraftVersion, 128)
	r.JavaVersion = cleanRuntimeText0192(r.JavaVersion, 128)
	r.JavaVendor = cleanRuntimeText0192(r.JavaVendor, 128)
	r.JavaVMName = cleanRuntimeText0192(r.JavaVMName, 128)
	r.Platform = strings.ToLower(cleanRuntimeText0192(r.Platform, 64))
	r.LoaderName = cleanRuntimeText0192(r.LoaderName, 128)
	r.LoaderVersion = cleanRuntimeText0192(r.LoaderVersion, 128)
	r.ServerBrand = cleanRuntimeText0192(r.ServerBrand, 512)
	r.NodeKeyFingerprint = strings.ToLower(strings.TrimSpace(r.NodeKeyFingerprint))
	r.IdentitySignature = strings.TrimSpace(r.IdentitySignature)

	if !isSHA256Hex0134(r.RuntimeID) {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_ID_недопустимый")
	}
	expectedRuntimeID := bridgeRuntimeID0192(server.ID, r.NodeKeyFingerprint, r.StartedAtUnixMillis, r.ProcessID, r.Hostname)
	if subtle.ConstantTimeCompare([]byte(r.RuntimeID), []byte(expectedRuntimeID)) != 1 {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_ID_привязка_недопустимый")
	}
	if r.StartedAtUnixMillis <= 0 || r.ProcessID <= 0 || r.UptimeSeconds < 0 {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_процесс_метаданные_недопустимый")
	}
	startedAt := time.UnixMilli(r.StartedAtUnixMillis).UTC()
	if startedAt.After(now.Add(2 * time.Minute)) {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_started_at_in_future")
	}
	if strings.TrimSpace(r.StartedAt) == "" {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_started_at_required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(r.StartedAt))
	if err != nil || parsed.UTC().UnixMilli() != r.StartedAtUnixMillis {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_started_at_mismatch")
	}
	if r.UptimeSeconds > int64((10*365*24*time.Hour)/time.Second) {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_uptime_недопустимый")
	}
	if r.Hostname == "" || r.NodeName == "" || r.MinecraftVersion == "" || r.JavaVersion == "" || r.Platform == "" || r.LoaderName == "" || r.ServerBrand == "" {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_discovery_incomplete")
	}
	if r.Platform != strings.ToLower(strings.TrimSpace(req.ServerType)) || r.Platform != strings.ToLower(strings.TrimSpace(server.Kind)) {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_platform_mismatch")
	}
	if len(r.Capabilities) == 0 || len(r.Capabilities) > 64 {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_возможности_недопустимый")
	}
	capabilities := make([]string, 0, len(r.Capabilities))
	seen := map[string]struct{}{}
	for _, capability := range r.Capabilities {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if capability == "" || len(capability) > 128 || strings.ContainsAny(capability, "\r\n\x00") {
			return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_возможность_недопустимый")
		}
		if _, ok := seen[capability]; ok {
			return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_capability_duplicate")
		}
		seen[capability] = struct{}{}
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	if len(server.KeyFingerprint) != 64 || subtle.ConstantTimeCompare([]byte(r.NodeKeyFingerprint), []byte(strings.ToLower(server.KeyFingerprint))) != 1 {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_runtime_node_identity_mismatch")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(server.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_узел_публичный_ключ_недопустимый")
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.IdentitySignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_подпись_недопустимый")
	}
	canonical := bridgeRuntimeCanonical0192(server.ID, r, capabilities)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(canonical), signature) {
		return model.ServerBridgeRuntimeIdentity{}, fmt.Errorf("serverbridge_среда выполнения_подпись_недопустимый")
	}
	digest := sha256.Sum256([]byte(canonical))
	return model.ServerBridgeRuntimeIdentity{
		RuntimeID:           r.RuntimeID,
		StartedAt:           startedAt,
		StartedAtUnixMillis: r.StartedAtUnixMillis,
		UptimeSeconds:       r.UptimeSeconds,
		ProcessID:           r.ProcessID,
		Hostname:            r.Hostname,
		NodeName:            r.NodeName,
		MinecraftVersion:    r.MinecraftVersion,
		JavaVersion:         r.JavaVersion,
		JavaVendor:          r.JavaVendor,
		JavaVMName:          r.JavaVMName,
		Platform:            r.Platform,
		LoaderName:          r.LoaderName,
		LoaderVersion:       r.LoaderVersion,
		ServerBrand:         r.ServerBrand,
		Capabilities:        capabilities,
		NodeKeyFingerprint:  r.NodeKeyFingerprint,
		IdentitySignature:   r.IdentitySignature,
		IdentityDigest:      hex.EncodeToString(digest[:]),
	}, nil
}

func bridgeRuntimeID0192(serverID, fingerprint string, startedAtUnixMillis, processID int64, hostname string) string {
	source := strings.Join([]string{
		serverBridgeRuntimeIDScheme0192,
		base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(serverID))),
		strings.ToLower(strings.TrimSpace(fingerprint)),
		fmt.Sprintf("%d", startedAtUnixMillis),
		fmt.Sprintf("%d", processID),
		base64.RawURLEncoding.EncodeToString([]byte(hostname)),
	}, "\n")
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func bridgeRuntimeCanonical0192(serverID string, r bridgeRuntimeIdentityV3Contract0192, capabilities []string) string {
	return strings.Join([]string{
		serverBridgeRuntimeIdentityScheme0192,
		base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(serverID))),
		strings.ToLower(strings.TrimSpace(r.NodeKeyFingerprint)),
		strings.ToLower(strings.TrimSpace(r.RuntimeID)),
		fmt.Sprintf("%d", r.StartedAtUnixMillis),
		fmt.Sprintf("%d", r.ProcessID),
		base64.RawURLEncoding.EncodeToString([]byte(r.Hostname)),
		base64.RawURLEncoding.EncodeToString([]byte(r.NodeName)),
		base64.RawURLEncoding.EncodeToString([]byte(r.MinecraftVersion)),
		base64.RawURLEncoding.EncodeToString([]byte(r.JavaVersion)),
		base64.RawURLEncoding.EncodeToString([]byte(r.JavaVendor)),
		base64.RawURLEncoding.EncodeToString([]byte(r.JavaVMName)),
		base64.RawURLEncoding.EncodeToString([]byte(strings.ToLower(r.Platform))),
		base64.RawURLEncoding.EncodeToString([]byte(r.LoaderName)),
		base64.RawURLEncoding.EncodeToString([]byte(r.LoaderVersion)),
		base64.RawURLEncoding.EncodeToString([]byte(r.ServerBrand)),
		base64.RawURLEncoding.EncodeToString([]byte(strings.Join(capabilities, "\n"))),
	}, "\n")
}

func cleanRuntimeText0192(value string, max int) string {
	value = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(value))
	if len(value) > max {
		return value[:max]
	}
	return value
}

func (b *serverBridgeStore) markRuntimeHeartbeat0192(serverID, serverType, pluginVersion string, protocolVersion int, runtime model.ServerBridgeRuntimeIdentity) (model.ServerBridgeRuntimeTransition, error) {
	now := time.Now().UTC()
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.TouchServerBridgeNodeRuntimeHeartbeat(ctx, serverID, serverType, pluginVersion, protocolVersion, runtime, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("сервер мост узел не found")
	}
	if server.Status != "active" || strings.ToLower(strings.TrimSpace(serverType)) != strings.ToLower(strings.TrimSpace(server.Kind)) || !strings.EqualFold(server.KeyFingerprint, runtime.NodeKeyFingerprint) {
		return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("сервер мост узел identity/type является не активный")
	}
	if server.RuntimeID == runtime.RuntimeID {
		if server.RuntimeIdentityDigest == "" || !strings.EqualFold(server.RuntimeIdentityDigest, runtime.IdentityDigest) {
			return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("%w: среда выполнения идентичность mutated для существующий среда выполнения ID", repository.ErrConflict)
		}
		server.ProtocolVersion = protocolVersion
		server.LastHeartbeatAt = now
		server.RuntimeLastSeenAt = now
		server.RuntimeUptimeSeconds = runtime.UptimeSeconds
		server.Fingerprint = firstNonEmpty(server.Fingerprint, "plugin:"+pluginVersion)
		b.servers[serverID] = server
		return model.ServerBridgeRuntimeTransition{RuntimeID: runtime.RuntimeID, RuntimeEpoch: server.RuntimeEpoch, Transition: "unchanged", StartedAt: server.RuntimeStartedAt, FirstSeenAt: server.RuntimeFirstSeenAt, LastSeenAt: now}, nil
	}
	previous := server.RuntimeID
	if previous != "" && !server.RuntimeStartedAt.IsZero() && !runtime.StartedAt.After(server.RuntimeStartedAt) {
		return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("%w: среда выполнения экземпляр является старый чем активный среда выполнения", repository.ErrConflict)
	}
	replacement := previous != "" && !server.RuntimeLastSeenAt.IsZero() && server.RuntimeLastSeenAt.After(now.Add(-2*time.Minute))
	transition := "started"
	if previous != "" {
		if replacement {
			transition = "replacement"
		} else {
			transition = "restart"
		}
	}
	server.RuntimeEpoch++
	if server.RuntimeEpoch < 1 {
		server.RuntimeEpoch = 1
	}
	server.RuntimePreviousID = previous
	server.RuntimeID = runtime.RuntimeID
	server.RuntimeTransition = transition
	server.RuntimeReplacementDetected = replacement
	server.RuntimeStartedAt = runtime.StartedAt
	server.RuntimeFirstSeenAt = now
	server.RuntimeLastSeenAt = now
	server.RuntimeUptimeSeconds = runtime.UptimeSeconds
	server.RuntimeProcessID = runtime.ProcessID
	server.Hostname = runtime.Hostname
	server.NodeName = runtime.NodeName
	server.MinecraftVersion = runtime.MinecraftVersion
	server.JavaVersion = runtime.JavaVersion
	server.JavaVendor = runtime.JavaVendor
	server.JavaVMName = runtime.JavaVMName
	server.RuntimePlatform = runtime.Platform
	server.LoaderName = runtime.LoaderName
	server.LoaderVersion = runtime.LoaderVersion
	server.ServerBrand = runtime.ServerBrand
	server.RuntimeCapabilities = append([]string(nil), runtime.Capabilities...)
	server.RuntimeIdentityDigest = runtime.IdentityDigest
	server.Telemetry = nil
	server.ProtocolVersion = protocolVersion
	server.LastHeartbeatAt = now
	server.Fingerprint = firstNonEmpty(server.Fingerprint, "plugin:"+pluginVersion)
	b.servers[serverID] = server
	return model.ServerBridgeRuntimeTransition{RuntimeID: runtime.RuntimeID, RuntimeEpoch: server.RuntimeEpoch, PreviousRuntimeID: previous, Transition: transition, ReplacementDetected: replacement, StartedAt: runtime.StartedAt, FirstSeenAt: now, LastSeenAt: now}, nil
}

func bridgeRuntimeResponse0192(runtime model.ServerBridgeRuntimeIdentity, transition model.ServerBridgeRuntimeTransition) map[string]any {
	return map[string]any{
		"runtimeId":           transition.RuntimeID,
		"runtimeEpoch":        transition.RuntimeEpoch,
		"previousRuntimeId":   transition.PreviousRuntimeID,
		"transition":          transition.Transition,
		"replacementDetected": transition.ReplacementDetected,
		"startedAt":           transition.StartedAt,
		"firstSeenAt":         transition.FirstSeenAt,
		"lastSeenAt":          transition.LastSeenAt,
		"uptimeSeconds":       runtime.UptimeSeconds,
		"processId":           runtime.ProcessID,
		"hostname":            runtime.Hostname,
		"nodeName":            runtime.NodeName,
		"minecraftVersion":    runtime.MinecraftVersion,
		"java":                map[string]any{"version": runtime.JavaVersion, "vendor": runtime.JavaVendor, "vmName": runtime.JavaVMName},
		"platform":            runtime.Platform,
		"loader":              map[string]any{"name": runtime.LoaderName, "version": runtime.LoaderVersion},
		"serverBrand":         runtime.ServerBrand,
		"capabilities":        runtime.Capabilities,
		"identityDigest":      runtime.IdentityDigest,
		"nodeKeyFingerprint":  runtime.NodeKeyFingerprint,
		"attestation":         "ed25519-node-identity",
	}
}
