package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	serverBridgeProtocolV2      = 2
	serverBridgeProtocolV3      = 3
	serverBridgeProtocolCurrent = serverBridgeProtocolV3
	serverBridgeProtocolMinimum = serverBridgeProtocolV2
)

const (
	serverBridgeFeatureCapabilityNegotiation = "protocol.capability-negotiation"
	serverBridgeFeatureFlags                 = "protocol.feature-flags"
	serverBridgeFeatureRollingUpgrade        = "protocol.rolling-upgrade-v2"
	serverBridgeFeatureNodeSignatures        = "security.ed25519-node-requests"
	serverBridgeFeatureNonceReplay           = "security.single-use-node-nonce"
	serverBridgeFeatureArtifactIntegrity     = "integrity.sha256"
	serverBridgeFeatureOneTimeJoin           = "join.one-time"
	serverBridgeFeatureOneTimeHandoff        = "handoff.one-time"
	serverBridgeFeatureRuntimeTopology       = "topology.runtime-learned"
	serverBridgeFeatureRuntimeDiscovery      = "runtime.node-discovery-v1"
	serverBridgeFeatureRuntimeIdentity       = "security.runtime-identity-ed25519"
	serverBridgeFeatureServerTelemetry       = "telemetry.server-v1"
	serverBridgeFeatureEventStream           = "events.ordered-stream-v1"
	serverBridgeFeatureControlAPI            = "control.secure-channel-v1"
	serverBridgeFeatureRoutingV2             = "topology.routing-v2"
	serverBridgeFeaturePlayerSessionV3        = "session.player-lifecycle-v3"
)

var serverBridgeSupportedProtocols0191 = []int{serverBridgeProtocolV3, serverBridgeProtocolV2}
var serverBridgeV3RequiredFeatures0191 = []string{
	serverBridgeFeatureCapabilityNegotiation,
	serverBridgeFeatureFlags,
}

var serverBridgeV2Features0191 = []string{
	serverBridgeFeatureNodeSignatures,
	serverBridgeFeatureNonceReplay,
	serverBridgeFeatureArtifactIntegrity,
	serverBridgeFeatureOneTimeJoin,
	serverBridgeFeatureOneTimeHandoff,
	serverBridgeFeatureRuntimeTopology,
}

var serverBridgeV3Features0191 = []string{
	serverBridgeFeatureCapabilityNegotiation,
	serverBridgeFeatureFlags,
	serverBridgeFeatureRollingUpgrade,
	serverBridgeFeatureNodeSignatures,
	serverBridgeFeatureNonceReplay,
	serverBridgeFeatureArtifactIntegrity,
	serverBridgeFeatureOneTimeJoin,
	serverBridgeFeatureOneTimeHandoff,
	serverBridgeFeatureRuntimeTopology,
	serverBridgeFeatureRuntimeDiscovery,
	serverBridgeFeatureRuntimeIdentity,
	serverBridgeFeatureServerTelemetry,
	serverBridgeFeatureEventStream,
	serverBridgeFeatureControlAPI,
	serverBridgeFeatureRoutingV2,
	serverBridgeFeaturePlayerSessionV3,
}

type bridgeProtocolEnvelope0191 struct {
	ProtocolVersion int `json:"protocolVersion"`
}

// Protocol v2 request contracts are retained byte-for-byte compatible for a
// rolling upgrade. Protocol v3 has a separate wire contract and carries the
// feature set selected by /server-bridge/capabilities.
type bridgeHeartbeatV2Contract0191 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	ServerID        string `json:"serverId"`
	ServerType      string `json:"serverType"`
	PluginVersion   string `json:"pluginVersion"`
	PluginSHA256    string `json:"pluginSha256"`
	Hostname        string `json:"hostname,omitempty"`
	PlayersOnline   int    `json:"playersOnline,omitempty"`
}

type bridgeHeartbeatV3Contract0191 struct {
	ProtocolVersion int                                  `json:"protocolVersion"`
	Features        []string                             `json:"features"`
	ServerID        string                               `json:"serverId"`
	ServerType      string                               `json:"serverType"`
	PluginVersion   string                               `json:"pluginVersion"`
	PluginSHA256    string                               `json:"pluginSha256"`
	Hostname        string                               `json:"hostname,omitempty"`
	PlayersOnline   int                                  `json:"playersOnline,omitempty"`
	Runtime         *bridgeRuntimeIdentityV3Contract0192 `json:"runtime,omitempty"`
	Telemetry       *bridgeServerTelemetryV3Contract0193 `json:"telemetry,omitempty"`
	Routing         *bridgeRoutingV3Contract0196         `json:"routing,omitempty"`
}

type bridgeValidateJoinV2Contract0191 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	ServerID        string `json:"serverId"`
	Username        string `json:"username"`
	UUID            string `json:"uuid,omitempty"`
	ServerHash      string `json:"serverHash,omitempty"`
	IP              string `json:"ip,omitempty"`
	ProjectID       string `json:"projectId"`
	ProfileID       string `json:"profileId"`
	Channel         string `json:"channel"`
	PluginVersion   string `json:"pluginVersion"`
	PluginSHA256    string `json:"pluginSha256"`
}

type bridgeValidateJoinV3Contract0191 struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Features        []string `json:"features"`
	ServerID        string   `json:"serverId"`
	Username        string   `json:"username"`
	UUID            string   `json:"uuid,omitempty"`
	ServerHash      string   `json:"serverHash,omitempty"`
	IP              string   `json:"ip,omitempty"`
	ProjectID       string   `json:"projectId"`
	ProfileID       string   `json:"profileId"`
	Channel         string   `json:"channel"`
	PluginVersion   string   `json:"pluginVersion"`
	PluginSHA256    string   `json:"pluginSha256"`
}

type bridgeHandoffV2Contract0191 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Username        string `json:"username"`
	TargetServer    string `json:"targetServer"`
}

type bridgeHandoffV3Contract0191 struct {
	ProtocolVersion      int      `json:"protocolVersion"`
	Features             []string `json:"features"`
	Username             string   `json:"username"`
	TargetServer         string   `json:"targetServer"`
	SessionCorrelationID string   `json:"sessionCorrelationId,omitempty"`
}

type bridgePluginHeartbeatRequest940 struct {
	ProtocolVersion int
	Features        []string
	ServerID        string
	ServerType      string
	PluginVersion   string
	PluginSHA256    string
	Hostname        string
	PlayersOnline   int
	Runtime         *bridgeRuntimeIdentityV3Contract0192
	Telemetry       *bridgeServerTelemetryV3Contract0193
	Routing         *bridgeRoutingV3Contract0196
}

type bridgeValidateJoinRequest940 struct {
	ProtocolVersion int
	Features        []string
	ServerID        string
	Username        string
	UUID            string
	ServerHash      string
	IP              string
	ProjectID       string
	ProfileID       string
	Channel         string
	PluginVersion   string
	PluginSHA256    string
}

type bridgeHandoffRequest0148 struct {
	ProtocolVersion      int
	Features             []string
	Username             string
	TargetServer         string
	SessionCorrelationID string
}

func readBridgeProtocolBody0191(r io.Reader) ([]byte, bridgeProtocolEnvelope0191, error) {
	body, err := io.ReadAll(io.LimitReader(r, 128*1024+1))
	if err != nil {
		return nil, bridgeProtocolEnvelope0191{}, err
	}
	if len(body) > 128*1024 {
		return nil, bridgeProtocolEnvelope0191{}, fmt.Errorf("serverbridge request body exceeds 128 KiB")
	}
	var envelope bridgeProtocolEnvelope0191
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, bridgeProtocolEnvelope0191{}, err
	}
	return body, envelope, nil
}

func decodeBridgeContract0191(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values in ServerBridge payload")
		}
		return err
	}
	return nil
}

func decodeBridgeHeartbeat0191(r io.Reader) (bridgePluginHeartbeatRequest940, error) {
	body, envelope, err := readBridgeProtocolBody0191(r)
	if err != nil {
		return bridgePluginHeartbeatRequest940{}, err
	}
	switch envelope.ProtocolVersion {
	case serverBridgeProtocolV2:
		var req bridgeHeartbeatV2Contract0191
		if err := decodeBridgeContract0191(body, &req); err != nil {
			return bridgePluginHeartbeatRequest940{}, err
		}
		return bridgePluginHeartbeatRequest940{ProtocolVersion: req.ProtocolVersion, ServerID: req.ServerID, ServerType: req.ServerType, PluginVersion: req.PluginVersion, PluginSHA256: req.PluginSHA256, Hostname: req.Hostname, PlayersOnline: req.PlayersOnline}, nil
	case serverBridgeProtocolV3:
		var req bridgeHeartbeatV3Contract0191
		if err := decodeBridgeContract0191(body, &req); err != nil {
			return bridgePluginHeartbeatRequest940{}, err
		}
		return bridgePluginHeartbeatRequest940{ProtocolVersion: req.ProtocolVersion, Features: normalizeBridgeFeatures0191(req.Features), ServerID: req.ServerID, ServerType: req.ServerType, PluginVersion: req.PluginVersion, PluginSHA256: req.PluginSHA256, Hostname: req.Hostname, PlayersOnline: req.PlayersOnline, Runtime: req.Runtime, Telemetry: req.Telemetry, Routing: req.Routing}, nil
	default:
		return bridgePluginHeartbeatRequest940{ProtocolVersion: envelope.ProtocolVersion}, nil
	}
}

func decodeBridgeValidateJoin0191(r io.Reader) (bridgeValidateJoinRequest940, error) {
	body, envelope, err := readBridgeProtocolBody0191(r)
	if err != nil {
		return bridgeValidateJoinRequest940{}, err
	}
	switch envelope.ProtocolVersion {
	case serverBridgeProtocolV2:
		var req bridgeValidateJoinV2Contract0191
		if err := decodeBridgeContract0191(body, &req); err != nil {
			return bridgeValidateJoinRequest940{}, err
		}
		return bridgeValidateJoinRequest940{ProtocolVersion: req.ProtocolVersion, ServerID: req.ServerID, Username: req.Username, UUID: req.UUID, ServerHash: req.ServerHash, IP: req.IP, ProjectID: req.ProjectID, ProfileID: req.ProfileID, Channel: req.Channel, PluginVersion: req.PluginVersion, PluginSHA256: req.PluginSHA256}, nil
	case serverBridgeProtocolV3:
		var req bridgeValidateJoinV3Contract0191
		if err := decodeBridgeContract0191(body, &req); err != nil {
			return bridgeValidateJoinRequest940{}, err
		}
		return bridgeValidateJoinRequest940{ProtocolVersion: req.ProtocolVersion, Features: normalizeBridgeFeatures0191(req.Features), ServerID: req.ServerID, Username: req.Username, UUID: req.UUID, ServerHash: req.ServerHash, IP: req.IP, ProjectID: req.ProjectID, ProfileID: req.ProfileID, Channel: req.Channel, PluginVersion: req.PluginVersion, PluginSHA256: req.PluginSHA256}, nil
	default:
		return bridgeValidateJoinRequest940{ProtocolVersion: envelope.ProtocolVersion}, nil
	}
}

func decodeBridgeHandoff0191(r io.Reader) (bridgeHandoffRequest0148, error) {
	body, envelope, err := readBridgeProtocolBody0191(r)
	if err != nil {
		return bridgeHandoffRequest0148{}, err
	}
	switch envelope.ProtocolVersion {
	case serverBridgeProtocolV2:
		var req bridgeHandoffV2Contract0191
		if err := decodeBridgeContract0191(body, &req); err != nil {
			return bridgeHandoffRequest0148{}, err
		}
		return bridgeHandoffRequest0148{ProtocolVersion: req.ProtocolVersion, Username: req.Username, TargetServer: req.TargetServer}, nil
	case serverBridgeProtocolV3:
		var req bridgeHandoffV3Contract0191
		if err := decodeBridgeContract0191(body, &req); err != nil {
			return bridgeHandoffRequest0148{}, err
		}
		return bridgeHandoffRequest0148{ProtocolVersion: req.ProtocolVersion, Features: normalizeBridgeFeatures0191(req.Features), Username: req.Username, TargetServer: req.TargetServer, SessionCorrelationID: req.SessionCorrelationID}, nil
	default:
		return bridgeHandoffRequest0148{ProtocolVersion: envelope.ProtocolVersion}, nil
	}
}

func bridgeNodeProtocolVersion0191(version int) int {
	if bridgeProtocolSupported0191(version) {
		return version
	}
	return serverBridgeProtocolV2
}

func bridgeProtocolSupported0191(version int) bool {
	return version == serverBridgeProtocolV2 || version == serverBridgeProtocolV3
}

func validateBridgeProtocolFeatures0191(version int, features []string) (bool, string) {
	if !bridgeProtocolSupported0191(version) {
		return false, "serverbridge_protocol_unsupported"
	}
	if version == serverBridgeProtocolV2 {
		return true, ""
	}
	normalized := normalizeBridgeFeatures0191(features)
	supported := make(map[string]struct{}, len(serverBridgeV3Features0191))
	for _, feature := range serverBridgeV3Features0191 {
		supported[feature] = struct{}{}
	}
	set := make(map[string]struct{}, len(normalized))
	for _, feature := range normalized {
		if _, ok := supported[feature]; !ok {
			return false, "serverbridge_v3_feature_unsupported"
		}
		set[feature] = struct{}{}
	}
	for _, required := range serverBridgeV3RequiredFeatures0191 {
		if _, ok := set[required]; !ok {
			return false, "serverbridge_v3_required_features_missing"
		}
	}
	return true, ""
}

func normalizeBridgeFeatures0191(features []string) []string {
	set := make(map[string]struct{}, len(features))
	for _, feature := range features {
		feature = strings.ToLower(strings.TrimSpace(feature))
		if feature != "" {
			set[feature] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for feature := range set {
		out = append(out, feature)
	}
	sort.Strings(out)
	return out
}

func bridgeProtocolFeatures0191(version int) []string {
	if version == serverBridgeProtocolV3 {
		return append([]string(nil), serverBridgeV3Features0191...)
	}
	if version == serverBridgeProtocolV2 {
		return append([]string(nil), serverBridgeV2Features0191...)
	}
	return nil
}

func bridgeNegotiatedFeatures0191(version int, offered []string, discovery bool) []string {
	supported := bridgeProtocolFeatures0191(version)
	if discovery {
		return supported
	}
	offeredSet := map[string]struct{}{}
	for _, feature := range normalizeBridgeFeatures0191(offered) {
		offeredSet[feature] = struct{}{}
	}
	out := make([]string, 0, len(supported))
	for _, feature := range supported {
		if _, ok := offeredSet[feature]; ok {
			out = append(out, feature)
		}
	}
	return out
}

func parseBridgeProtocolOffers0191(raw string) ([]int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return append([]int(nil), serverBridgeSupportedProtocols0191...), true
	}
	seen := map[int]struct{}{}
	var out []int
	for _, item := range strings.Split(raw, ",") {
		version, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || version <= 0 {
			continue
		}
		if _, ok := seen[version]; ok {
			continue
		}
		seen[version] = struct{}{}
		out = append(out, version)
	}
	return out, false
}

func parseBridgeFeatureOffers0191(raw string) ([]string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	return normalizeBridgeFeatures0191(strings.Split(raw, ",")), false
}

func negotiateBridgeProtocol0191(protocols []int, features []string, featureDiscovery bool) (int, []string) {
	protocolSet := map[int]struct{}{}
	for _, version := range protocols {
		protocolSet[version] = struct{}{}
	}
	for _, version := range serverBridgeSupportedProtocols0191 {
		if _, ok := protocolSet[version]; !ok {
			continue
		}
		enabled := bridgeNegotiatedFeatures0191(version, features, featureDiscovery)
		if ok, _ := validateBridgeProtocolFeatures0191(version, enabled); ok {
			return version, enabled
		}
	}
	return 0, nil
}

func bridgeFeatureFlags0191(features []string) map[string]bool {
	out := make(map[string]bool, len(serverBridgeV3Features0191))
	for _, feature := range serverBridgeV3Features0191 {
		out[feature] = false
	}
	for _, feature := range features {
		out[feature] = true
	}
	return out
}

func (s Server) serverBridgeCapabilities0191(w http.ResponseWriter, r *http.Request) {
	protocols, _ := parseBridgeProtocolOffers0191(r.URL.Query().Get("protocols"))
	features, featureDiscovery := parseBridgeFeatureOffers0191(r.URL.Query().Get("features"))
	negotiatedProtocol, enabledFeatures := negotiateBridgeProtocol0191(protocols, features, featureDiscovery)
	status := http.StatusOK
	reason := "negotiated"
	if negotiatedProtocol == 0 {
		status = http.StatusUpgradeRequired
		reason = "serverbridge_no_compatible_protocol"
	}
	data := map[string]any{
		"schemaVersion":               bridgePluginsSchema940,
		"toolVersion":                 s.Version,
		"release":                     "ServerBridge 3",
		"status":                      reason,
		"preferredProtocolVersion":    serverBridgeProtocolCurrent,
		"minimumProtocolVersion":      serverBridgeProtocolMinimum,
		"supportedProtocolVersions":   serverBridgeSupportedProtocols0191,
		"negotiatedProtocolVersion":   negotiatedProtocol,
		"features":                    enabledFeatures,
		"featureFlags":                bridgeFeatureFlags0191(enabledFeatures),
		"requiredFeatures":            map[string][]string{"2": []string{}, "3": append([]string(nil), serverBridgeV3RequiredFeatures0191...)},
		"rollingUpgrade":              true,
		"legacyProtocolV2Supported":   true,
		"capabilityNegotiationActive": true,
	}
	if negotiatedProtocol == 0 {
		data["reason"] = reason
	}
	writeJSON(w, status, map[string]any{"apiVersion": bridgePluginsSchema940, "data": data})
}
