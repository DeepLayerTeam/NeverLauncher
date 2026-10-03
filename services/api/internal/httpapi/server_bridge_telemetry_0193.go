package httpapi

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	serverBridgeTelemetryMaxClockPast0193   = 5 * time.Minute
	serverBridgeTelemetryMaxClockFuture0193 = 2 * time.Minute
)

type bridgeServerTelemetryV3Contract0193 struct {
	Sequence                    int64    `json:"sequence"`
	SampledAtUnixMillis         int64    `json:"sampledAtUnixMillis"`
	WindowMillis                int64    `json:"windowMillis"`
	RuntimeID                   string   `json:"runtimeId"`
	TPS                         *float64 `json:"tps,omitempty"`
	MSPT                        *float64 `json:"mspt,omitempty"`
	TickHealth                  string   `json:"tickHealth"`
	PlayersOnline               int      `json:"playersOnline"`
	PlayersMax                  int      `json:"playersMax"`
	HeapUsedBytes               int64    `json:"heapUsedBytes"`
	HeapCommittedBytes          int64    `json:"heapCommittedBytes"`
	HeapMaxBytes                int64    `json:"heapMaxBytes"`
	NonHeapUsedBytes            int64    `json:"nonHeapUsedBytes"`
	NonHeapCommittedBytes       int64    `json:"nonHeapCommittedBytes"`
	GCCollections               int64    `json:"gcCollections"`
	GCCollectionTimeMillis      int64    `json:"gcCollectionTimeMillis"`
	GCCollectionsDelta          int64    `json:"gcCollectionsDelta"`
	GCCollectionTimeDeltaMillis int64    `json:"gcCollectionTimeDeltaMillis"`
	ThreadCount                 int      `json:"threadCount"`
	DaemonThreadCount           int      `json:"daemonThreadCount"`
	PeakThreadCount             int      `json:"peakThreadCount"`
	LoadedWorlds                *int     `json:"loadedWorlds,omitempty"`
	LoadedDimensions            *int     `json:"loadedDimensions,omitempty"`
	LoadedChunks                *int64   `json:"loadedChunks,omitempty"`
	EntityCount                 *int64   `json:"entityCount,omitempty"`
	SamplingBudgetExceeded      bool     `json:"samplingBudgetExceeded"`
	Metrics                     []string `json:"metrics"`
}

func bridgeTelemetryFeatureMode0193(features []string) (bool, string) {
	set := make(map[string]struct{})
	for _, feature := range normalizeBridgeFeatures0191(features) {
		set[feature] = struct{}{}
	}
	_, telemetry := set[serverBridgeFeatureServerTelemetry]
	if !telemetry {
		return false, ""
	}
	_, discovery := set[serverBridgeFeatureRuntimeDiscovery]
	_, identity := set[serverBridgeFeatureRuntimeIdentity]
	if !discovery || !identity {
		return false, "serverbridge_telemetry_requires_runtime_identity"
	}
	return true, ""
}

func validateBridgeTelemetry0193(raw *bridgeServerTelemetryV3Contract0193, runtime model.ServerBridgeRuntimeIdentity, runtimeEpoch int64, now time.Time) (model.ServerBridgeTelemetry, error) {
	if raw == nil {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_required")
	}
	if raw.Sequence <= 0 {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_sequence_invalid")
	}
	if raw.SampledAtUnixMillis <= 0 || raw.WindowMillis < 0 || raw.WindowMillis > int64((10*time.Minute)/time.Millisecond) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_time_invalid")
	}
	sampledAt := time.UnixMilli(raw.SampledAtUnixMillis).UTC()
	if sampledAt.Before(now.Add(-serverBridgeTelemetryMaxClockPast0193)) || sampledAt.After(now.Add(serverBridgeTelemetryMaxClockFuture0193)) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_clock_invalid")
	}
	if !isSHA256Hex0134(strings.ToLower(strings.TrimSpace(raw.RuntimeID))) || !strings.EqualFold(strings.TrimSpace(raw.RuntimeID), runtime.RuntimeID) || runtimeEpoch < 1 {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_runtime_mismatch")
	}
	if raw.TPS != nil && (!finiteBetween0193(*raw.TPS, 0, 1000)) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_tps_invalid")
	}
	if raw.MSPT != nil && (!finiteBetween0193(*raw.MSPT, 0, 600000)) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_mspt_invalid")
	}
	health := strings.ToLower(strings.TrimSpace(raw.TickHealth))
	switch health {
	case "unavailable", "healthy", "degraded", "overloaded":
	default:
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_tick_health_invalid")
	}
	if raw.PlayersOnline < 0 || raw.PlayersOnline > 1_000_000 || raw.PlayersMax < 0 || raw.PlayersMax > 1_000_000 || (raw.PlayersMax > 0 && raw.PlayersOnline > raw.PlayersMax) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_players_invalid")
	}
	if !nonNegativeBounded0193(raw.HeapUsedBytes, 1<<62) ||
		!nonNegativeBounded0193(raw.HeapCommittedBytes, 1<<62) ||
		!nonNegativeBounded0193(raw.HeapMaxBytes, 1<<62) ||
		!nonNegativeBounded0193(raw.NonHeapUsedBytes, 1<<62) ||
		!nonNegativeBounded0193(raw.NonHeapCommittedBytes, 1<<62) ||
		!nonNegativeBounded0193(raw.GCCollections, 1<<62) ||
		!nonNegativeBounded0193(raw.GCCollectionTimeMillis, 1<<62) ||
		!nonNegativeBounded0193(raw.GCCollectionsDelta, 1<<62) ||
		!nonNegativeBounded0193(raw.GCCollectionTimeDeltaMillis, 1<<62) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_jvm_counter_invalid")
	}
	if raw.ThreadCount < 0 || raw.ThreadCount > 1_000_000 || raw.DaemonThreadCount < 0 || raw.DaemonThreadCount > raw.ThreadCount || raw.PeakThreadCount < raw.ThreadCount || raw.PeakThreadCount > 1_000_000 {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_threads_invalid")
	}
	if !validOptionalInt0193(raw.LoadedWorlds, 100_000) || !validOptionalInt0193(raw.LoadedDimensions, 100_000) || !validOptionalInt640193(raw.LoadedChunks, 10_000_000_000) || !validOptionalInt640193(raw.EntityCount, 10_000_000_000) {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_game_counter_invalid")
	}

	metrics := normalizeTelemetryMetrics0193(raw.Metrics)
	if len(metrics) == 0 || len(metrics) > 64 {
		return model.ServerBridgeTelemetry{}, fmt.Errorf("serverbridge_telemetry_metrics_invalid")
	}
	return model.ServerBridgeTelemetry{
		Sequence: raw.Sequence, SampledAtUnixMillis: raw.SampledAtUnixMillis, WindowMillis: raw.WindowMillis,
		RuntimeID: strings.ToLower(strings.TrimSpace(raw.RuntimeID)), RuntimeEpoch: runtimeEpoch, TPS: raw.TPS, MSPT: raw.MSPT,
		TickHealth: health, PlayersOnline: raw.PlayersOnline, PlayersMax: raw.PlayersMax,
		HeapUsedBytes: raw.HeapUsedBytes, HeapCommittedBytes: raw.HeapCommittedBytes, HeapMaxBytes: raw.HeapMaxBytes,
		NonHeapUsedBytes: raw.NonHeapUsedBytes, NonHeapCommittedBytes: raw.NonHeapCommittedBytes,
		GCCollections: raw.GCCollections, GCCollectionTimeMillis: raw.GCCollectionTimeMillis,
		GCCollectionsDelta: raw.GCCollectionsDelta, GCCollectionTimeDeltaMillis: raw.GCCollectionTimeDeltaMillis,
		ThreadCount: raw.ThreadCount, DaemonThreadCount: raw.DaemonThreadCount, PeakThreadCount: raw.PeakThreadCount,
		LoadedWorlds: raw.LoadedWorlds, LoadedDimensions: raw.LoadedDimensions, LoadedChunks: raw.LoadedChunks, EntityCount: raw.EntityCount,
		SamplingBudgetExceeded: raw.SamplingBudgetExceeded, Metrics: metrics,
	}, nil
}

func normalizeTelemetryMetrics0193(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 96 {
			continue
		}
		valid := true
		for _, r := range value {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) > 64 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func finiteBetween0193(value, min, max float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= min && value <= max
}

func nonNegativeBounded0193(value, max int64) bool { return value >= 0 && value <= max }
func validOptionalInt0193(value *int, max int) bool {
	return value == nil || (*value >= 0 && *value <= max)
}
func validOptionalInt640193(value *int64, max int64) bool {
	return value == nil || (*value >= 0 && *value <= max)
}

func (b *serverBridgeStore) saveTelemetry0193(serverID string, runtimeEpoch int64, telemetry model.ServerBridgeTelemetry) error {
	now := time.Now().UTC()
	telemetry.RuntimeEpoch = runtimeEpoch
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		return backend.SaveServerBridgeTelemetry(ctx, serverID, runtimeEpoch, telemetry, now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return fmt.Errorf("server bridge node not found")
	}
	if server.Status != "active" || server.RuntimeEpoch != runtimeEpoch || !strings.EqualFold(server.RuntimeID, telemetry.RuntimeID) {
		return fmt.Errorf("%w: telemetry runtime is not active", repository.ErrConflict)
	}
	if server.Telemetry != nil && server.Telemetry.RuntimeEpoch == runtimeEpoch && telemetry.SampledAtUnixMillis <= server.Telemetry.SampledAtUnixMillis {
		return fmt.Errorf("%w: duplicate or stale telemetry sample", repository.ErrConflict)
	}
	copyValue := telemetry
	copyValue.Metrics = append([]string(nil), telemetry.Metrics...)
	server.Telemetry = &copyValue
	b.servers[serverID] = server
	return nil
}
