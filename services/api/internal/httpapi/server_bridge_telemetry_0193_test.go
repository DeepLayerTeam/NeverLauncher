package httpapi

import (
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func testTelemetry0193(now time.Time, runtimeID string) *bridgeServerTelemetryV3Contract0193 {
	tps := 20.0
	mspt := 12.5
	worlds := 3
	dimensions := 3
	chunks := int64(420)
	entities := int64(1337)
	return &bridgeServerTelemetryV3Contract0193{
		Sequence: 7, SampledAtUnixMillis: now.UnixMilli(), WindowMillis: 10_000, RuntimeID: runtimeID,
		TPS: &tps, MSPT: &mspt, TickHealth: "healthy", PlayersOnline: 4, PlayersMax: 100,
		HeapUsedBytes: 128 << 20, HeapCommittedBytes: 256 << 20, HeapMaxBytes: 1024 << 20,
		NonHeapUsedBytes: 32 << 20, NonHeapCommittedBytes: 64 << 20,
		GCCollections: 12, GCCollectionTimeMillis: 80, GCCollectionsDelta: 1, GCCollectionTimeDeltaMillis: 4,
		ThreadCount: 42, DaemonThreadCount: 20, PeakThreadCount: 48,
		LoadedWorlds: &worlds, LoadedDimensions: &dimensions, LoadedChunks: &chunks, EntityCount: &entities,
		Metrics: []string{"JVM.Heap", "server.tick", "server.tick"},
	}
}

func TestValidateBridgeTelemetry0193BindsRuntimeAndNormalizesMetrics(t *testing.T) {
	now := time.Now().UTC()
	runtimeID := strings.Repeat("a", 64)
	runtime := model.ServerBridgeRuntimeIdentity{RuntimeID: runtimeID}
	got, err := validateBridgeTelemetry0193(testTelemetry0193(now, runtimeID), runtime, 9, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.RuntimeEpoch != 9 || got.RuntimeID != runtimeID || got.Sequence != 7 {
		t.Fatalf("unexpected runtime binding: %+v", got)
	}
	if len(got.Metrics) != 2 || got.Metrics[0] != "jvm.heap" || got.Metrics[1] != "server.tick" {
		t.Fatalf("metrics were not normalized: %#v", got.Metrics)
	}
}

func TestValidateBridgeTelemetry0193RejectsRuntimeMismatchAndStaleClock(t *testing.T) {
	now := time.Now().UTC()
	runtimeID := strings.Repeat("b", 64)
	runtime := model.ServerBridgeRuntimeIdentity{RuntimeID: runtimeID}
	raw := testTelemetry0193(now, strings.Repeat("c", 64))
	if _, err := validateBridgeTelemetry0193(raw, runtime, 2, now); err == nil || !strings.Contains(err.Error(), "runtime_mismatch") {
		t.Fatalf("expected runtime mismatch, got %v", err)
	}
	raw = testTelemetry0193(now.Add(-10*time.Minute), runtimeID)
	if _, err := validateBridgeTelemetry0193(raw, runtime, 2, now); err == nil || !strings.Contains(err.Error(), "clock_invalid") {
		t.Fatalf("expected stale sample rejection, got %v", err)
	}
}

func TestValidateBridgeTelemetry0193AllowsUnsupportedPlatformCounters(t *testing.T) {
	now := time.Now().UTC()
	runtimeID := strings.Repeat("d", 64)
	runtime := model.ServerBridgeRuntimeIdentity{RuntimeID: runtimeID}
	raw := testTelemetry0193(now, runtimeID)
	raw.TPS = nil
	raw.MSPT = nil
	raw.TickHealth = "unavailable"
	raw.LoadedWorlds = nil
	raw.LoadedDimensions = nil
	raw.LoadedChunks = nil
	raw.EntityCount = nil
	raw.SamplingBudgetExceeded = true
	raw.Metrics = []string{"jvm.heap", "jvm.threads", "proxy.players"}
	got, err := validateBridgeTelemetry0193(raw, runtime, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.LoadedChunks != nil || got.EntityCount != nil || !got.SamplingBudgetExceeded {
		t.Fatalf("unsupported/budgeted metrics were altered: %+v", got)
	}
}

func TestBridgeTelemetryFeatureRequiresRuntimeIdentity(t *testing.T) {
	if enabled, reason := bridgeTelemetryFeatureMode0193([]string{serverBridgeFeatureServerTelemetry}); enabled || reason == "" {
		t.Fatalf("telemetry without runtime pair must be rejected: enabled=%v reason=%q", enabled, reason)
	}
	enabled, reason := bridgeTelemetryFeatureMode0193([]string{
		serverBridgeFeatureRuntimeDiscovery,
		serverBridgeFeatureRuntimeIdentity,
		serverBridgeFeatureServerTelemetry,
	})
	if !enabled || reason != "" {
		t.Fatalf("expected telemetry to be enabled: enabled=%v reason=%q", enabled, reason)
	}
}
