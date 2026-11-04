package httpapi

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"strings"
	"testing"
	"time"
)

func TestBridgeLiveTelemetry0419FailClosed(t *testing.T) {
	now := time.Now().UTC()
	rid := strings.Repeat("a", 64)
	pid := int64(71234)
	node := bridgeServerRecord{Status: "active", RuntimeID: rid, RuntimeEpoch: 6, RuntimeProcessID: pid,
		LastHeartbeatAt: now.Add(-2 * time.Second), Telemetry: &model.ServerBridgeTelemetry{
			RuntimeID: rid, RuntimeEpoch: 6, SampledAtUnixMillis: now.Add(-3 * time.Second).UnixMilli(), ProcessID: &pid,
		}}
	if _, status := bridgeCurrentTelemetry0419(node, now); status != "fresh" {
		t.Fatal(status)
	}
	scenarios := map[string]func(*bridgeServerRecord){
		"lost heartbeat":   func(n *bridgeServerRecord) { n.LastHeartbeatAt = now.Add(-95 * time.Second) },
		"future heartbeat": func(n *bridgeServerRecord) { n.LastHeartbeatAt = now.Add(2 * time.Minute) },
		"old telemetry":    func(n *bridgeServerRecord) { n.Telemetry.SampledAtUnixMillis = now.Add(-95 * time.Second).UnixMilli() },
		"future telemetry": func(n *bridgeServerRecord) { n.Telemetry.SampledAtUnixMillis = now.Add(2 * time.Minute).UnixMilli() },
		"replaced runtime": func(n *bridgeServerRecord) { n.RuntimeEpoch++ },
		"different pid":    func(n *bridgeServerRecord) { n.RuntimeProcessID++ },
		"inactive":         func(n *bridgeServerRecord) { n.Status = "disabled" },
	}
	for name, change := range scenarios {
		t.Run(name, func(t *testing.T) {
			copyNode := node
			copyTelemetry := *node.Telemetry
			copyNode.Telemetry = &copyTelemetry
			change(&copyNode)
			if value, status := bridgeCurrentTelemetry0419(copyNode, now); status != "stale" || value != nil {
				t.Fatalf("%s: %s %+v", name, status, value)
			}
		})
	}
	node.Telemetry = nil
	if value, status := bridgeCurrentTelemetry0419(node, now); status != "unknown" || value != nil {
		t.Fatal(status)
	}
}

func TestTelemetryProcessHostFields0419(t *testing.T) {
	now := time.Now().UTC()
	rid := strings.Repeat("b", 64)
	pid := int64(42)
	raw := testTelemetry0193(now, rid)
	raw.ProcessID = &pid
	cpu := int64(4000000)
	load := 0.4
	total := int64(16 << 30)
	free := int64(6 << 30)
	raw.ProcessCPUTimeNanos = &cpu
	raw.ProcessCPULoad = &load
	raw.HostTotalMemoryBytes = &total
	raw.HostFreeMemoryBytes = &free
	runtime := model.ServerBridgeRuntimeIdentity{RuntimeID: rid, ProcessID: pid}
	got, err := validateBridgeTelemetry0193(raw, runtime, 3, now)
	if err != nil || got.ProcessID == nil || *got.ProcessID != pid || got.HostFreeMemoryBytes == nil {
		t.Fatalf("unexpected telemetry %v: %+v", err, got)
	}
	wrong := pid + 1
	raw.ProcessID = &wrong
	if _, err := validateBridgeTelemetry0193(raw, runtime, 3, now); err == nil {
		t.Fatal("accepted different physical JVM")
	}
	raw.ProcessID = &pid
	free = total + 1
	if _, err := validateBridgeTelemetry0193(raw, runtime, 3, now); err == nil {
		t.Fatal("accepted impossible host memory")
	}
	free = 6 << 30
	raw.ProcessID = nil
	if _, err := validateBridgeTelemetry0193(raw, runtime, 3, now); err == nil {
		t.Fatal("accepted CPU counters without process identity")
	}
	raw.ProcessID = &pid
	load = 1.5
	if _, err := validateBridgeTelemetry0193(raw, runtime, 3, now); err == nil {
		t.Fatal("accepted invalid cpu load")
	}
}

func TestTelemetryMissingPlatformSample0419(t *testing.T) {
	now := time.Now().UTC()
	rid := strings.Repeat("c", 64)
	runtime := model.ServerBridgeRuntimeIdentity{RuntimeID: rid}
	raw := testTelemetry0193(now, rid)
	raw.PlayersOnline = nil
	raw.PlayersMax = nil
	raw.TPS = nil
	raw.MSPT = nil
	raw.TickHealth = "unavailable"
	value, err := validateBridgeTelemetry0193(raw, runtime, 2, now)
	if err != nil || value.PlayersOnline != nil || value.PlayersMax != nil {
		t.Fatalf("missing platform values must remain unknown, got %+v err %v", value, err)
	}
	raw.TickHealth = "healthy"
	if _, err := validateBridgeTelemetry0193(raw, runtime, 2, now); err == nil {
		t.Fatal("missing ticks claimed healthy")
	}
	raw.TickHealth = "unavailable"
	online := 4
	raw.PlayersOnline = &online
	if _, err := validateBridgeTelemetry0193(raw, runtime, 2, now); err == nil {
		t.Fatal("partial player metric pair accepted")
	}
}
