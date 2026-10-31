package httpapi

import (
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// bridgeCurrentTelemetry0419 is the fail-closed view of the persisted history.
// Historical samples remain in PostgreSQL; this is ONLY for live dashboards.
// A heartbeat alone does not establish that a telemetry sample is healthy.
func bridgeCurrentTelemetry0419(node bridgeServerRecord, now time.Time) (*model.ServerBridgeTelemetry, string) {
	if node.Telemetry == nil {
		return nil, "unknown"
	}
	sample := node.Telemetry
	sampledAt := time.UnixMilli(sample.SampledAtUnixMillis)
	if node.Status != "active" || node.RuntimeEpoch <= 0 || node.RuntimeID == "" ||
		sample.RuntimeEpoch != node.RuntimeEpoch || !strings.EqualFold(sample.RuntimeID, node.RuntimeID) ||
		node.LastHeartbeatAt.IsZero() || node.LastHeartbeatAt.After(now.Add(30*time.Second)) ||
		now.Sub(node.LastHeartbeatAt) >= 90*time.Second ||
		sampledAt.After(now.Add(30*time.Second)) || now.Sub(sampledAt) >= 90*time.Second ||
		sampledAt.After(node.LastHeartbeatAt.Add(30*time.Second)) ||
		(sample.ProcessID != nil && (node.RuntimeProcessID <= 0 || *sample.ProcessID != node.RuntimeProcessID)) {
		return nil, "stale"
	}
	copyValue := *sample
	return &copyValue, "fresh"
}
