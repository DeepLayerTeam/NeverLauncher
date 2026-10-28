package model

import (
	"encoding/json"
	"time"
)

// StagedRuntimeRun0342 stores observational execution telemetry. In 0.34.2 it
// deliberately does not confer release certification or stable eligibility.
type StagedRuntimeRun0342 struct {
	RunID          string          `json:"runId"`
	PackageID      string          `json:"packageId"`
	ProjectID      string          `json:"projectId"`
	ManifestSHA256 string          `json:"manifestSha256"`
	ArtifactSHA256 string          `json:"artifactSha256"`
	Stages         json.RawMessage `json:"stages"`
	StartedAt      time.Time       `json:"startedAt"`
	FinishedAt     time.Time       `json:"finishedAt"`
	ReceivedAt     time.Time       `json:"receivedAt"`
}
