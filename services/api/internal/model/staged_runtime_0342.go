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

// ValidationAttestation0345 is an immutable result issued by an independent
// trusted execution attestor; it is NOT stable certification until V05/V11 GA.
type ValidationAttestation0345 struct {
	RunID          string          `json:"runId"`
	PackageID      string          `json:"packageId"`
	ProjectID      string          `json:"projectId"`
	ManifestSHA256 string          `json:"manifestSha256"`
	ArtifactSHA256 string          `json:"artifactSha256"`
	Evidence       json.RawMessage `json:"evidence"`
	Signature      string          `json:"signature"`
	ReceivedAt     time.Time       `json:"receivedAt"`
}
