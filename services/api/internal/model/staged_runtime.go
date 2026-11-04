package model

import (
	"encoding/json"
	"time"
)

// StagedRuntimeRun0342 хранит наблюдательную телеметрию исполнения. В версии
// 0.34.2 она намеренно не даёт сертификацию релиза или допуск stable.
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

// ValidationAttestation0345 — неизменяемый результат независимого доверенного
// аттестатора исполнения; это НЕ сертификация stable до V05/V11 GA.
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
