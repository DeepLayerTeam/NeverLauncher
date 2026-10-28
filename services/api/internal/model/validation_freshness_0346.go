package model

import "time"

// ValidationChallenge0346 is a one-use, backend-issued authorization to attest
// one immutable staged snapshot under one explicitly configured target matrix.
type ValidationChallenge0346 struct {
	RunID              string    `json:"runId"`
	Nonce              string    `json:"nonce"`
	PackageID          string    `json:"packageId"`
	ProjectID          string    `json:"projectId"`
	ManifestSHA256     string    `json:"manifestSha256"`
	ArtifactSHA256     string    `json:"artifactSha256"`
	TargetMatrixSHA256 string    `json:"targetMatrixSha256"`
	IssuedAt           time.Time `json:"issuedAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
}
