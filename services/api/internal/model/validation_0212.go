package model

import "time"

// IntegrityCheckResult records a server-side verification of the exact package
// bytes currently stored for a release. It is intentionally not runtime proof.
type IntegrityCheckResult struct {
	ID                    string           `json:"id"`
	PackageID             string           `json:"packageId"`
	ProjectID             string           `json:"projectId"`
	ManifestDigest        string           `json:"manifestDigest"`
	ArtifactDigest        string           `json:"artifactDigest"`
	SignatureVerified     bool             `json:"signatureVerified"`
	StorageVerified       bool             `json:"storageVerified"`
	FilesVerified         bool             `json:"filesVerified"`
	CompatibilityVerified bool             `json:"compatibilityMetadataVerified"`
	Result                string           `json:"result"`
	Checks                []map[string]any `json:"checks,omitempty"`
	CheckedAt             time.Time        `json:"checkedAt"`
}

// RuntimeValidationResult is accepted only after verification of signed runtime
// evidence and is bound to an exact package/manifest digest.
type RuntimeValidationResult struct {
	ID                   string            `json:"id"`
	PackageID            string            `json:"packageId"`
	ProjectID            string            `json:"projectId"`
	ManifestDigest       string            `json:"manifestDigest"`
	TargetID             string            `json:"targetId"`
	MinecraftVersion     string            `json:"minecraftVersion"`
	Loader               string            `json:"loader"`
	OS                   string            `json:"os"`
	Arch                 string            `json:"arch"`
	Java                 string            `json:"java"`
	ActualClient         bool              `json:"actualClient"`
	ExitCode             int               `json:"exitCode"`
	ServerJoin           bool              `json:"serverJoin"`
	RunID                string            `json:"runId"`
	Commit               string            `json:"commit"`
	EvidenceHashes       map[string]string `json:"evidenceHashes,omitempty"`
	SignerKeyID          string            `json:"signerKeyId"`
	SignerKeyFingerprint string            `json:"signerKeyFingerprint"`
	EvidenceDigest       string            `json:"evidenceDigest"`
	StartedAt            time.Time         `json:"startedAt"`
	FinishedAt           time.Time         `json:"finishedAt"`
	Result               string            `json:"result"`
	CreatedAt            time.Time         `json:"createdAt"`
}

// TrustAssessment is the canonical trust view. Assurance remains a legacy
// compatibility field on TrustedDevice and must not collapse these dimensions.
type TrustAssessment struct {
	KeyPossession            string    `json:"keyPossession"`
	LocalHardwareBinding     string    `json:"localHardwareBinding"`
	RemoteHardwareProvenance string    `json:"remoteHardwareProvenance"`
	ArtifactIntegrity        string    `json:"artifactIntegrity"`
	RuntimeEvidence          string    `json:"runtimeEvidence"`
	PolicyDecision           string    `json:"policyDecision"`
	ReasonCodes              []string  `json:"reasonCodes,omitempty"`
	AssessedAt               time.Time `json:"assessedAt"`
	EvidenceExpiresAt        time.Time `json:"evidenceExpiresAt,omitempty"`
}

// ProjectValidationPolicy controls the minimum evidence required to publish.
type ProjectValidationPolicy struct {
	ProjectID         string    `json:"projectId"`
	RequiredLevel     string    `json:"requiredLevel"`
	RequireServerJoin bool      `json:"requireServerJoin"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
