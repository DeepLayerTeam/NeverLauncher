package model

import "time"

// IntegrityCheckResult фиксирует серверную проверку точных байтов пакета,
// сохранённых для релиза. Намеренно не является доказательством выполнения.
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

// RuntimeValidationResult принимается только после проверки подписанных
// свидетельств выполнения и привязан к точному хешу пакета и манифеста.
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

// TrustAssessment — каноническое представление доверия. Assurance остаётся
// устаревшим полем совместимости TrustedDevice и не должно смешивать эти аспекты.
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

// ProjectValidationPolicy задаёт минимальные доказательства, необходимые для публикации.
type ProjectValidationPolicy struct {
	ProjectID         string    `json:"projectId"`
	RequiredLevel     string    `json:"requiredLevel"`
	RequireServerJoin bool      `json:"requireServerJoin"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
