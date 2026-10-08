package model

import "time"

// IntegrityCheckResult записывает на стороне сервера проверка конкретный пакет
// байты сейчас сохранённый для релиз. Это является намеренно не среда выполнения доказательство.
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

// RuntimeValidationResult является принят только после проверка подписанный среда выполнения
// свидетельство и является привязанный к точный package/manifest хеш.
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

// TrustAssessment является канонический доверие view. Уверенность остаётся устаревший
// совместимость field на TrustedDevice и должен не collapse эти dimensions.
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

// ProjectValidationPolicy средства управления minimum свидетельство обязательный к публикация.
type ProjectValidationPolicy struct {
	ProjectID         string    `json:"projectId"`
	RequiredLevel     string    `json:"requiredLevel"`
	RequireServerJoin bool      `json:"requireServerJoin"`
	UpdatedAt         time.Time `json:"updatedAt"`
}
