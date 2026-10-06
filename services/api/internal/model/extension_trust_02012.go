package model

import "time"

const (
	ExtensionTrustModeStrict = "strict"
	ExtensionTrustModeAudit  = "audit"
)

// ExtensionTrustPolicy is the registry-wide publisher trust policy. Strict mode
// fails closed; audit mode records policy violations but still requires a valid
// package signature and a non-revoked registered key.
type ExtensionTrustPolicy struct {
	Mode              string    `json:"mode"`
	AllowedPublishers []string  `json:"allowedPublishers,omitempty"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// ExtensionQuarantineEntry records an artifact that must not be published,
// installed, updated or started until an administrator explicitly releases it.
type ExtensionQuarantineEntry struct {
	ID              string     `json:"id"`
	PackageIdentity string     `json:"packageIdentity"`
	ArtifactSHA256  string     `json:"artifactSha256"`
	ExtensionID     string     `json:"extensionId,omitempty"`
	Version         string     `json:"version,omitempty"`
	PublisherID     string     `json:"publisherId,omitempty"`
	KeyFingerprint  string     `json:"keyFingerprint,omitempty"`
	Reason          string     `json:"reason"`
	StorageProject  string     `json:"storageProject,omitempty"`
	StorageVersion  string     `json:"storageVersion,omitempty"`
	StoragePath     string     `json:"storagePath,omitempty"`
	Active          bool       `json:"active"`
	CreatedAt       time.Time  `json:"createdAt"`
	ReleasedAt      *time.Time `json:"releasedAt,omitempty"`
	ReleasedBy      string     `json:"releasedBy,omitempty"`
}

// ExtensionEmergencyDisable is a persistent kill-switch. It survives Backend
// restarts and is checked before an extension can be enabled or started.
type ExtensionEmergencyDisable struct {
	ExtensionID string     `json:"extensionId"`
	Scope       string     `json:"scope"`
	ScopeID     string     `json:"scopeId,omitempty"`
	Reason      string     `json:"reason"`
	Source      string     `json:"source"`
	CreatedAt   time.Time  `json:"createdAt"`
	ClearedAt   *time.Time `json:"clearedAt,omitempty"`
	ClearedBy   string     `json:"clearedBy,omitempty"`
}

// ExtensionRecoveryExport is portable JSON state. Private signing keys and
// extension secret plaintext are deliberately excluded.
type ExtensionRecoveryExport struct {
	SchemaVersion     string                          `json:"schemaVersion"`
	GeneratedAt       time.Time                       `json:"generatedAt"`
	TrustPolicy       ExtensionTrustPolicy            `json:"trustPolicy"`
	Publishers        []ExtensionRegistryPublisher    `json:"publishers"`
	PublisherKeys     []ExtensionRegistryPublisherKey `json:"publisherKeys"`
	EmergencyDisables []ExtensionEmergencyDisable     `json:"emergencyDisables"`
	Quarantine        []ExtensionQuarantineEntry      `json:"quarantine"`
	Installs          []ExtensionInstall              `json:"installs"`
	Pins              []ExtensionUpdatePin            `json:"pins"`
}
