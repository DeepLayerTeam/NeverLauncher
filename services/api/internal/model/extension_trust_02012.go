package model

import "time"

const (
	ExtensionTrustModeStrict = "strict"
	ExtensionTrustModeAudit  = "audit"
)

// ExtensionTrustPolicy — общая политика доверия к издателям реестра.
// Строгий режим запрещает нарушения; режим аудита их записывает, но также
// требует правильную подпись и неотозванный зарегистрированный ключ.
type ExtensionTrustPolicy struct {
	Mode              string    `json:"mode"`
	AllowedPublishers []string  `json:"allowedPublishers,omitempty"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// ExtensionQuarantineEntry отмечает артефакт, который нельзя публиковать,
// устанавливать, обновлять или запускать до явного разрешения администратора.
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

// ExtensionEmergencyDisable — постоянный аварийный выключатель. Переживает
// перезапуски бэкенда и проверяется перед включением или запуском расширения.
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

// ExtensionRecoveryExport — переносимое состояние JSON. Закрытые
// ключи подписи и открытые секреты расширений специально исключены.
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
