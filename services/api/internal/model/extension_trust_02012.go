package model

import "time"

const (
	ExtensionTrustModeStrict = "strict"
	ExtensionTrustModeAudit  = "audit"
)

// ExtensionTrustPolicy является реестр-wide издатель доверие политика. Строгий режим
// завершается ошибкой закрытый; аудит режим записывает политика нарушение но по-прежнему требует действительный
// пакет подпись и non-отозванный регистрировать ключ.
type ExtensionTrustPolicy struct {
	Mode              string    `json:"mode"`
	AllowedPublishers []string  `json:"allowedPublishers,omitempty"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// ExtensionQuarantineEntry записывает артефакт тот должен не быть опубликованный,
// установленный, обновлён или запущен до администратор явно релизы это.
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

// ExtensionEmergencyDisable является постоянный kill-переключение. Это переживает Серверная часть
// перезапуски и является проверен до расширение может быть включённый или запущен.
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

// ExtensionRecoveryExport является переносимый JSON состояние. Закрытый ключи подписи и
// расширение секрет открытый текст являются намеренно excluded.
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
