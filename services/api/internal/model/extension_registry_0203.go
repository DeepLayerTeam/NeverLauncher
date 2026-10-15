package model

import "time"

// ExtensionRegistryPublisher — идентичность, которой разрешено публиковать
// подписанные .nlext в закрытый/локальный реестр NeverExtensions.
type ExtensionRegistryPublisher struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ExtensionRegistryPublisherKey — доверенный открытый ключ Ed25519. Fingerprint
// уникален глобально, чтобы артефакт однозначно связывался с одним издателем.
type ExtensionRegistryPublisherKey struct {
	PublisherID     string     `json:"publisherId"`
	Fingerprint     string     `json:"fingerprint"`
	Algorithm       string     `json:"algorithm"`
	PublicKeyBase64 string     `json:"publicKeyBase64,omitempty"`
	Active          bool       `json:"active"`
	CreatedAt       time.Time  `json:"createdAt"`
	RevokedAt       *time.Time `json:"revokedAt,omitempty"`
}

// ExtensionRegistryCompatibility — неизменяемые метаданные одной опубликованной
// версии. Пустые списки ОС или архитектур означают независимость от платформы.
type ExtensionRegistryCompatibility struct {
	MinNeverLauncher       string   `json:"minNeverLauncher,omitempty"`
	MaxNeverLauncher       string   `json:"maxNeverLauncher,omitempty"`
	MinAPI                 string   `json:"minApi,omitempty"`
	MaxAPI                 string   `json:"maxApi,omitempty"`
	SupportedOS            []string `json:"supportedOs,omitempty"`
	SupportedArchitectures []string `json:"supportedArchitectures,omitempty"`
}

// ExtensionRegistryArtifact указывает на неизменяемые байты в настроенном хранилище.
type ExtensionRegistryArtifact struct {
	PackageIdentity         string    `json:"packageIdentity"`
	ExtensionID             string    `json:"extensionId"`
	Version                 string    `json:"version"`
	SHA256                  string    `json:"sha256"`
	Size                    int64     `json:"size"`
	StorageProject          string    `json:"storageProject,omitempty"`
	StorageVersion          string    `json:"storageVersion,omitempty"`
	StoragePath             string    `json:"storagePath,omitempty"`
	SignatureKeyFingerprint string    `json:"signatureKeyFingerprint"`
	CreatedAt               time.Time `json:"createdAt"`
}

// ExtensionRegistryVersion — полное представление одной публикации в реестре.
type ExtensionRegistryVersion struct {
	ExtensionID   string                         `json:"extensionId"`
	Version       string                         `json:"version"`
	PublisherID   string                         `json:"publisherId"`
	Manifest      ExtensionManifest              `json:"manifest"`
	Compatibility ExtensionRegistryCompatibility `json:"compatibility"`
	Artifact      ExtensionRegistryArtifact      `json:"artifact"`
	Channels      []string                       `json:"channels"`
	PublishedAt   time.Time                      `json:"publishedAt"`
	YankedAt      *time.Time                     `json:"yankedAt,omitempty"`
	YankReason    string                         `json:"yankReason,omitempty"`
}

// ExtensionRegistryPublication сохраняется только после
// проверки целостности .nlext и доверенной подписи Ed25519.
type ExtensionRegistryPublication struct {
	Manifest      ExtensionManifest
	PublisherID   string
	Compatibility ExtensionRegistryCompatibility
	Artifact      ExtensionRegistryArtifact
	Channels      []string
}

// ExtensionRegistrySearch описывает фильтрацию реестра на стороне сервера.
type ExtensionRegistrySearch struct {
	Query           string
	Channel         string
	LauncherVersion string
	OS              string
	Architecture    string
	IncludeYanked   bool
}

// ExtensionRegistryExtension возвращается API деталей расширения.
type ExtensionRegistryExtension struct {
	Extension Extension                  `json:"extension"`
	Versions  []ExtensionRegistryVersion `json:"versions"`
}
