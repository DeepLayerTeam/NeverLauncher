package model

import "time"

// ExtensionRegistryPublisher является идентичность разрешён к публикация подписанный.nlext
// пакеты в private/local NeverExtensions реестр.
type ExtensionRegistryPublisher struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ExtensionRegistryPublisherKey является доверенный Ed25519 открытый ключ. Отпечаток
// является глобально уникальный так артефакт может unambiguously привязывать к один издатель.
type ExtensionRegistryPublisherKey struct {
	PublisherID     string     `json:"publisherId"`
	Fingerprint     string     `json:"fingerprint"`
	Algorithm       string     `json:"algorithm"`
	PublicKeyBase64 string     `json:"publicKeyBase64,omitempty"`
	Active          bool       `json:"active"`
	CreatedAt       time.Time  `json:"createdAt"`
	RevokedAt       *time.Time `json:"revokedAt,omitempty"`
}

// ExtensionRegistryCompatibility является неизменяемый метаданные подключение к один
// опубликованный версия. Пустой OS/architecture список mean платформа-независимый.
type ExtensionRegistryCompatibility struct {
	MinNeverLauncher       string   `json:"minNeverLauncher,omitempty"`
	MaxNeverLauncher       string   `json:"maxNeverLauncher,omitempty"`
	MinAPI                 string   `json:"minApi,omitempty"`
	MaxAPI                 string   `json:"maxApi,omitempty"`
	SupportedOS            []string `json:"supportedOs,omitempty"`
	SupportedArchitectures []string `json:"supportedArchitectures,omitempty"`
}

// ExtensionRegistryArtifact точки в неизменяемый байты в настраивать хранилище.
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

// ExtensionRegistryVersion является полный реестр view один публикация.
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

// ExtensionRegistryPublication является сохранённый только после.nlext байты имеют
// пройден пакет-целостность и доверенный Ed25519 проверка.
type ExtensionRegistryPublication struct {
	Manifest      ExtensionManifest
	PublisherID   string
	Compatibility ExtensionRegistryCompatibility
	Artifact      ExtensionRegistryArtifact
	Channels      []string
}

// ExtensionRegistrySearch описывает на стороне сервера реестр filtering.
type ExtensionRegistrySearch struct {
	Query           string
	Channel         string
	LauncherVersion string
	OS              string
	Architecture    string
	IncludeYanked   bool
}

// ExtensionRegistryExtension является возвращён через detail API.
type ExtensionRegistryExtension struct {
	Extension Extension                  `json:"extension"`
	Versions  []ExtensionRegistryVersion `json:"versions"`
}
