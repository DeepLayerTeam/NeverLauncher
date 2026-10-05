package model

import "time"

// ExtensionRegistryPublisher is an identity allowed to publish signed .nlext
// packages into the private/local NeverExtensions registry.
type ExtensionRegistryPublisher struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ExtensionRegistryPublisherKey is a trusted Ed25519 public key. Fingerprint
// is globally unique so an artifact can unambiguously bind to one publisher.
type ExtensionRegistryPublisherKey struct {
	PublisherID     string     `json:"publisherId"`
	Fingerprint     string     `json:"fingerprint"`
	Algorithm       string     `json:"algorithm"`
	PublicKeyBase64 string     `json:"publicKeyBase64,omitempty"`
	Active          bool       `json:"active"`
	CreatedAt       time.Time  `json:"createdAt"`
	RevokedAt       *time.Time `json:"revokedAt,omitempty"`
}

// ExtensionRegistryCompatibility is immutable metadata attached to one
// published version. Empty OS/architecture lists mean platform-independent.
type ExtensionRegistryCompatibility struct {
	MinNeverLauncher       string   `json:"minNeverLauncher,omitempty"`
	MaxNeverLauncher       string   `json:"maxNeverLauncher,omitempty"`
	SupportedOS            []string `json:"supportedOs,omitempty"`
	SupportedArchitectures []string `json:"supportedArchitectures,omitempty"`
}

// ExtensionRegistryArtifact points at immutable bytes in configured storage.
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

// ExtensionRegistryVersion is the complete registry view of one publication.
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

// ExtensionRegistryPublication is persisted only after the .nlext bytes have
// passed package-integrity and trusted Ed25519 verification.
type ExtensionRegistryPublication struct {
	Manifest      ExtensionManifest
	PublisherID   string
	Compatibility ExtensionRegistryCompatibility
	Artifact      ExtensionRegistryArtifact
	Channels      []string
}

// ExtensionRegistrySearch describes server-side registry filtering.
type ExtensionRegistrySearch struct {
	Query           string
	Channel         string
	LauncherVersion string
	OS              string
	Architecture    string
	IncludeYanked   bool
}

// ExtensionRegistryExtension is returned by the detail API.
type ExtensionRegistryExtension struct {
	Extension Extension                  `json:"extension"`
	Versions  []ExtensionRegistryVersion `json:"versions"`
}
