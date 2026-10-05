package model

import "time"

// ExtensionTarget is one executable/UI target declared by a canonical
// neverlauncher-extension.json manifest.
type ExtensionTarget struct {
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
}

// ExtensionDependency declares another extension required by a concrete
// immutable extension version.
type ExtensionDependency struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Optional bool   `json:"optional,omitempty"`
}

// ExtensionManifest is the canonical NeverExtensions manifest introduced in
// NeverLauncher 0.20.1. It replaces newly-authored neverlauncher-plugin.json
// manifests while the CLI can still import the legacy format.
type ExtensionManifest struct {
	SchemaVersion string                `json:"schemaVersion"`
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Version       string                `json:"version"`
	Publisher     string                `json:"publisher"`
	Description   string                `json:"description,omitempty"`
	Homepage      string                `json:"homepage,omitempty"`
	Repository    string                `json:"repository,omitempty"`
	API           string                `json:"api"`
	Targets       []ExtensionTarget     `json:"targets"`
	Permissions   []string              `json:"permissions,omitempty"`
	Hooks         []string              `json:"hooks,omitempty"`
	Dependencies  []ExtensionDependency `json:"dependencies,omitempty"`
	Metadata      map[string]string     `json:"metadata,omitempty"`
}

// Extension is the stable identity shared by all immutable versions.
type Extension struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Publisher   string    `json:"publisher"`
	Description string    `json:"description,omitempty"`
	Homepage    string    `json:"homepage,omitempty"`
	Repository  string    `json:"repository,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ExtensionVersion stores one immutable canonical manifest. ManifestSHA256 is
// computed from deterministic canonical JSON before persistence.
type ExtensionVersion struct {
	ExtensionID    string            `json:"extensionId"`
	Version        string            `json:"version"`
	SchemaVersion  string            `json:"schemaVersion"`
	API            string            `json:"api"`
	Manifest       ExtensionManifest `json:"manifest"`
	ManifestSHA256 string            `json:"manifestSha256"`
	CreatedAt      time.Time         `json:"createdAt"`
}

// ExtensionInstall is persisted desired installation state. 0.20.1 does not
// start extension processes; later lifecycle releases consume this state.
type ExtensionInstall struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Version     string    `json:"version"`
	Enabled     bool      `json:"enabled"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installedAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
