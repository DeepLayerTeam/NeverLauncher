package model

import "time"

// ExtensionTarget is one executable/UI target declared by a canonical
// neverlauncher-extension.json manifest.
type ExtensionTarget struct {
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
}

// ExtensionAdminPage declares a sandboxed Admin page rendered by the host.
type ExtensionAdminPage struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// ExtensionAdminNavigation contributes one sidebar entry backed by an Admin page.
type ExtensionAdminNavigation struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}

// ExtensionAdminWidget contributes a dashboard iframe backed by an Admin page.
type ExtensionAdminWidget struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	PageID string `json:"pageId"`
	Height int    `json:"height,omitempty"`
}

// ExtensionAdminAction contributes a toolbar action that activates a page and
// delivers the action ID over the typed Admin bridge.
type ExtensionAdminAction struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}

// ExtensionAdminContributions are declarative slot bindings. The executable UI
// stays inside the sandboxed admin target iframe; these values never inject JS
// into the NeverLauncher Admin bundle.
type ExtensionAdminContributions struct {
	Pages            []ExtensionAdminPage       `json:"pages,omitempty"`
	Navigation       []ExtensionAdminNavigation `json:"navigation,omitempty"`
	DashboardWidgets []ExtensionAdminWidget     `json:"dashboardWidgets,omitempty"`
	Actions          []ExtensionAdminAction     `json:"actions,omitempty"`
}

// ExtensionDesktopPage declares one sandboxed Desktop page.
type ExtensionDesktopPage struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// ExtensionDesktopNavigation contributes a Desktop sidebar entry.
type ExtensionDesktopNavigation struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}

// ExtensionDesktopAction contributes an action delivered to the sandboxed page.
type ExtensionDesktopAction struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}

// ExtensionDesktopContributions bind an isolated Desktop target to launcher slots.
type ExtensionDesktopContributions struct {
	Pages      []ExtensionDesktopPage       `json:"pages,omitempty"`
	Navigation []ExtensionDesktopNavigation `json:"navigation,omitempty"`
	Actions    []ExtensionDesktopAction     `json:"actions,omitempty"`
}

// ExtensionCLICommand is one namespaced command exposed by a CLI target.
type ExtensionCLICommand struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Usage       string `json:"usage,omitempty"`
}

// ExtensionCLIContributions describe the namespace that nl resolves before
// starting the isolated CLI target through the Extension Host Protocol.
type ExtensionCLIContributions struct {
	Namespace string                `json:"namespace"`
	Commands  []ExtensionCLICommand `json:"commands"`
}

// ExtensionDependency declares another extension required by a concrete
// immutable extension version.
type ExtensionDependency struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Optional bool   `json:"optional,omitempty"`
}

// ExtensionConflict declares an incompatible extension/version range.
// Version uses the NeverExtensions SemVer range grammar introduced in 0.20.11.
type ExtensionConflict struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ExtensionManifest is the canonical NeverExtensions manifest introduced in
// NeverLauncher 0.20.1. It replaces newly-authored neverlauncher-plugin.json
// manifests while the CLI can still import the legacy format.
type ExtensionManifest struct {
	SchemaVersion string                         `json:"schemaVersion"`
	ID            string                         `json:"id"`
	Name          string                         `json:"name"`
	Version       string                         `json:"version"`
	Publisher     string                         `json:"publisher"`
	Description   string                         `json:"description,omitempty"`
	Homepage      string                         `json:"homepage,omitempty"`
	Repository    string                         `json:"repository,omitempty"`
	API           string                         `json:"api"`
	Targets       []ExtensionTarget              `json:"targets"`
	Permissions   []string                       `json:"permissions,omitempty"`
	Hooks         []string                       `json:"hooks,omitempty"`
	Dependencies  []ExtensionDependency          `json:"dependencies,omitempty"`
	Conflicts     []ExtensionConflict            `json:"conflicts,omitempty"`
	Metadata      map[string]string              `json:"metadata,omitempty"`
	Admin         *ExtensionAdminContributions   `json:"admin,omitempty"`
	Desktop       *ExtensionDesktopContributions `json:"desktop,omitempty"`
	CLI           *ExtensionCLIContributions     `json:"cli,omitempty"`
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

// ExtensionInstall is the persisted desired/current lifecycle state. The 0.20.4
// lifecycle manager owns transitions; the 0.20.5 Extension Host consumes enabled state.
type ExtensionInstall struct {
	ExtensionID string `json:"extensionId"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId,omitempty"`
	// Version is retained as the 0.20.1 compatibility alias for DesiredVersion.
	Version                 string     `json:"version"`
	DesiredVersion          string     `json:"desiredVersion"`
	CurrentVersion          string     `json:"currentVersion,omitempty"`
	DesiredState            string     `json:"desiredState"`
	CurrentState            string     `json:"currentState"`
	Enabled                 bool       `json:"enabled"`
	PackageIdentity         string     `json:"packageIdentity,omitempty"`
	CurrentPackageIdentity  string     `json:"currentPackageIdentity,omitempty"`
	PreviousVersion         string     `json:"previousVersion,omitempty"`
	PreviousPackageIdentity string     `json:"previousPackageIdentity,omitempty"`
	Generation              int64      `json:"generation"`
	Source                  string     `json:"source"`
	LastError               string     `json:"lastError,omitempty"`
	InstalledAt             time.Time  `json:"installedAt"`
	UpdatedAt               time.Time  `json:"updatedAt"`
	ActivatedAt             *time.Time `json:"activatedAt,omitempty"`
}
