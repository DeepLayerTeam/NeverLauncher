package model

import "time"

const (
	ExtensionInstallStateAbsent   = "absent"
	ExtensionInstallStateDisabled = "disabled"
	ExtensionInstallStateEnabled  = "enabled"
	ExtensionInstallStateError    = "error"
)

// ExtensionLifecycleTransition is the single atomic persistence operation used
// after a staged filesystem activation has succeeded. ExpectedGeneration makes
// concurrent lifecycle mutations fail rather than overwrite each other.
type ExtensionLifecycleTransition struct {
	ExtensionID             string
	Scope                   string
	ScopeID                 string
	DesiredVersion          string
	CurrentVersion          string
	DesiredState            string
	CurrentState            string
	PackageIdentity         string
	CurrentPackageIdentity  string
	PreviousVersion         string
	PreviousPackageIdentity string
	Enabled                 bool
	Source                  string
	LastError               string
	Operation               string
	BackupPath              string
	ExpectedGeneration      int64
	ActivatedAt             *time.Time
}

// ExtensionInstallRevision is an append-only successful lifecycle transition.
// BackupPath points at the previous activated payload when the operation moved
// or removed it, making rollback deterministic and auditable.
type ExtensionInstallRevision struct {
	ID                  int64     `json:"id"`
	ExtensionID         string    `json:"extensionId"`
	Scope               string    `json:"scope"`
	ScopeID             string    `json:"scopeId,omitempty"`
	Generation          int64     `json:"generation"`
	Operation           string    `json:"operation"`
	FromVersion         string    `json:"fromVersion,omitempty"`
	ToVersion           string    `json:"toVersion,omitempty"`
	FromState           string    `json:"fromState"`
	ToState             string    `json:"toState"`
	FromPackageIdentity string    `json:"fromPackageIdentity,omitempty"`
	ToPackageIdentity   string    `json:"toPackageIdentity,omitempty"`
	BackupPath          string    `json:"backupPath,omitempty"`
	Source              string    `json:"source"`
	CreatedAt           time.Time `json:"createdAt"`
}
