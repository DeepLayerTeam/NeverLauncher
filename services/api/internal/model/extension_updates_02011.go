package model

import "time"

// ExtensionUpdatePin freezes one extension to an exact immutable registry version
// within a global/project install scope. Resolver decisions are fail-closed when a
// pin cannot satisfy dependency or compatibility requirements.
type ExtensionUpdatePin struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ExtensionUpdateRoot is an explicit root requested by an operator. Empty
// Version means "best version in Channel"; empty Channel resolves to stable.
type ExtensionUpdateRoot struct {
	ExtensionID string `json:"extensionId"`
	Version     string `json:"version,omitempty"`
	Channel     string `json:"channel,omitempty"`
}

// ExtensionUpdatePlanItem is one final graph node. Dependencies are ordered
// before dependants in ExtensionUpdatePlan.Items.
type ExtensionUpdatePlanItem struct {
	ExtensionID     string   `json:"extensionId"`
	FromVersion     string   `json:"fromVersion,omitempty"`
	ToVersion       string   `json:"toVersion"`
	PackageIdentity string   `json:"packageIdentity"`
	Operation       string   `json:"operation"` // install, update, unchanged
	Channel         string   `json:"channel"`
	RequiredBy      []string `json:"requiredBy,omitempty"`
	Optional        bool     `json:"optional,omitempty"`
	Pinned          bool     `json:"pinned,omitempty"`
}

// ExtensionUpdatePlan is a fully resolved immutable candidate graph.
type ExtensionUpdatePlan struct {
	Scope           string                    `json:"scope"`
	ScopeID         string                    `json:"scopeId,omitempty"`
	LauncherVersion string                    `json:"launcherVersion"`
	APIVersion      string                    `json:"apiVersion"`
	OS              string                    `json:"os"`
	Architecture    string                    `json:"architecture"`
	DefaultChannel  string                    `json:"defaultChannel"`
	Items           []ExtensionUpdatePlanItem `json:"items"`
	ResolvedAt      time.Time                 `json:"resolvedAt"`
}

// ExtensionUpdateTransaction records a compensation-backed multi-extension
// update. State is persisted so an interrupted operator workflow is observable.
type ExtensionUpdateTransaction struct {
	ID         string              `json:"id"`
	Scope      string              `json:"scope"`
	ScopeID    string              `json:"scopeId,omitempty"`
	Status     string              `json:"status"` // running,succeeded,rolled_back,rollback_failed,failed
	Plan       ExtensionUpdatePlan `json:"plan"`
	Applied    []string            `json:"applied,omitempty"`
	InFlight   string              `json:"inFlight,omitempty"`
	RolledBack []string            `json:"rolledBack,omitempty"`
	Failure    string              `json:"failure,omitempty"`
	StartedAt  time.Time           `json:"startedAt"`
	FinishedAt *time.Time          `json:"finishedAt,omitempty"`
	LeaseOwner string              `json:"leaseOwner,omitempty"`
}
