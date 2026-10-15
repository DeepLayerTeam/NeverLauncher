package model

import "time"

// ExtensionUpdatePin закрепляет расширение на одной неизменяемой версии
// реестра в глобальной или проектной области. Если закрепление несовместимо
// с зависимостями или требованиями, разрешение завершается отказом.
type ExtensionUpdatePin struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ExtensionUpdateRoot — явное корневое расширение, указанное оператором.
// Пустое Version означает лучшую версию в Channel; пустой Channel — stable.
type ExtensionUpdateRoot struct {
	ExtensionID string `json:"extensionId"`
	Version     string `json:"version,omitempty"`
	Channel     string `json:"channel,omitempty"`
}

// ExtensionUpdatePlanItem — узел окончательного графа. В
// ExtensionUpdatePlan.Items зависимости идут раньше зависимых.
type ExtensionUpdatePlanItem struct {
	ExtensionID     string   `json:"extensionId"`
	FromVersion     string   `json:"fromVersion,omitempty"`
	ToVersion       string   `json:"toVersion"`
	PackageIdentity string   `json:"packageIdentity"`
	Operation       string   `json:"operation"` // Возможные операции: install, update, unchanged.
	Channel         string   `json:"channel"`
	RequiredBy      []string `json:"requiredBy,omitempty"`
	Optional        bool     `json:"optional,omitempty"`
	Pinned          bool     `json:"pinned,omitempty"`
}

// ExtensionUpdatePlan — полностью разрешённый неизменяемый граф-кандидат.
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

// ExtensionUpdateTransaction записывает обновление нескольких расширений с компенсационным
// механизмом. Состояние сохраняется, поэтому прерванная операция оператора наблюдаема.
type ExtensionUpdateTransaction struct {
	ID         string              `json:"id"`
	Scope      string              `json:"scope"`
	ScopeID    string              `json:"scopeId,omitempty"`
	Status     string              `json:"status"` // Возможные статусы: running, succeeded, rolled_back, rollback_failed, failed.
	Plan       ExtensionUpdatePlan `json:"plan"`
	Applied    []string            `json:"applied,omitempty"`
	InFlight   string              `json:"inFlight,omitempty"`
	RolledBack []string            `json:"rolledBack,omitempty"`
	Failure    string              `json:"failure,omitempty"`
	StartedAt  time.Time           `json:"startedAt"`
	FinishedAt *time.Time          `json:"finishedAt,omitempty"`
	LeaseOwner string              `json:"leaseOwner,omitempty"`
}
