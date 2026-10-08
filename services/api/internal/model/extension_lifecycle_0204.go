package model

import "time"

const (
	ExtensionInstallStateAbsent   = "absent"
	ExtensionInstallStateDisabled = "disabled"
	ExtensionInstallStateEnabled  = "enabled"
	ExtensionInstallStateError    = "error"
)

// ExtensionLifecycleTransition является единый атомарный хранение операция используется
// после подготовленный файловая система активация имеет succeeded. ExpectedGeneration создаёт
// конкурентный жизненный цикл изменение завершаться ошибкой вместо чем overwrite каждый другой.
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

// ExtensionInstallRevision является только добавление успешный жизненный цикл переход.
// BackupPath точки в предыдущий activated полезная нагрузка когда операция moved
// или удалён это, making откат детерминированный и auditable.
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
