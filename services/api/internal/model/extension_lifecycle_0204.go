package model

import "time"

const (
	ExtensionInstallStateAbsent   = "absent"
	ExtensionInstallStateDisabled = "disabled"
	ExtensionInstallStateEnabled  = "enabled"
	ExtensionInstallStateError    = "error"
)

// ExtensionLifecycleTransition — одна атомарная операция сохранения после
// успешной активации файлов из промежуточного каталога. ExpectedGeneration
// предотвращает перезапись при параллельных изменениях жизненного цикла.
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

// ExtensionInstallRevision — успешное изменение жизненного цикла в журнале только
// для добавления. BackupPath указывает на прежние активные данные, если они
// перемещены или удалены, обеспечивая детерминированный проверяемый откат.
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
