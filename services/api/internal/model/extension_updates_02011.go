package model

import "time"

// ExtensionUpdatePin фиксирует один расширение к точный неизменяемый реестр версия
// в пределах global/project установка область. Разрешатель решения являются отказ с блокировкой когда 
// закреплять не может satisfy зависимость или совместимость требования.
type ExtensionUpdatePin struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ExtensionUpdateRoot является явный корень запрошенный через оператор. Пустой
// Версия means "best версия в Канал"; пустой Канал разрешает к стабильный.
type ExtensionUpdateRoot struct {
	ExtensionID string `json:"extensionId"`
	Version     string `json:"version,omitempty"`
	Channel     string `json:"channel,omitempty"`
}

// ExtensionUpdatePlanItem является один итоговый graph узел. Зависимости являются упорядоченный
// до dependants в ExtensionUpdatePlan.Items.
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

// ExtensionUpdatePlan является fully разрешённый неизменяемый кандидат graph.
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

// ExtensionUpdateTransaction записывает compensation-основанный multi-расширение
// обновление. Состояние является сохранённый так прерванный оператор процесс является observable.
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
