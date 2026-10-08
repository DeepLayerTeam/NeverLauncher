package model

import "time"

// ExtensionTarget является один executable/UI цель объявлять через канонический
// neverlauncher-расширение.JSON манифест.
type ExtensionTarget struct {
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
}

// ExtensionAdminPage объявлять песочница Администратор страница rendered через хост.
type ExtensionAdminPage struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// ExtensionAdminNavigation contributes один sidebar запись основанный через Администратор страница.
type ExtensionAdminNavigation struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}

// ExtensionAdminWidget contributes dashboard iframe основанный через Администратор страница.
type ExtensionAdminWidget struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	PageID string `json:"pageId"`
	Height int    `json:"height,omitempty"`
}

// ExtensionAdminAction contributes toolbar действие тот activates страница и
// доставляет действие ID над типизированный Администратор мост.
type ExtensionAdminAction struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}

// ExtensionAdminContributions являются declarative slot привязка. исполняемый UI
// оставаться внутри песочница администратор цель iframe; эти значения никогда inject JS
// в NeverLauncher Администратор комплект.
type ExtensionAdminContributions struct {
	Pages            []ExtensionAdminPage       `json:"pages,omitempty"`
	Navigation       []ExtensionAdminNavigation `json:"navigation,omitempty"`
	DashboardWidgets []ExtensionAdminWidget     `json:"dashboardWidgets,omitempty"`
	Actions          []ExtensionAdminAction     `json:"actions,omitempty"`
}

// ExtensionDesktopPage объявлять один песочница Настольное приложение страница.
type ExtensionDesktopPage struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// ExtensionDesktopNavigation contributes Настольное приложение sidebar запись.
type ExtensionDesktopNavigation struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}

// ExtensionDesktopAction contributes действие доставлять к песочница страница.
type ExtensionDesktopAction struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}

// ExtensionDesktopContributions привязывать изолированный Настольное приложение цель к лаунчер slots.
type ExtensionDesktopContributions struct {
	Pages      []ExtensionDesktopPage       `json:"pages,omitempty"`
	Navigation []ExtensionDesktopNavigation `json:"navigation,omitempty"`
	Actions    []ExtensionDesktopAction     `json:"actions,omitempty"`
}

// ExtensionCLICommand является один пространство имён команда предоставлять через CLI цель.
type ExtensionCLICommand struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Usage       string `json:"usage,omitempty"`
}

// ExtensionCLIContributions описывать пространство имён тот nl разрешает до
// запуск изолированный CLI цель через Хост расширений Протокол.
type ExtensionCLIContributions struct {
	Namespace string                `json:"namespace"`
	Commands  []ExtensionCLICommand `json:"commands"`
}

// ExtensionDependency объявлять другой расширение обязательный через конкретный
// неизменяемый расширение версия.
type ExtensionDependency struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Optional bool   `json:"optional,omitempty"`
}

// ExtensionConflict объявлять incompatible extension/version диапазон.
// Версия использует NeverExtensions SemVer диапазон grammar добавленный в 0.20.11.
type ExtensionConflict struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ExtensionManifest является канонический NeverExtensions манифест добавленный в
// NeverLauncher 0.20.1. Это заменяет вновь-authored neverlauncher-плагин.JSON
// манифесты пока CLI может по-прежнему импорт устаревший формат.
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

// Расширение является стабильный идентичность общий через все неизменяемый версии.
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

// ExtensionVersion хранит один неизменяемый канонический манифест. ManifestSHA256 является
// computed из детерминированный канонический JSON до хранение.
type ExtensionVersion struct {
	ExtensionID    string            `json:"extensionId"`
	Version        string            `json:"version"`
	SchemaVersion  string            `json:"schemaVersion"`
	API            string            `json:"api"`
	Manifest       ExtensionManifest `json:"manifest"`
	ManifestSHA256 string            `json:"manifestSha256"`
	CreatedAt      time.Time         `json:"createdAt"`
}

// ExtensionInstall является сохранённый desired/current жизненный цикл состояние. 0.20.4
// жизненный цикл диспетчер владеет переходы; 0.20.5 Хост расширений использовать включённый состояние.
type ExtensionInstall struct {
	ExtensionID string `json:"extensionId"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId,omitempty"`
	// Версия является сохранённый как 0.20.1 совместимость псевдоним для DesiredVersion.
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
