package model

import "time"

// ExtensionTarget — отдельная исполняемая или интерфейсная
// цель из канонического neverlauncher-extension.json.
type ExtensionTarget struct {
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
}

// ExtensionAdminPage объявляет изолированную страницу Admin, отображаемую хостом.
type ExtensionAdminPage struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// ExtensionAdminNavigation добавляет пункт бокового меню для страницы Admin.
type ExtensionAdminNavigation struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}

// ExtensionAdminWidget добавляет iframe панели, основанный на странице Admin.
type ExtensionAdminWidget struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	PageID string `json:"pageId"`
	Height int    `json:"height,omitempty"`
}

// ExtensionAdminAction добавляет действие панели инструментов, открывающее
// страницу и передающее action ID через типизированный мост Admin.
type ExtensionAdminAction struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}

// ExtensionAdminContributions — декларативные привязки слотов.
// Исполняемый интерфейс остаётся в изолированном iframe цели Admin;
// значения никогда не внедряют JS в сборку Admin NeverLauncher.
type ExtensionAdminContributions struct {
	Pages            []ExtensionAdminPage       `json:"pages,omitempty"`
	Navigation       []ExtensionAdminNavigation `json:"navigation,omitempty"`
	DashboardWidgets []ExtensionAdminWidget     `json:"dashboardWidgets,omitempty"`
	Actions          []ExtensionAdminAction     `json:"actions,omitempty"`
}

// ExtensionDesktopPage объявляет одну изолированную страницу Desktop.
type ExtensionDesktopPage struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// ExtensionDesktopNavigation добавляет пункт бокового меню Desktop.
type ExtensionDesktopNavigation struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}

// ExtensionDesktopAction добавляет действие, передаваемое изолированной странице.
type ExtensionDesktopAction struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}

// ExtensionDesktopContributions связывает отдельную цель Desktop со слотами лаунчера.
type ExtensionDesktopContributions struct {
	Pages      []ExtensionDesktopPage       `json:"pages,omitempty"`
	Navigation []ExtensionDesktopNavigation `json:"navigation,omitempty"`
	Actions    []ExtensionDesktopAction     `json:"actions,omitempty"`
}

// ExtensionCLICommand — отдельная команда с пространством имён цели CLI.
type ExtensionCLICommand struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Usage       string `json:"usage,omitempty"`
}

// ExtensionCLIContributions описывает пространство имён, разрешаемое
// nl перед запуском отдельной цели CLI через Extension Host Protocol.
type ExtensionCLIContributions struct {
	Namespace string                `json:"namespace"`
	Commands  []ExtensionCLICommand `json:"commands"`
}

// ExtensionDependency объявляет зависимость от другого
// расширения для конкретной неизменяемой версии.
type ExtensionDependency struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Optional bool   `json:"optional,omitempty"`
}

// ExtensionConflict объявляет несовместимый диапазон версий расширения.
// Version использует грамматику диапазонов NeverExtensions SemVer из 0.20.11.
type ExtensionConflict struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// ExtensionManifest — канонический манифест NeverExtensions,
// введённый в 0.20.1. Он заменяет новые neverlauncher-plugin.json,
// сохраняя импорт старого формата через CLI.
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
	Sandbox       *ExtensionSandboxPolicy        `json:"sandbox,omitempty"`
	Hooks         []string                       `json:"hooks,omitempty"`
	Dependencies  []ExtensionDependency          `json:"dependencies,omitempty"`
	Conflicts     []ExtensionConflict            `json:"conflicts,omitempty"`
	Metadata      map[string]string              `json:"metadata,omitempty"`
	Admin         *ExtensionAdminContributions   `json:"admin,omitempty"`
	Desktop       *ExtensionDesktopContributions `json:"desktop,omitempty"`
	CLI           *ExtensionCLIContributions     `json:"cli,omitempty"`
}

// Extension — устойчивая идентичность, общая всем неизменяемым версиям.
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

// ExtensionVersion хранит один неизменяемый канонический манифест. ManifestSHA256
// вычисляется из детерминированного канонического JSON до сохранения.
type ExtensionVersion struct {
	ExtensionID    string            `json:"extensionId"`
	Version        string            `json:"version"`
	SchemaVersion  string            `json:"schemaVersion"`
	API            string            `json:"api"`
	Manifest       ExtensionManifest `json:"manifest"`
	ManifestSHA256 string            `json:"manifestSha256"`
	CreatedAt      time.Time         `json:"createdAt"`
}

// ExtensionInstall — сохраняемое желаемое и текущее состояние жизненного цикла. Менеджер
// 0.20.4 управляет переходами; Extension Host 0.20.5 потребляет активное состояние.
type ExtensionInstall struct {
	ExtensionID string `json:"extensionId"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId,omitempty"`
	// Version оставлен как совместимый псевдоним DesiredVersion из 0.20.1.
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
