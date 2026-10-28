package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var ErrNotFound = errors.New("запись не найдена")
var ErrImmutable = errors.New("published release immutable")
var ErrConflict = errors.New("repository conflict")

// ErrStableRuntimeGate0341 is a non-overridable release protection boundary.
// 0.34.1 has no attested runtime executor; signed legacy JSON is not sufficient.
var ErrStableRuntimeGate0341 = errors.New("stable_runtime_gate_0341: trusted staged-client/server execution is not yet available; stable publication denied")

func IsStableChannel0341(channel string) bool {
	return strings.EqualFold(strings.TrimSpace(channel), "stable")
}

// DeviceKeyReplacementRepository реализуют репозитории, способные атомарно заменить
// идентичность доверенного устройства вместе с текущей привязкой сеанса авторизации
// и каскадом отзыва. PostgreSQL поддерживает это непосредственно; репозиторий
// разработки в памяти использует транзакционный запасной механизм уровня HTTP.
type DeviceKeyReplacementRepository interface {
	ReplaceTrustedDeviceKey(ctx context.Context, userID, oldDeviceID, currentSessionID, mode, reason string, replacement model.TrustedDevice, now time.Time) (model.DeviceKeyReplacementResult, error)
}

type Repository interface {
	ListProjects() []model.Project
	GetProject(id string) (model.Project, error)
	SaveProject(project model.Project) (model.Project, error)
	ListProfiles(projectID string) ([]model.Profile, error)
	SaveProfile(profile model.Profile) (model.Profile, error)
	ListChannels(projectID string) ([]model.ReleaseChannel, error)
	SaveChannel(channel model.ReleaseChannel) (model.ReleaseChannel, error)
	ListVersions(projectID string) ([]model.ReleaseVersion, error)
	ListFiles(projectID, versionID string) ([]model.FileObject, error)
	ListUsers() []model.User
	GetUser(id string) (model.User, error)
	GetUserByEmail(email string) (model.User, error)
	SaveUser(user model.User) (model.User, error)
	SetUserDisabled(id string, disabled bool) (model.User, error)
	SetUserPassword(id, passwordHash string) (model.User, error)
	TouchUserLogin(id string) (model.User, error)
	GetAuthIdentity(provider, subject string) (model.AuthIdentity, error)
	GetAuthIdentityByIssuer(provider, issuer, subject string) (model.AuthIdentity, error)
	ListAuthIdentities(userID string) []model.AuthIdentity
	SaveAuthIdentity(identity model.AuthIdentity) (model.AuthIdentity, error)
	SaveFederatedUser(ctx context.Context, user model.User, identity model.AuthIdentity) (model.User, model.AuthIdentity, error)
	TouchAuthIdentity(id string) (model.AuthIdentity, error)
	SaveTrustedDevice(ctx context.Context, device model.TrustedDevice) (model.TrustedDevice, error)
	GetTrustedDevice(userID, deviceID string) (model.TrustedDevice, error)
	GetTrustedDeviceByID(deviceID string) (model.TrustedDevice, error)
	ListTrustedDevices(userID, status string) []model.TrustedDevice
	RenameTrustedDevice(userID, deviceID, name string) (model.TrustedDevice, error)
	RevokeTrustedDevice(ctx context.Context, userID, deviceID, reason string) (model.DeviceRevocationResult, error)
	RevokeOtherTrustedDevices(ctx context.Context, userID, exceptDeviceID, reason string) (model.DeviceRevocationBatch, error)
	TouchTrustedDevice(ctx context.Context, userID, deviceID, ip, userAgent string) (model.TrustedDevice, error)
	AttestTrustedDevice(ctx context.Context, userID, deviceID, method string, attestedAt, expiresAt time.Time) (model.TrustedDevice, error)
	SaveHardwareEvidence(ctx context.Context, evidence model.DeviceHardwareEvidence) error
	LatestHardwareEvidence(ctx context.Context, userID, deviceID string) (model.DeviceHardwareEvidence, error)
	SaveMeasuredBoot0315(ctx context.Context, evidence model.MeasuredBootEvidence0315) error
	LatestMeasuredBoot0315(ctx context.Context, userID, deviceID string) (model.MeasuredBootEvidence0315, error)
	SaveDeviceChallenge(ctx context.Context, challenge model.DeviceChallenge) error
	ConsumeDeviceChallenge(ctx context.Context, id, userID, deviceID, purpose, challengeHash string, now time.Time) (model.DeviceChallenge, error)
	ListRoles() []model.Role
	ListAuditEvents() []model.AuditEvent
	AddAuditEvent(event model.AuditEvent)
	GetManifest(projectID, profileID, channel string) (model.Manifest, error)
	CreateVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error)
	PublishVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error)
	PublishVersionWithManifest(projectID, profileID, channel, version string, manifest model.Manifest) (model.ReleaseVersion, error)
	UpdateVersionManifest(projectID, versionID string, manifest model.Manifest) (model.ReleaseVersion, error)
	UpdateVersionStatus(projectID, versionID, status string) (model.ReleaseVersion, error)
	SaveIntegrityCheck(ctx context.Context, result model.IntegrityCheckResult) (model.IntegrityCheckResult, error)
	LatestIntegrityCheck(ctx context.Context, packageID string) (model.IntegrityCheckResult, error)
	SaveRuntimeValidation(ctx context.Context, result model.RuntimeValidationResult) (model.RuntimeValidationResult, error)
	ListRuntimeValidations(ctx context.Context, packageID string) ([]model.RuntimeValidationResult, error)
	GetProjectValidationPolicy(ctx context.Context, projectID string) (model.ProjectValidationPolicy, error)
	SaveProjectValidationPolicy(ctx context.Context, policy model.ProjectValidationPolicy) (model.ProjectValidationPolicy, error)
	AddFile(file model.FileObject) (model.FileObject, error)
	ExportProject(projectID string) (map[string]any, error)
	ImportProject(payload map[string]any) error
	AddTelemetryEvent(event model.TelemetryEvent)
	AddCrashReport(report model.CrashReport)
	ListTelemetryEvents() []model.TelemetryEvent
	ListCrashReports() []model.CrashReport
	ListExtensions(ctx context.Context) ([]model.Extension, error)
	GetExtension(ctx context.Context, id string) (model.Extension, error)
	ListExtensionVersions(ctx context.Context, extensionID string) ([]model.ExtensionVersion, error)
	GetExtensionVersion(ctx context.Context, extensionID, version string) (model.ExtensionVersion, error)
	ListExtensionPermissions(ctx context.Context, extensionID, version string) ([]string, error)
	ListExtensionDependencies(ctx context.Context, extensionID, version string) ([]model.ExtensionDependency, error)
	SaveExtensionVersion(ctx context.Context, manifest model.ExtensionManifest) (model.ExtensionVersion, error)
	ListExtensionInstalls(ctx context.Context, scope, scopeID string) ([]model.ExtensionInstall, error)
	GetExtensionInstall(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionInstall, error)
	SaveExtensionInstall(ctx context.Context, install model.ExtensionInstall) (model.ExtensionInstall, error)
	DeleteExtensionInstall(ctx context.Context, extensionID, scope, scopeID string) error
	SaveExtensionRegistryPublisher(ctx context.Context, publisher model.ExtensionRegistryPublisher) (model.ExtensionRegistryPublisher, error)
	ListExtensionRegistryPublishers(ctx context.Context) ([]model.ExtensionRegistryPublisher, error)
	SaveExtensionRegistryPublisherKey(ctx context.Context, key model.ExtensionRegistryPublisherKey) (model.ExtensionRegistryPublisherKey, error)
	GetExtensionRegistryPublisherKey(ctx context.Context, publisherID, fingerprint string) (model.ExtensionRegistryPublisherKey, error)
	ListExtensionRegistryPublisherKeys(ctx context.Context, publisherID string) ([]model.ExtensionRegistryPublisherKey, error)
	PublishExtensionRegistryVersion(ctx context.Context, publication model.ExtensionRegistryPublication) (model.ExtensionRegistryVersion, error)
	SearchExtensionRegistry(ctx context.Context, query model.ExtensionRegistrySearch) ([]model.ExtensionRegistryVersion, error)
	GetExtensionRegistryVersion(ctx context.Context, extensionID, version string) (model.ExtensionRegistryVersion, error)
	GetExtensionRegistryExtension(ctx context.Context, extensionID string) (model.ExtensionRegistryExtension, error)
	SetExtensionRegistryChannel(ctx context.Context, extensionID, channel, version string) (model.ExtensionRegistryVersion, error)
	YankExtensionRegistryVersion(ctx context.Context, extensionID, version, reason string) (model.ExtensionRegistryVersion, error)
	GetExtensionInstallState(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionInstall, error)
	ListExtensionInstallStates(ctx context.Context, scope, scopeID string) ([]model.ExtensionInstall, error)
	TransitionExtensionInstall(ctx context.Context, transition model.ExtensionLifecycleTransition) (model.ExtensionInstall, error)
	ListExtensionInstallRevisions(ctx context.Context, extensionID, scope, scopeID string, limit int) ([]model.ExtensionInstallRevision, error)
	ListExtensionPermissionGrants(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionPermissionGrant, error)
	GrantExtensionPermission(ctx context.Context, grant model.ExtensionPermissionGrant) (model.ExtensionPermissionGrant, error)
	RevokeExtensionPermission(ctx context.Context, extensionID, scope, scopeID, permission string) error
	PutExtensionSecret(ctx context.Context, secret model.ExtensionSecret) (model.ExtensionSecret, error)
	GetExtensionSecret(ctx context.Context, extensionID, scope, scopeID, name string) (model.ExtensionSecret, error)
	ListExtensionSecrets(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionSecretMetadata, error)
	DeleteExtensionSecret(ctx context.Context, extensionID, scope, scopeID, name string) error
	ListExtensionUpdatePins(ctx context.Context, scope, scopeID string) ([]model.ExtensionUpdatePin, error)
	SetExtensionUpdatePin(ctx context.Context, pin model.ExtensionUpdatePin) (model.ExtensionUpdatePin, error)
	DeleteExtensionUpdatePin(ctx context.Context, extensionID, scope, scopeID string) error
	AcquireExtensionUpdateLease(ctx context.Context, scope, scopeID, owner string, ttl time.Duration) (bool, error)
	ReleaseExtensionUpdateLease(ctx context.Context, scope, scopeID, owner string) error
	SaveExtensionUpdateTransaction(ctx context.Context, tx model.ExtensionUpdateTransaction) (model.ExtensionUpdateTransaction, error)
	GetExtensionUpdateTransaction(ctx context.Context, id string) (model.ExtensionUpdateTransaction, error)
	ListExtensionUpdateTransactions(ctx context.Context, scope, scopeID, status string) ([]model.ExtensionUpdateTransaction, error)
	GetExtensionTrustPolicy(ctx context.Context) (model.ExtensionTrustPolicy, error)
	SaveExtensionTrustPolicy(ctx context.Context, policy model.ExtensionTrustPolicy) (model.ExtensionTrustPolicy, error)
	RevokeExtensionRegistryPublisherKey(ctx context.Context, publisherID, fingerprint string) (model.ExtensionRegistryPublisherKey, error)
	SaveExtensionQuarantine(ctx context.Context, entry model.ExtensionQuarantineEntry) (model.ExtensionQuarantineEntry, error)
	ListExtensionQuarantine(ctx context.Context, activeOnly bool) ([]model.ExtensionQuarantineEntry, error)
	GetExtensionQuarantine(ctx context.Context, id string) (model.ExtensionQuarantineEntry, error)
	ReleaseExtensionQuarantine(ctx context.Context, id, actor string) (model.ExtensionQuarantineEntry, error)
	IsExtensionPackageQuarantined(ctx context.Context, packageIdentity string) (bool, error)
	SetExtensionEmergencyDisable(ctx context.Context, item model.ExtensionEmergencyDisable) (model.ExtensionEmergencyDisable, error)
	GetExtensionEmergencyDisable(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionEmergencyDisable, error)
	ListExtensionEmergencyDisables(ctx context.Context, activeOnly bool) ([]model.ExtensionEmergencyDisable, error)
	ClearExtensionEmergencyDisable(ctx context.Context, extensionID, scope, scopeID, actor string) (model.ExtensionEmergencyDisable, error)
}

type MemoryRepository struct {
	managedProviderMu              sync.Mutex
	managedProviders               map[string]ManagedProviderHead02910
	hwidMu                         sync.Mutex
	hwidObservations               map[string]HWIDObservation0299
	hwidAppeals                    map[string]HWIDAppeal0299
	protectionMu                   sync.RWMutex
	protectionBans                 map[string]ProtectionBan
	buildMu                        sync.Mutex
	buildWorkspaces                map[string]BuildWorkspace
	operationalConfigMu            sync.Mutex
	officialProviderMu             sync.Mutex
	officialProviderHistory        []OfficialProviderRevision02611
	operationalConfigRevisions     []OperationalConfigRevision
	draftMu                        sync.Mutex
	releaseDrafts                  map[string]ReleaseDraft
	validationMu                   sync.Mutex
	deviceMu                       sync.Mutex
	minecraftMu                    sync.Mutex
	extensionMu                    sync.Mutex
	auditSinkMu                    sync.RWMutex
	auditSink                      func(model.AuditEvent)
	durableMu                      sync.Mutex
	channelHeads                   map[string]model.ChannelHead
	durableJobs                    map[string]model.DurableJob
	durableOpAttempts              map[string][]model.DurableJobAttempt
	durableJobKeys                 map[string]string
	durableScopeLeases             map[string]model.DurableScopeLease
	durableOutbox                  map[string]model.DurableOutboxEvent
	durableNonces                  map[string]time.Time
	idempotencyDigests             map[string]string
	projects                       []model.Project
	profileMu                      sync.RWMutex
	profileHistory                 map[string][]model.ProfileSnapshot
	profiles                       []model.Profile
	channels                       []model.ReleaseChannel
	releases                       []model.ReleaseVersion
	integrityChecks                []model.IntegrityCheckResult
	runtimeValidations             []model.RuntimeValidationResult
	stagedRuntimeRuns0342          []model.StagedRuntimeRun0342
	validationAttestations0345     []model.ValidationAttestation0345
	validationChallenges0346       map[string]model.ValidationChallenge0346
	validationRevocations0346      map[string]bool
	validationPolicies             map[string]model.ProjectValidationPolicy
	files                          []model.FileObject
	users                          []model.User
	identities                     []model.AuthIdentity
	providerCredentials            []model.ProviderCredential
	minecraftProfiles              []model.MinecraftProfile
	minecraftSessions              []model.MinecraftSession
	minecraftJoins                 []model.MinecraftJoin
	trustedDevices                 []model.TrustedDevice
	deviceChallenges               []model.DeviceChallenge
	hardwareEvidence               []model.DeviceHardwareEvidence
	measuredBoot0315               []model.MeasuredBootEvidence0315
	roles                          []model.Role
	audit                          []model.AuditEvent
	telemetry                      []model.TelemetryEvent
	crashes                        []model.CrashReport
	extensions                     []model.Extension
	extensionVersions              []model.ExtensionVersion
	extensionInstalls              []model.ExtensionInstall
	extensionRegistryPublishers    []model.ExtensionRegistryPublisher
	extensionRegistryKeys          []model.ExtensionRegistryPublisherKey
	extensionRegistryVersions      []model.ExtensionRegistryVersion
	extensionInstallRevisions      []model.ExtensionInstallRevision
	extensionEvents                []model.ExtensionEvent
	extensionEventSubscriptions    []model.ExtensionEventSubscription
	extensionEventDeliveries       []model.ExtensionEventDelivery
	extensionEventDeadLetters      []model.ExtensionEventDeadLetter
	extensionPermissionGrants      []model.ExtensionPermissionGrant
	extensionSecrets               []model.ExtensionSecret
	extensionUpdatePins            []model.ExtensionUpdatePin
	extensionUpdateTransactions    []model.ExtensionUpdateTransaction
	extensionUpdateLeases          map[string]extensionUpdateLease02011
	extensionTrustPolicy           model.ExtensionTrustPolicy
	extensionQuarantine            []model.ExtensionQuarantineEntry
	extensionEmergencyDisables     []model.ExtensionEmergencyDisable
	nextExtensionInstallRevisionID int64
	nextExtensionEventSequence     int64
	nextExtensionSubscriptionID    int64
	nextExtensionDeliveryID        int64
	nextExtensionDeadLetterID      int64
}

func NewMemoryRepository(publicURL string) *MemoryRepository {
	now := time.Now().UTC()
	// The demo's published v2 manifest must pin the same immutable revision
	// as the initial vanilla profile. Do not try to read a repository before
	// its constructor has finished.
	snapshot := model.SnapshotProfile(model.Profile{
		SchemaVersion: model.ProfileSchemaV2, Revision: 1,
		ID: "vanilla", ProjectID: "demo-project", Name: "Vanilla",
		Description: "Минимальный vanilla-профиль", Loader: "vanilla", IsDefault: true,
	})
	manifest := model.Manifest{
		SchemaVersion:   model.ManifestSchemaV2,
		ProfileSnapshot: &snapshot,
		ProjectID:       "demo-project",
		ProfileID:       "vanilla",
		Channel:         "stable",
		Version:         "3.4.0",
		CreatedAt:       now.Format(time.RFC3339),
		Minecraft: model.MinecraftInfo{
			Version:   "1.21.1",
			Loader:    "vanilla",
			MainClass: "net.minecraft.client.main.Main",
			GameArgs: []string{
				"--username", "${player_name}",
				"--version", "${minecraft_version}",
				"--gameDir", "${game_directory}",
			},
		},
		Runtime: model.RuntimeInfo{
			Java:    model.JavaInfo{MajorVersion: 21, Distribution: "any", AllowCustomPath: true},
			JVMArgs: []string{"-Xms2G", "-Xmx4G"},
			Memory:  model.MemoryInfo{MinimumMb: 2048, RecommendedMb: 4096, MaximumMb: 8192},
			Launch:  model.RuntimeLaunch{MainClass: "net.minecraft.client.main.Main", ClasspathStrategy: "libraries", NativesDirectory: "natives", OfflineMode: true},
		},
		Directories: model.Directories{Game: ".minecraft", Assets: "assets", Libraries: "libraries", Natives: "natives"},
		Files: []model.ManifestFile{
			{
				Path:     "README.txt",
				Size:     0,
				SHA256:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				URL:      publicURL + "/api/v1/files/demo-project/3.4.0/README.txt",
				Required: true,
			},
		},
	}

	return &MemoryRepository{
		nextExtensionInstallRevisionID: 1,
		extensionUpdateLeases:          map[string]extensionUpdateLease02011{},
		durableJobs:                    map[string]model.DurableJob{},
		channelHeads:                   map[string]model.ChannelHead{headKey0228("demo-project", "vanilla", "stable"): {ProjectID: "demo-project", ProfileID: "vanilla", Channel: "stable", Revision: 1, ReleaseID: "demo-project-vanilla-3.4.0", Version: "3.4.0", UpdatedAt: now}},
		durableOpAttempts:              map[string][]model.DurableJobAttempt{},
		durableJobKeys:                 map[string]string{},
		durableScopeLeases:             map[string]model.DurableScopeLease{},
		durableOutbox:                  map[string]model.DurableOutboxEvent{},
		durableNonces:                  map[string]time.Time{},
		idempotencyDigests:             map[string]string{},
		validationPolicies:             map[string]model.ProjectValidationPolicy{"demo-project": {ProjectID: "demo-project", RequiredLevel: "integrity", UpdatedAt: now}},
		extensionTrustPolicy:           model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeStrict, AllowedPublishers: []string{}, UpdatedAt: now},
		projects: []model.Project{
			{ID: "demo-project", Name: "Демонстрационный проект", Description: "Пример проекта NeverLauncher", DefaultChannel: "stable", CreatedAt: now, UpdatedAt: now},
		},
		profiles: []model.Profile{
			{ID: "vanilla", ProjectID: "demo-project", Name: "Vanilla", Description: "Минимальный vanilla-профиль", Loader: "vanilla", IsDefault: true, CreatedAt: now, UpdatedAt: now},
			{ID: "fabric", ProjectID: "demo-project", Name: "Fabric", Description: "Пример профиля для Fabric-сборки", Loader: "fabric", Preset: "recommended", IsDefault: false, CreatedAt: now, UpdatedAt: now},
			{ID: "lite", ProjectID: "demo-project", Name: "Lite", Description: "Лёгкий профиль для слабых машин", Loader: "vanilla", Preset: "lite", IsDefault: false, CreatedAt: now, UpdatedAt: now},
			{ID: "recommended", ProjectID: "demo-project", Name: "Recommended", Description: "Рекомендуемый профиль", Loader: "fabric", Preset: "recommended", IsDefault: false, CreatedAt: now, UpdatedAt: now},
			{ID: "cinematic", ProjectID: "demo-project", Name: "Cinematic", Description: "Профиль с упором на визуальную часть", Loader: "fabric", Preset: "cinematic", IsDefault: false, CreatedAt: now, UpdatedAt: now},
			{ID: "custom", ProjectID: "demo-project", Name: "Custom", Description: "Пользовательский профиль", Loader: "fabric", Preset: "custom", IsDefault: false, CreatedAt: now, UpdatedAt: now},
		},
		channels: []model.ReleaseChannel{
			{ID: "dev", ProjectID: "demo-project", Name: "dev", Description: "Канал разработки", Protected: false},
			{ID: "beta", ProjectID: "demo-project", Name: "beta", Description: "Канал предварительного тестирования", Protected: false},
			{ID: "stable", ProjectID: "demo-project", Name: "stable", Description: "Стабильный канал", Protected: true},
		},
		releases: []model.ReleaseVersion{
			{ID: "demo-project-vanilla-3.4.0", ProjectID: "demo-project", ProfileID: "vanilla", Channel: "stable", Version: "3.4.0", Status: "published", Manifest: manifest, PublishedAt: now},
		},
		files: []model.FileObject{
			{ID: "demo-readme", ProjectID: "demo-project", VersionID: "demo-project-vanilla-3.4.0", Path: "README.txt", Size: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", URL: publicURL + "/api/v1/files/demo-project/3.4.0/README.txt", Required: true},
		},
		roles: []model.Role{
			{ID: "owner", Name: "Владелец", Description: "Полный доступ к проекту", Permissions: []string{"*"}},
			{ID: "admin", Name: "Администратор", Description: "Управление проектами, версиями, файлами, пользователями и аудитом", Permissions: []string{"project:read", "project:write", "release:prepare", "release:publish", "file:write", "users:manage", "roles:manage", "audit:read", "diagnostics:read", "storage:manage", "settings:manage", "security:read", "extension:manage", "serverbridge:control", "serverbridge:console", "gameserver:broadcast", "gameserver:moderate", "gameserver:save", "gameserver:traffic", "gameserver:shutdown", "gameserver:console"}},
			{ID: "release-manager", Name: "Release Manager", Description: "Подготовка, публикация и откат релизов", Permissions: []string{"project:read", "release:prepare", "release:publish", "audit:read"}},
			{ID: "operator", Name: "Оператор", Description: "Работа с профилями, пакетами и файлами без финальной публикации", Permissions: []string{"project:read", "project:write", "release:prepare", "file:write", "diagnostics:read", "serverbridge:control", "gameserver:broadcast", "gameserver:moderate", "gameserver:save", "gameserver:traffic"}},
			{ID: "support", Name: "Поддержка", Description: "Чтение проекта, диагностика и аудит без права изменения", Permissions: []string{"project:read", "diagnostics:read", "audit:read"}},
			{ID: "developer", Name: "Разработчик (legacy)", Description: "Совместимая ограниченная роль подготовки версий", Permissions: []string{"project:read", "release:prepare", "file:write"}},
			{ID: "viewer", Name: "Наблюдатель", Description: "Только чтение", Permissions: []string{"project:read"}},
			{ID: "player", Name: "Игрок", Description: "Вход в desktop и запуск доступных профилей", Permissions: []string{"launcher:login", "profile:download", "profile:launch"}},
		},
		users: []model.User{
			{ID: "admin", Email: "admin@neverlauncher.local", DisplayName: "Администратор", RoleID: "owner", Status: "active", ProjectRoles: map[string]string{"demo-project": "owner"}, PasswordHash: "sha256:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", PasswordUpdatedAt: now, CreatedAt: now, UpdatedAt: now},
		},
		identities: []model.AuthIdentity{
			{ID: "identity-local-admin", UserID: "admin", Provider: "local", Issuer: "neverlauncher", Subject: "admin", Email: "admin@neverlauncher.local", Username: "admin@neverlauncher.local", DisplayName: "Администратор", CreatedAt: now, UpdatedAt: now},
		},
		audit: []model.AuditEvent{
			{ID: "audit-start", Actor: "system", Action: "backend:start", Target: "neverlauncher-api", CreatedAt: now},
		},
	}
}

func (r *MemoryRepository) ListProjects() []model.Project {
	items := append([]model.Project(nil), r.projects...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (r *MemoryRepository) GetProject(id string) (model.Project, error) {
	for _, item := range r.projects {
		if item.ID == id {
			return item, nil
		}
	}
	return model.Project{}, ErrNotFound
}

func (r *MemoryRepository) SaveProject(project model.Project) (model.Project, error) {
	now := time.Now().UTC()
	project.ID = strings.TrimSpace(project.ID)
	project.Name = strings.TrimSpace(project.Name)
	if project.ID == "" {
		project.ID = strings.ToLower(strings.ReplaceAll(project.Name, " ", "-"))
	}
	if project.ID == "" || project.Name == "" {
		return model.Project{}, fmt.Errorf("id и name проекта обязательны")
	}
	if project.DefaultChannel == "" {
		project.DefaultChannel = "stable"
	}
	for i := range r.projects {
		if r.projects[i].ID == project.ID {
			if project.CreatedAt.IsZero() {
				project.CreatedAt = r.projects[i].CreatedAt
			}
			project.UpdatedAt = now
			r.projects[i] = project
			return project, nil
		}
	}
	if project.CreatedAt.IsZero() {
		project.CreatedAt = now
	}
	if project.UpdatedAt.IsZero() {
		project.UpdatedAt = now
	}
	r.projects = append(r.projects, project)
	return project, nil
}

func (r *MemoryRepository) ListProfiles(projectID string) ([]model.Profile, error) {
	if _, err := r.GetProject(projectID); err != nil {
		return nil, err
	}
	r.profileMu.RLock()
	defer r.profileMu.RUnlock()
	var result []model.Profile
	for _, item := range r.profiles {
		if item.ProjectID == projectID {
			item.SchemaVersion = model.ProfileSchemaV2
			if item.Revision == 0 {
				item.Revision = 1
			}
			item.Digest = model.ProfileDigest(model.ProfileSpecOf(item))
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (r *MemoryRepository) SaveProfile(profile model.Profile) (model.Profile, error) {
	if _, err := r.GetProject(profile.ProjectID); err != nil {
		return model.Profile{}, err
	}
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.ID == "" {
		profile.ID = strings.ToLower(strings.ReplaceAll(profile.Name, " ", "-"))
	}
	var err error
	profile, err = model.NormalizeProfileV2(profile)
	if err != nil {
		return model.Profile{}, err
	}
	now := time.Now().UTC()
	r.profileMu.Lock()
	defer r.profileMu.Unlock()
	if r.profileHistory == nil {
		r.profileHistory = make(map[string][]model.ProfileSnapshot)
	}
	key := profile.ProjectID + "\x00" + profile.ID
	for i := range r.profiles {
		current := r.profiles[i]
		if current.ProjectID == profile.ProjectID && current.ID == profile.ID {
			if current.Revision == 0 {
				current.Revision = 1
			}
			current.SchemaVersion = model.ProfileSchemaV2
			current.Digest = model.ProfileDigest(model.ProfileSpecOf(current))
			if profile.Revision != 0 && profile.Revision != current.Revision {
				return model.Profile{}, ErrConflict
			}
			if len(r.profileHistory[key]) == 0 {
				r.profileHistory[key] = append(r.profileHistory[key], model.SnapshotProfile(current))
			}
			if profile.Digest == current.Digest {
				return current, nil
			}
			profile.Revision = current.Revision + 1
			profile.CreatedAt = current.CreatedAt
			profile.UpdatedAt = now
			r.profiles[i] = profile
			r.profileHistory[key] = append(r.profileHistory[key], model.SnapshotProfile(profile))
			return profile, nil
		}
	}
	if profile.Revision > 1 {
		return model.Profile{}, ErrConflict
	}
	profile.Revision = 1
	profile.CreatedAt = now
	profile.UpdatedAt = now
	r.profiles = append(r.profiles, profile)
	r.profileHistory[key] = append(r.profileHistory[key], model.SnapshotProfile(profile))
	return profile, nil
}

func (r *MemoryRepository) ListProfileRevisions(projectID, profileID string) ([]model.ProfileSnapshot, error) {
	r.profileMu.RLock()
	defer r.profileMu.RUnlock()
	key := projectID + "\x00" + profileID
	for _, p := range r.profiles {
		if p.ProjectID == projectID && p.ID == profileID {
			result := append([]model.ProfileSnapshot(nil), r.profileHistory[key]...)
			if len(result) == 0 {
				p.SchemaVersion = model.ProfileSchemaV2
				p.Revision = 1
				result = append(result, model.SnapshotProfile(p))
			}
			return result, nil
		}
	}
	return nil, ErrNotFound
}

func (r *MemoryRepository) ListChannels(projectID string) ([]model.ReleaseChannel, error) {
	if _, err := r.GetProject(projectID); err != nil {
		return nil, err
	}
	var result []model.ReleaseChannel
	for _, item := range r.channels {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (r *MemoryRepository) SaveChannel(channel model.ReleaseChannel) (model.ReleaseChannel, error) {
	if _, err := r.GetProject(channel.ProjectID); err != nil {
		return model.ReleaseChannel{}, err
	}
	channel.ID = strings.TrimSpace(channel.ID)
	channel.Name = strings.TrimSpace(channel.Name)
	if channel.ID == "" {
		channel.ID = strings.ToLower(strings.ReplaceAll(channel.Name, " ", "-"))
	}
	if channel.Name == "" {
		channel.Name = channel.ID
	}
	if channel.ID == "" || channel.ProjectID == "" {
		return model.ReleaseChannel{}, fmt.Errorf("projectId и id канала обязательны")
	}
	for i := range r.channels {
		if r.channels[i].ProjectID == channel.ProjectID && r.channels[i].ID == channel.ID {
			r.channels[i] = channel
			return channel, nil
		}
	}
	r.channels = append(r.channels, channel)
	return channel, nil
}

func (r *MemoryRepository) ListVersions(projectID string) ([]model.ReleaseVersion, error) {
	if _, err := r.GetProject(projectID); err != nil {
		return nil, err
	}
	var result []model.ReleaseVersion
	for _, item := range r.releases {
		if item.ProjectID == projectID {
			result = append(result, cloneRelease0222(item))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PublishedAt.After(result[j].PublishedAt) })
	return result, nil
}

func (r *MemoryRepository) ListFiles(projectID, versionID string) ([]model.FileObject, error) {
	if _, err := r.GetProject(projectID); err != nil {
		return nil, err
	}
	var result []model.FileObject
	for _, item := range r.files {
		if item.ProjectID == projectID && (versionID == "" || item.VersionID == versionID) {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func (r *MemoryRepository) ListUsers() []model.User {
	items := append([]model.User(nil), r.users...)
	sort.Slice(items, func(i, j int) bool { return items[i].Email < items[j].Email })
	return items
}

func (r *MemoryRepository) GetUser(id string) (model.User, error) {
	for _, item := range r.users {
		if item.ID == id {
			return item, nil
		}
	}
	return model.User{}, ErrNotFound
}

func (r *MemoryRepository) GetUserByEmail(email string) (model.User, error) {
	for _, item := range r.users {
		if strings.EqualFold(item.Email, email) {
			return item, nil
		}
	}
	return model.User{}, ErrNotFound
}

func (r *MemoryRepository) SaveUser(user model.User) (model.User, error) {
	now := time.Now().UTC()
	if user.ID == "" {
		user.ID = fmt.Sprintf("user-%d", now.UnixNano())
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.RoleID == "" {
		user.RoleID = "viewer"
	}
	if user.ProjectRoles == nil {
		user.ProjectRoles = map[string]string{}
	}
	roleExists := func(roleID string) bool {
		for _, role := range r.roles {
			if role.ID == roleID {
				return true
			}
		}
		return false
	}
	if !roleExists(strings.TrimSpace(user.RoleID)) {
		return model.User{}, fmt.Errorf("неизвестная глобальная роль %q", user.RoleID)
	}
	canonicalProjectRoles := make(map[string]string, len(user.ProjectRoles))
	for projectID, roleID := range user.ProjectRoles {
		projectID = strings.TrimSpace(projectID)
		roleID = strings.TrimSpace(roleID)
		if projectID == "*" {
			return model.User{}, fmt.Errorf("wildcard project role is not supported; use a global role")
		}
		if projectID == "" || roleID == "" {
			continue
		}
		if _, err := r.GetProject(projectID); err != nil {
			return model.User{}, fmt.Errorf("неизвестный проект %q для project role", projectID)
		}
		if !roleExists(roleID) {
			return model.User{}, fmt.Errorf("неизвестная проектная роль %q", roleID)
		}
		canonicalProjectRoles[projectID] = roleID
	}
	user.ProjectRoles = canonicalProjectRoles
	for _, existing := range r.users {
		if existing.ID != user.ID && strings.EqualFold(existing.Email, user.Email) {
			return model.User{}, fmt.Errorf("пользователь с таким email уже существует")
		}
	}
	updatedExisting := false
	for i := range r.users {
		if r.users[i].ID == user.ID {
			if user.CreatedAt.IsZero() {
				user.CreatedAt = r.users[i].CreatedAt
			}
			user.UpdatedAt = now
			r.users[i] = user
			updatedExisting = true
			break
		}
	}
	if !updatedExisting {
		if user.CreatedAt.IsZero() {
			user.CreatedAt = now
		}
		if user.UpdatedAt.IsZero() {
			user.UpdatedAt = now
		}
		r.users = append(r.users, user)
	}
	if strings.TrimSpace(user.PasswordHash) != "" {
		if _, err := r.SaveAuthIdentity(model.AuthIdentity{
			UserID: user.ID, Provider: "local", Subject: user.ID,
			Email: user.Email, Username: user.Email, DisplayName: user.DisplayName,
		}); err != nil {
			return model.User{}, err
		}
	}
	return user, nil
}

func (r *MemoryRepository) SetUserDisabled(id string, disabled bool) (model.User, error) {
	user, err := r.GetUser(id)
	if err != nil {
		return model.User{}, err
	}
	if disabled {
		user.Status = "disabled"
		user.DisabledAt = time.Now().UTC()
	} else {
		user.Status = "active"
		user.DisabledAt = time.Time{}
	}
	return r.SaveUser(user)
}

func (r *MemoryRepository) SetUserPassword(id, passwordHash string) (model.User, error) {
	user, err := r.GetUser(id)
	if err != nil {
		return model.User{}, err
	}
	user.PasswordHash = passwordHash
	user.PasswordUpdatedAt = time.Now().UTC()
	return r.SaveUser(user)
}

func (r *MemoryRepository) TouchUserLogin(id string) (model.User, error) {
	user, err := r.GetUser(id)
	if err != nil {
		return model.User{}, err
	}
	user.LastLoginAt = time.Now().UTC()
	return r.SaveUser(user)
}

func (r *MemoryRepository) GetAuthIdentity(provider, subject string) (model.AuthIdentity, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	subject = strings.TrimSpace(subject)
	var found model.AuthIdentity
	for _, item := range r.identities {
		if item.Provider == provider && item.Subject == subject {
			if found.ID != "" {
				return model.AuthIdentity{}, ErrConflict
			}
			found = item
		}
	}
	if found.ID == "" {
		return model.AuthIdentity{}, ErrNotFound
	}
	return found, nil
}

func (r *MemoryRepository) GetAuthIdentityByIssuer(provider, issuer, subject string) (model.AuthIdentity, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	normalized, err := model.CanonicalAuthIssuer(provider, issuer)
	if err != nil {
		return model.AuthIdentity{}, err
	}
	subject = strings.TrimSpace(subject)
	for _, item := range r.identities {
		if item.Provider == provider && item.Issuer == normalized && item.Subject == subject {
			return item, nil
		}
	}
	return model.AuthIdentity{}, ErrNotFound
}

func (r *MemoryRepository) ListAuthIdentities(userID string) []model.AuthIdentity {
	items := make([]model.AuthIdentity, 0)
	for _, item := range r.identities {
		if userID == "" || item.UserID == userID {
			copy := item
			if item.Claims != nil {
				copy.Claims = make(map[string]any, len(item.Claims))
				for k, v := range item.Claims {
					copy.Claims[k] = v
				}
			}
			items = append(items, copy)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Provider == items[j].Provider {
			return items[i].Subject < items[j].Subject
		}
		return items[i].Provider < items[j].Provider
	})
	return items
}

func (r *MemoryRepository) SaveAuthIdentity(identity model.AuthIdentity) (model.AuthIdentity, error) {
	now := time.Now().UTC()
	identity.Provider = strings.ToLower(strings.TrimSpace(identity.Provider))
	var issuerErr error
	identity.Issuer, issuerErr = model.CanonicalAuthIssuer(identity.Provider, identity.Issuer)
	if issuerErr != nil {
		return model.AuthIdentity{}, issuerErr
	}
	identity.Subject = strings.TrimSpace(identity.Subject)
	identity.UserID = strings.TrimSpace(identity.UserID)
	if identity.Provider == "" || identity.Subject == "" || identity.UserID == "" {
		return model.AuthIdentity{}, fmt.Errorf("userId, provider и subject identity обязательны")
	}
	if _, err := r.GetUser(identity.UserID); err != nil {
		return model.AuthIdentity{}, err
	}
	for i := range r.identities {
		item := r.identities[i]
		if item.Provider == identity.Provider && item.Issuer == identity.Issuer && item.Subject == identity.Subject && item.UserID != identity.UserID {
			return model.AuthIdentity{}, fmt.Errorf("%w: identity %s/%s уже связана с другим пользователем", ErrConflict, identity.Provider, identity.Subject)
		}
		if item.UserID == identity.UserID && item.Provider == identity.Provider && item.Issuer == identity.Issuer {
			if item.Subject != identity.Subject {
				return model.AuthIdentity{}, fmt.Errorf("%w: provider %s уже связан с другим subject для пользователя", ErrConflict, identity.Provider)
			}
			if identity.ID == "" {
				identity.ID = item.ID
			}
			if identity.CreatedAt.IsZero() {
				identity.CreatedAt = item.CreatedAt
			}
			identity.UpdatedAt = now
			r.identities[i] = identity
			return identity, nil
		}
	}
	if identity.ID == "" {
		identity.ID = scopedAuthIdentityID0291(identity.Provider, identity.Issuer, identity.UserID)
	}
	identity.CreatedAt = now
	identity.UpdatedAt = now
	r.identities = append(r.identities, identity)
	return identity, nil
}

func (r *MemoryRepository) SaveFederatedUser(_ context.Context, user model.User, identity model.AuthIdentity) (model.User, model.AuthIdentity, error) {
	now := time.Now().UTC()
	user.ID = strings.TrimSpace(user.ID)
	user.Email = strings.TrimSpace(user.Email)
	identity.Provider = strings.ToLower(strings.TrimSpace(identity.Provider))
	var issuerErr error
	identity.Issuer, issuerErr = model.CanonicalAuthIssuer(identity.Provider, identity.Issuer)
	if issuerErr != nil {
		return model.User{}, model.AuthIdentity{}, issuerErr
	}
	identity.Subject = strings.TrimSpace(identity.Subject)
	if user.ID == "" || user.Email == "" || identity.Provider == "" || identity.Subject == "" {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("federated user id/email and provider/subject are required")
	}
	existingUserIndex := -1
	for i, existing := range r.users {
		if strings.EqualFold(existing.Email, user.Email) && existing.ID != user.ID {
			return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: canonical email is already used by another Never user", ErrConflict)
		}
		if existing.ID == user.ID {
			if !strings.EqualFold(existing.Email, user.Email) {
				return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: deterministic canonical user id already exists with another email", ErrConflict)
			}
			existingUserIndex = i
		}
	}
	for _, existing := range r.identities {
		if existing.UserID == user.ID && existing.Provider == identity.Provider && existing.Issuer == identity.Issuer && existing.Subject != identity.Subject {
			return model.User{}, model.AuthIdentity{}, ErrConflict
		}
		if existing.Provider == identity.Provider && existing.Issuer == identity.Issuer && existing.Subject == identity.Subject {
			if existing.UserID != user.ID {
				return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: external identity is already linked", ErrConflict)
			}
			canonical, err := r.GetUser(existing.UserID)
			return canonical, existing, err
		}
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.RoleID == "" {
		user.RoleID = "player"
	}
	if user.ProjectRoles == nil {
		user.ProjectRoles = map[string]string{}
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	if existingUserIndex >= 0 {
		user = r.users[existingUserIndex]
	} else {
		r.users = append(r.users, user)
	}
	identity.UserID = user.ID
	if identity.ID == "" {
		identity.ID = scopedAuthIdentityID0291(identity.Provider, identity.Issuer, user.ID)
	}
	identity.CreatedAt = now
	identity.UpdatedAt = now
	if identity.LastAuthenticatedAt.IsZero() {
		identity.LastAuthenticatedAt = now
	}
	r.identities = append(r.identities, identity)
	return user, identity, nil
}

func (r *MemoryRepository) TouchAuthIdentity(id string) (model.AuthIdentity, error) {
	for i := range r.identities {
		if r.identities[i].ID == id {
			r.identities[i].LastAuthenticatedAt = time.Now().UTC()
			r.identities[i].UpdatedAt = r.identities[i].LastAuthenticatedAt
			return r.identities[i], nil
		}
	}
	return model.AuthIdentity{}, ErrNotFound
}

func (r *MemoryRepository) ListRoles() []model.Role {
	items := append([]model.Role(nil), r.roles...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (r *MemoryRepository) ListAuditEvents() []model.AuditEvent {
	items := append([]model.AuditEvent(nil), r.audit...)
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (r *MemoryRepository) AddAuditEvent(event model.AuditEvent) {
	if event.ID == "" {
		event.ID = fmt.Sprintf("audit-%d", time.Now().UTC().UnixNano())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	r.audit = append(r.audit, event)
	r.auditSinkMu.RLock()
	sink := r.auditSink
	r.auditSinkMu.RUnlock()
	if sink != nil {
		sink(event)
	}
}

func (r *MemoryRepository) SetAuditEventSink(sink func(model.AuditEvent)) {
	r.auditSinkMu.Lock()
	r.auditSink = sink
	r.auditSinkMu.Unlock()
}

func (r *MemoryRepository) GetManifest(projectID, profileID, channel string) (model.Manifest, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	h, ok := r.channelHeads[headKey0228(projectID, profileID, channel)]
	if !ok || h.Revision == 0 {
		return model.Manifest{}, ErrNotFound
	}
	for _, rel := range r.releases {
		if rel.ID == h.ReleaseID && rel.ProjectID == projectID && rel.ProfileID == profileID && rel.Channel == channel && rel.Status == "published" {
			return cloneManifest0222(rel.Manifest), nil
		}
	}
	return model.Manifest{}, ErrNotFound
}

// PublishVersion only commits a previously signed draft. It does not regenerate
// timestamps or an unsigned manifest (which would invalidate Ed25519 signatures).
func (r *MemoryRepository) PublishVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	for _, release := range r.releases {
		if release.ProjectID == projectID && release.ProfileID == profileID && release.Channel == channel && release.Version == version {
			if release.Status == "published" {
				return model.ReleaseVersion{}, ErrImmutable
			}
			if release.Manifest.Signature == nil {
				return model.ReleaseVersion{}, ErrConflict
			}
			return r.PublishVersionWithManifest(projectID, profileID, channel, version, release.Manifest)
		}
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *MemoryRepository) PublishVersionWithManifest(projectID, profileID, channel, version string, manifest model.Manifest) (model.ReleaseVersion, error) {
	head, err := r.GetChannelHead(context.Background(), projectID, profileID, channel)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	return r.PublishVersionWithManifestCAS(projectID, profileID, channel, version, manifest, head.Revision)
}

func (r *MemoryRepository) PublishVersionWithManifestCAS(projectID, profileID, channel, version string, manifest model.Manifest, expected int64) (model.ReleaseVersion, error) {
	if IsStableChannel0341(channel) {
		return model.ReleaseVersion{}, ErrStableRuntimeGate0341
	}
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	if r.channelHeads[headKey0228(projectID, profileID, channel)].Revision != expected {
		return model.ReleaseVersion{}, ErrConflict
	}

	if _, err := r.GetProject(projectID); err != nil {
		return model.ReleaseVersion{}, err
	}
	now := time.Now().UTC()
	for i := range r.releases {
		item := &r.releases[i]
		if item.ProjectID != projectID || item.ProfileID != profileID || item.Channel != channel || item.Version != version {
			continue
		}
		if item.Status == "published" {
			return model.ReleaseVersion{}, ErrImmutable
		}
		manifest.ProjectID = projectID
		manifest.ProfileID = profileID
		manifest.Channel = channel
		manifest.Version = version
		if manifest.SchemaVersion == "" {
			manifest.SchemaVersion = "1.0"
		}
		if manifest.Files == nil {
			manifest.Files = []model.ManifestFile{}
		}
		if err := model.ValidateReleaseManifestTransition(item.Manifest, manifest); err != nil {
			return model.ReleaseVersion{}, err
		}
		item.Manifest = cloneManifest0222(manifest)
		item.Status = "published"
		item.PublishedAt = now
		raw, _ := json.Marshal(manifest)
		sum := sha256.Sum256(raw)
		key := headKey0228(projectID, profileID, channel)
		r.channelHeads[key] = model.ChannelHead{ProjectID: projectID, ProfileID: profileID, Channel: channel, Revision: expected + 1, ReleaseID: item.ID, Version: version, ManifestDigest: hex.EncodeToString(sum[:]), UpdatedAt: now}
		return cloneRelease0222(*item), nil
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *MemoryRepository) CreateVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	if _, err := r.GetProject(projectID); err != nil {
		return model.ReleaseVersion{}, err
	}
	if profileID == "" {
		profileID = "vanilla"
	}
	if channel == "" {
		channel = "dev"
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102150405")
	}
	for _, existing := range r.releases {
		if existing.ProjectID == projectID && existing.ProfileID == profileID && existing.Channel == channel && existing.Version == version {
			return model.ReleaseVersion{}, ErrConflict
		}
	}
	now := time.Now().UTC()
	snapshot, err := ReadProfileSnapshot(r, projectID, profileID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	manifest := model.Manifest{
		SchemaVersion:   model.ManifestSchemaV2,
		ProfileSnapshot: &snapshot,
		ProjectID:       projectID,
		ProfileID:       profileID,
		Channel:         channel,
		Version:         version,
		CreatedAt:       now.Format(time.RFC3339),
		Files:           []model.ManifestFile{},
	}
	release := model.ReleaseVersion{
		ID:          fmt.Sprintf("%s-%s-%s", projectID, profileID, version),
		ProjectID:   projectID,
		ProfileID:   profileID,
		Channel:     channel,
		Version:     version,
		Status:      "draft",
		Manifest:    manifest,
		PublishedAt: now,
	}
	r.releases = append(r.releases, cloneRelease0222(release))
	return cloneRelease0222(release), nil
}

// CreateVersionV3 creates an unsigned v3 draft with a content-addressed
// empty catalog. Existing v2 drafts/releases are never converted in place.
func (r *MemoryRepository) CreateVersionV3(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	release, err := r.CreateVersion(projectID, profileID, channel, version)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	for i := range r.releases {
		if r.releases[i].ID == release.ID && r.releases[i].ProjectID == projectID {
			r.releases[i].Manifest.SchemaVersion = model.ManifestSchemaV3
			catalog := model.NewComponentCatalog0241(nil, 1)
			r.releases[i].Manifest.ComponentCatalog = &catalog
			return cloneRelease0222(r.releases[i]), nil
		}
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *MemoryRepository) UpdateVersionStatus(projectID, versionID, status string) (model.ReleaseVersion, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return model.ReleaseVersion{}, errors.New("status обязателен")
	}
	// Status mutation is not a substitute for the transactional publish path.
	for i := range r.releases {
		if r.releases[i].ProjectID == projectID && r.releases[i].ID == versionID {
			if strings.EqualFold(status, "published") {
				if IsStableChannel0341(r.releases[i].Channel) {
					return model.ReleaseVersion{}, ErrStableRuntimeGate0341
				}
				return model.ReleaseVersion{}, ErrConflict
			}
			if r.releases[i].Status == "published" {
				return model.ReleaseVersion{}, ErrImmutable
			}
			r.releases[i].Status = status
			return cloneRelease0222(r.releases[i]), nil
		}
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *MemoryRepository) UpdateVersionManifest(projectID, versionID string, manifest model.Manifest) (model.ReleaseVersion, error) {
	for i := range r.releases {
		if r.releases[i].ProjectID == projectID && r.releases[i].ID == versionID {
			if r.releases[i].Status == "published" {
				return model.ReleaseVersion{}, ErrImmutable
			}
			manifest.ProjectID = projectID
			manifest.ProfileID = r.releases[i].ProfileID
			manifest.Channel = r.releases[i].Channel
			manifest.Version = r.releases[i].Version
			if manifest.SchemaVersion == "" {
				manifest.SchemaVersion = "1.0"
			}
			if manifest.Files == nil {
				manifest.Files = []model.ManifestFile{}
			}
			if err := model.ValidateReleaseManifestTransition(r.releases[i].Manifest, manifest); err != nil {
				return model.ReleaseVersion{}, err
			}
			r.releases[i].Manifest = cloneManifest0222(manifest)
			return cloneRelease0222(r.releases[i]), nil
		}
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *MemoryRepository) AddFile(file model.FileObject) (model.FileObject, error) {
	if _, err := r.GetProject(file.ProjectID); err != nil {
		return model.FileObject{}, err
	}
	for i := range r.releases {
		if r.releases[i].ProjectID == file.ProjectID && r.releases[i].ID == file.VersionID && r.releases[i].Status == "published" {
			return model.FileObject{}, ErrImmutable
		}
	}
	if file.ID == "" {
		file.ID = fmt.Sprintf("file-%d", time.Now().UTC().UnixNano())
	}
	if file.Ownership == "" {
		file.Ownership = "required"
	}
	file.Required = file.Ownership == "required" || file.Ownership == "managed"
	r.files = append(r.files, file)
	for i := range r.releases {
		if r.releases[i].ProjectID == file.ProjectID && r.releases[i].ID == file.VersionID {
			r.releases[i].Manifest.Files = append(r.releases[i].Manifest.Files, model.ManifestFile{
				Path:       file.Path,
				Size:       file.Size,
				SHA256:     file.SHA256,
				URL:        file.URL,
				Required:   file.Required,
				Executable: file.Executable,
				TargetOS:   append([]string(nil), file.TargetOS...),
				Mirrors:    append([]string(nil), file.Mirrors...),
				Ownership:  file.Ownership,
			})
			r.releases[i].Manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339)
			break
		}
	}
	return file, nil
}

func (r *MemoryRepository) ExportProject(projectID string) (map[string]any, error) {
	project, err := r.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	profiles, _ := r.ListProfiles(projectID)
	channels, _ := r.ListChannels(projectID)
	versions, _ := r.ListVersions(projectID)
	files, _ := r.ListFiles(projectID, "")
	return map[string]any{
		"schemaVersion": "1.0",
		"exportedAt":    time.Now().UTC(),
		"project":       project,
		"profiles":      profiles,
		"channels":      channels,
		"versions":      versions,
		"files":         files,
	}, nil
}

func (r *MemoryRepository) ImportProject(payload map[string]any) error {
	project, ok := payload["project"].(map[string]any)
	if !ok {
		return errors.New("поле project обязательно для импорта")
	}
	id, _ := project["id"].(string)
	name, _ := project["name"].(string)
	if id == "" || name == "" {
		return errors.New("импортируемый проект должен содержать id и name")
	}
	now := time.Now().UTC()
	r.projects = append(r.projects, model.Project{ID: id, Name: name, Description: fmt.Sprint(project["description"]), DefaultChannel: "stable", CreatedAt: now, UpdatedAt: now})
	return nil
}

func (r *MemoryRepository) AddTelemetryEvent(event model.TelemetryEvent) {
	if event.ID == "" {
		event.ID = fmt.Sprintf("telemetry-%d", time.Now().UTC().UnixNano())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	r.telemetry = append(r.telemetry, event)
}

func (r *MemoryRepository) AddCrashReport(report model.CrashReport) {
	if report.ID == "" {
		report.ID = fmt.Sprintf("crash-%d", time.Now().UTC().UnixNano())
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}
	r.crashes = append(r.crashes, report)
}

func (r *MemoryRepository) ListTelemetryEvents() []model.TelemetryEvent {
	items := append([]model.TelemetryEvent(nil), r.telemetry...)
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (r *MemoryRepository) ListCrashReports() []model.CrashReport {
	items := append([]model.CrashReport(nil), r.crashes...)
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (r *MemoryRepository) GetProviderCredential(userID, provider string) (model.ProviderCredential, error) {
	userID = strings.TrimSpace(userID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	var found model.ProviderCredential
	for _, item := range r.providerCredentials {
		if item.UserID == userID && item.Provider == provider {
			if found.ID != "" {
				return model.ProviderCredential{}, ErrConflict
			}
			found = item
		}
	}
	if found.ID == "" {
		return model.ProviderCredential{}, ErrNotFound
	}
	return found, nil
}

func (r *MemoryRepository) GetProviderCredentialByIdentity(userID, identityID string) (model.ProviderCredential, error) {
	for _, item := range r.providerCredentials {
		if item.UserID == strings.TrimSpace(userID) && item.IdentityID == strings.TrimSpace(identityID) {
			return item, nil
		}
	}
	return model.ProviderCredential{}, ErrNotFound
}

func (r *MemoryRepository) SaveProviderCredential(item model.ProviderCredential) (model.ProviderCredential, error) {
	item.UserID = strings.TrimSpace(item.UserID)
	item.IdentityID = strings.TrimSpace(item.IdentityID)
	item.Provider = strings.ToLower(strings.TrimSpace(item.Provider))
	item.Subject = strings.TrimSpace(item.Subject)
	item.EncryptedRefreshToken = strings.TrimSpace(item.EncryptedRefreshToken)
	if item.UserID == "" || item.IdentityID == "" || item.Provider == "" || item.Subject == "" || item.EncryptedRefreshToken == "" {
		return model.ProviderCredential{}, fmt.Errorf("provider credential fields are required")
	}
	if _, err := r.GetUser(item.UserID); err != nil {
		return model.ProviderCredential{}, err
	}
	var matched bool
	for _, identity := range r.identities {
		if identity.ID == item.IdentityID && identity.UserID == item.UserID && identity.Provider == item.Provider && identity.Subject == item.Subject {
			matched = true
			break
		}
	}
	if !matched {
		return model.ProviderCredential{}, fmt.Errorf("provider credential identity mismatch")
	}
	now := time.Now().UTC()
	for i := range r.providerCredentials {
		existing := r.providerCredentials[i]
		if existing.IdentityID == item.IdentityID && (existing.UserID != item.UserID || existing.Provider != item.Provider || existing.Subject != item.Subject) {
			return model.ProviderCredential{}, ErrConflict
		}
		if existing.IdentityID == item.IdentityID {
			item.ID = existing.ID
			item.CreatedAt = existing.CreatedAt
			item.UpdatedAt = now
			r.providerCredentials[i] = item
			return item, nil
		}
	}
	if item.ID == "" {
		item.ID = "provider-credential-" + item.IdentityID
	}
	item.CreatedAt = now
	item.UpdatedAt = now
	r.providerCredentials = append(r.providerCredentials, item)
	return item, nil
}

func (r *MemoryRepository) DeleteProviderCredential(userID, provider string) error {
	item, err := r.GetProviderCredential(userID, provider)
	if err != nil {
		return err
	}
	return r.DeleteProviderCredentialByIdentity(userID, item.IdentityID)
}

func (r *MemoryRepository) DeleteProviderCredentialByIdentity(userID, identityID string) error {
	for i, item := range r.providerCredentials {
		if item.UserID == strings.TrimSpace(userID) && item.IdentityID == strings.TrimSpace(identityID) {
			r.providerCredentials = append(r.providerCredentials[:i], r.providerCredentials[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (r *MemoryRepository) GetMinecraftProfileByUser(userID string) (model.MinecraftProfile, error) {
	userID = strings.TrimSpace(userID)
	for _, item := range r.minecraftProfiles {
		if item.UserID == userID {
			return item, nil
		}
	}
	return model.MinecraftProfile{}, ErrNotFound
}

func (r *MemoryRepository) GetMinecraftProfileByUUID(uuid string) (model.MinecraftProfile, error) {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	for _, item := range r.minecraftProfiles {
		if strings.EqualFold(item.UUID, uuid) {
			return item, nil
		}
	}
	return model.MinecraftProfile{}, ErrNotFound
}

func (r *MemoryRepository) GetMinecraftProfileByName(name string) (model.MinecraftProfile, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, item := range r.minecraftProfiles {
		if strings.ToLower(item.Name) == name {
			return item, nil
		}
	}
	return model.MinecraftProfile{}, ErrNotFound
}

func (r *MemoryRepository) SaveMinecraftProfile(item model.MinecraftProfile) (model.MinecraftProfile, error) {
	item.UserID = strings.TrimSpace(item.UserID)
	item.UUID = strings.ToLower(strings.TrimSpace(item.UUID))
	item.Name = strings.TrimSpace(item.Name)
	item.Issuer = strings.ToLower(strings.TrimSpace(item.Issuer))
	item.Realm = strings.ToLower(strings.TrimSpace(item.Realm))
	item.Subject = strings.TrimSpace(item.Subject)
	item.IdentityVersion = strings.TrimSpace(item.IdentityVersion)
	if item.Issuer == "" {
		item.Issuer = "neverlauncher"
	}
	if item.Realm == "" {
		item.Realm = "local"
	}
	if item.Subject == "" {
		item.Subject = item.UUID
	}
	if item.IdentityVersion == "" {
		item.IdentityVersion = "independent-v1"
	}
	if item.UserID == "" || item.UUID == "" || item.Name == "" {
		return model.MinecraftProfile{}, fmt.Errorf("minecraft profile fields are required")
	}
	if _, err := r.GetUser(item.UserID); err != nil {
		return model.MinecraftProfile{}, err
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	for i, existing := range r.minecraftProfiles {
		if existing.UserID == item.UserID || strings.EqualFold(existing.UUID, item.UUID) || strings.EqualFold(existing.Name, item.Name) {
			if existing.UserID != item.UserID || !strings.EqualFold(existing.UUID, item.UUID) || existing.Issuer != item.Issuer || existing.Realm != item.Realm || existing.Subject != item.Subject {
				return model.MinecraftProfile{}, ErrConflict
			}
			item.CreatedAt = existing.CreatedAt
			r.minecraftProfiles[i] = item
			return item, nil
		}
	}
	r.minecraftProfiles = append(r.minecraftProfiles, item)
	return item, nil
}

func (r *MemoryRepository) SaveMinecraftSession(item model.MinecraftSession) (model.MinecraftSession, error) {
	item.ID = strings.TrimSpace(item.ID)
	item.UserID = strings.TrimSpace(item.UserID)
	item.NeverSessionID = strings.TrimSpace(item.NeverSessionID)
	item.ProfileUUID = strings.ToLower(strings.TrimSpace(item.ProfileUUID))
	item.TrustedDeviceID = strings.TrimSpace(item.TrustedDeviceID)
	if item.BindingEpoch < 1 {
		item.BindingEpoch = 1
	}
	item.AccessTokenHash = strings.TrimSpace(item.AccessTokenHash)
	if item.ID == "" || item.UserID == "" || item.NeverSessionID == "" || item.ProfileUUID == "" || item.AccessTokenHash == "" {
		return model.MinecraftSession{}, fmt.Errorf("minecraft session fields are required")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.LastSeenAt.IsZero() {
		item.LastSeenAt = now
	}
	if item.Status == "" {
		item.Status = "active"
	}
	for i, existing := range r.minecraftSessions {
		if existing.ID == item.ID {
			r.minecraftSessions[i] = item
			return item, nil
		}
		if existing.AccessTokenHash == item.AccessTokenHash {
			return model.MinecraftSession{}, ErrConflict
		}
	}
	r.minecraftSessions = append(r.minecraftSessions, item)
	return item, nil
}

func (r *MemoryRepository) GetMinecraftSessionByTokenHash(hash string) (model.MinecraftSession, error) {
	for _, item := range r.minecraftSessions {
		if item.AccessTokenHash == strings.TrimSpace(hash) {
			return item, nil
		}
	}
	return model.MinecraftSession{}, ErrNotFound
}

func (r *MemoryRepository) TouchMinecraftSession(id string) (model.MinecraftSession, error) {
	for i, item := range r.minecraftSessions {
		if item.ID == id {
			item.LastSeenAt = time.Now().UTC()
			r.minecraftSessions[i] = item
			return item, nil
		}
	}
	return model.MinecraftSession{}, ErrNotFound
}

func (r *MemoryRepository) RevokeMinecraftSession(id, reason string) error {
	for i, item := range r.minecraftSessions {
		if item.ID != id {
			continue
		}
		if item.Status != "active" {
			return ErrConflict
		}
		item.Status = "revoked"
		item.RevokedAt = time.Now().UTC()
		item.RevokedReason = strings.TrimSpace(reason)
		r.minecraftSessions[i] = item
		return nil
	}
	return ErrNotFound
}

func (r *MemoryRepository) RevokeMinecraftSessionsByNeverSession(neverSessionID, reason string) int {
	count := 0
	now := time.Now().UTC()
	for i, item := range r.minecraftSessions {
		if item.NeverSessionID == neverSessionID && item.Status == "active" {
			item.Status = "revoked"
			item.RevokedAt = now
			item.RevokedReason = reason
			r.minecraftSessions[i] = item
			count++
		}
	}
	return count
}

func (r *MemoryRepository) RevokeMinecraftSessionsByUser(userID, reason string) int {
	count := 0
	now := time.Now().UTC()
	for i, item := range r.minecraftSessions {
		if item.UserID == userID && item.Status == "active" {
			item.Status = "revoked"
			item.RevokedAt = now
			item.RevokedReason = reason
			r.minecraftSessions[i] = item
			count++
		}
	}
	return count
}

func (r *MemoryRepository) GetMinecraftSession(id string) (model.MinecraftSession, error) {
	for _, item := range r.minecraftSessions {
		if item.ID == strings.TrimSpace(id) {
			return item, nil
		}
	}
	return model.MinecraftSession{}, ErrNotFound
}

func (r *MemoryRepository) SaveMinecraftJoin(item model.MinecraftJoin) error {
	item.Username = strings.TrimSpace(item.Username)
	item.UsernameNormalized = strings.ToLower(item.Username)
	item.ProfileUUID = strings.ToLower(strings.TrimSpace(item.ProfileUUID))
	item.ServerID = strings.TrimSpace(item.ServerID)
	if item.Username == "" || item.ProfileUUID == "" || item.UserID == "" || item.MinecraftSessionID == "" || item.ServerID == "" {
		return fmt.Errorf("minecraft join fields are required")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.ExpiresAt.IsZero() {
		item.ExpiresAt = now.Add(2 * time.Minute)
	}
	item.TicketVersion = 2
	item.Status = "active"
	item.ConsumedAt = time.Time{}
	r.minecraftMu.Lock()
	defer r.minecraftMu.Unlock()
	for i, existing := range r.minecraftJoins {
		if existing.UsernameNormalized == item.UsernameNormalized && existing.ServerID == item.ServerID {
			r.minecraftJoins[i] = item
			return nil
		}
	}
	r.minecraftJoins = append(r.minecraftJoins, item)
	return nil
}

func (r *MemoryRepository) GetMinecraftJoin(username, serverID string) (model.MinecraftJoin, error) {
	name := strings.ToLower(strings.TrimSpace(username))
	sid := strings.TrimSpace(serverID)
	now := time.Now().UTC()
	r.minecraftMu.Lock()
	defer r.minecraftMu.Unlock()
	for _, item := range r.minecraftJoins {
		if item.UsernameNormalized == name && item.ServerID == sid && item.TicketVersion == 2 && item.Status == "active" && item.ExpiresAt.After(now) {
			return item, nil
		}
	}
	return model.MinecraftJoin{}, ErrNotFound
}

func (r *MemoryRepository) ConsumeMinecraftJoin(username, serverID, expectedSessionID string, now time.Time) (model.MinecraftJoin, error) {
	name := strings.ToLower(strings.TrimSpace(username))
	sid := strings.TrimSpace(serverID)
	expectedSessionID = strings.TrimSpace(expectedSessionID)
	r.minecraftMu.Lock()
	defer r.minecraftMu.Unlock()
	for i, item := range r.minecraftJoins {
		if item.UsernameNormalized != name || item.ServerID != sid || item.MinecraftSessionID != expectedSessionID || item.TicketVersion != 2 || item.Status != "active" || !item.ExpiresAt.After(now) {
			continue
		}
		item.Status = "consumed"
		item.ConsumedAt = now.UTC()
		r.minecraftJoins[i] = item
		return item, nil
	}
	return model.MinecraftJoin{}, ErrConflict
}
