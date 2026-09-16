package repository

import (
	"context"
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
	ListAuthIdentities(userID string) []model.AuthIdentity
	SaveAuthIdentity(identity model.AuthIdentity) (model.AuthIdentity, error)
	SaveFederatedUser(ctx context.Context, user model.User, identity model.AuthIdentity) (model.User, model.AuthIdentity, error)
	TouchAuthIdentity(id string) (model.AuthIdentity, error)
	SaveTrustedDevice(ctx context.Context, device model.TrustedDevice) (model.TrustedDevice, error)
	GetTrustedDevice(userID, deviceID string) (model.TrustedDevice, error)
	GetTrustedDeviceByID(deviceID string) (model.TrustedDevice, error)
	ListTrustedDevices(userID, status string) []model.TrustedDevice
	RenameTrustedDevice(userID, deviceID, name string) (model.TrustedDevice, error)
	RevokeTrustedDevice(ctx context.Context, userID, deviceID, reason string) (model.TrustedDevice, error)
	TouchTrustedDevice(ctx context.Context, userID, deviceID, ip, userAgent string) (model.TrustedDevice, error)
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
	AddFile(file model.FileObject) (model.FileObject, error)
	ExportProject(projectID string) (map[string]any, error)
	ImportProject(payload map[string]any) error
	AddTelemetryEvent(event model.TelemetryEvent)
	AddCrashReport(report model.CrashReport)
	ListTelemetryEvents() []model.TelemetryEvent
	ListCrashReports() []model.CrashReport
}

type MemoryRepository struct {
	deviceMu            sync.Mutex
	projects            []model.Project
	profiles            []model.Profile
	channels            []model.ReleaseChannel
	releases            []model.ReleaseVersion
	files               []model.FileObject
	users               []model.User
	identities          []model.AuthIdentity
	providerCredentials []model.ProviderCredential
	minecraftProfiles   []model.MinecraftProfile
	minecraftSessions   []model.MinecraftSession
	minecraftJoins      []model.MinecraftJoin
	trustedDevices      []model.TrustedDevice
	deviceChallenges    []model.DeviceChallenge
	roles               []model.Role
	audit               []model.AuditEvent
	telemetry           []model.TelemetryEvent
	crashes             []model.CrashReport
}

func NewMemoryRepository(publicURL string) *MemoryRepository {
	now := time.Now().UTC()
	manifest := model.Manifest{
		SchemaVersion: "1.0",
		ProjectID:     "demo-project",
		ProfileID:     "vanilla",
		Channel:       "stable",
		Version:       "3.4.0",
		CreatedAt:     now.Format(time.RFC3339),
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
			{ID: "admin", Name: "Администратор", Description: "Управление проектами, версиями, файлами, пользователями и аудитом", Permissions: []string{"project:read", "project:write", "release:prepare", "release:publish", "file:write", "users:manage", "roles:manage", "audit:read", "diagnostics:read", "storage:manage", "settings:manage", "security:read", "extension:manage"}},
			{ID: "release-manager", Name: "Release Manager", Description: "Подготовка, публикация и откат релизов", Permissions: []string{"project:read", "release:prepare", "release:publish", "audit:read"}},
			{ID: "support", Name: "Поддержка", Description: "Диагностика, чтение проекта и отзыв проблемных сессий", Permissions: []string{"project:read", "diagnostics:read", "sessions:revoke", "audit:read"}},
			{ID: "developer", Name: "Разработчик", Description: "Подготовка версий и загрузка файлов", Permissions: []string{"project:read", "release:prepare", "file:write"}},
			{ID: "viewer", Name: "Наблюдатель", Description: "Только чтение", Permissions: []string{"project:read"}},
			{ID: "player", Name: "Игрок", Description: "Вход в desktop и запуск доступных профилей", Permissions: []string{"launcher:login", "profile:download", "profile:launch"}},
		},
		users: []model.User{
			{ID: "admin", Email: "admin@neverlauncher.local", DisplayName: "Администратор", RoleID: "owner", Status: "active", ProjectRoles: map[string]string{"demo-project": "owner"}, PasswordHash: "sha256:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", PasswordUpdatedAt: now, CreatedAt: now, UpdatedAt: now},
		},
		identities: []model.AuthIdentity{
			{ID: "identity-local-admin", UserID: "admin", Provider: "local", Subject: "admin", Email: "admin@neverlauncher.local", Username: "admin@neverlauncher.local", DisplayName: "Администратор", CreatedAt: now, UpdatedAt: now},
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
	var result []model.Profile
	for _, item := range r.profiles {
		if item.ProjectID == projectID {
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
	now := time.Now().UTC()
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.ID == "" {
		profile.ID = strings.ToLower(strings.ReplaceAll(profile.Name, " ", "-"))
	}
	if profile.ID == "" || profile.ProjectID == "" || profile.Name == "" {
		return model.Profile{}, fmt.Errorf("projectId, id и name профиля обязательны")
	}
	if profile.Loader == "" {
		profile.Loader = "vanilla"
	}
	for i := range r.profiles {
		if r.profiles[i].ProjectID == profile.ProjectID && r.profiles[i].ID == profile.ID {
			if profile.CreatedAt.IsZero() {
				profile.CreatedAt = r.profiles[i].CreatedAt
			}
			profile.UpdatedAt = now
			r.profiles[i] = profile
			return profile, nil
		}
	}
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}
	r.profiles = append(r.profiles, profile)
	return profile, nil
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
			result = append(result, item)
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
	if user.ProjectRoles == nil {
		user.ProjectRoles = map[string]string{}
	}
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
	for _, item := range r.identities {
		if item.Provider == provider && item.Subject == subject {
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
		if item.Provider == identity.Provider && item.Subject == identity.Subject && item.UserID != identity.UserID {
			return model.AuthIdentity{}, fmt.Errorf("identity %s/%s уже связана с другим пользователем", identity.Provider, identity.Subject)
		}
		if item.UserID == identity.UserID && item.Provider == identity.Provider {
			if item.Subject != identity.Subject {
				return model.AuthIdentity{}, fmt.Errorf("provider %s уже связан с другим subject для пользователя", identity.Provider)
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
		identity.ID = "identity-" + identity.Provider + "-" + identity.UserID
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
		if existing.Provider == identity.Provider && existing.Subject == identity.Subject {
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
		identity.ID = "identity-" + identity.Provider + "-" + user.ID
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
}

func (r *MemoryRepository) GetManifest(projectID, profileID, channel string) (model.Manifest, error) {
	var latest *model.ReleaseVersion
	for i := range r.releases {
		item := &r.releases[i]
		if item.ProjectID == projectID && item.ProfileID == profileID && item.Channel == channel && item.Status == "published" {
			if latest == nil || item.PublishedAt.After(latest.PublishedAt) {
				latest = item
			}
		}
	}
	if latest != nil {
		return latest.Manifest, nil
	}
	for i := range r.releases {
		item := &r.releases[i]
		if item.ProjectID == projectID && item.ProfileID == profileID && item.Channel == channel {
			if latest == nil || item.PublishedAt.After(latest.PublishedAt) {
				latest = item
			}
		}
	}
	if latest != nil {
		return latest.Manifest, nil
	}
	return model.Manifest{}, ErrNotFound
}

func (r *MemoryRepository) PublishVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	if _, err := r.GetProject(projectID); err != nil {
		return model.ReleaseVersion{}, err
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102150405")
	}
	for i := range r.releases {
		if r.releases[i].ProjectID == projectID && r.releases[i].ProfileID == profileID && r.releases[i].Channel == channel && r.releases[i].Version == version {
			if r.releases[i].Status == "published" {
				return model.ReleaseVersion{}, ErrImmutable
			}
			r.releases[i].Status = "published"
			r.releases[i].PublishedAt = time.Now().UTC()
			r.releases[i].Manifest.Version = version
			r.releases[i].Manifest.Channel = channel
			return r.releases[i], nil
		}
	}
	manifest, err := r.GetManifest(projectID, profileID, channel)
	if err != nil {
		manifest = model.Manifest{SchemaVersion: "1.0", ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, CreatedAt: time.Now().UTC().Format(time.RFC3339), Files: []model.ManifestFile{}}
	}
	manifest.Version = version
	manifest.Channel = channel
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	release := model.ReleaseVersion{ID: fmt.Sprintf("%s-%s-%s", projectID, profileID, version), ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, Status: "published", Manifest: manifest, PublishedAt: time.Now().UTC()}
	r.releases = append(r.releases, release)
	return release, nil
}

func (r *MemoryRepository) PublishVersionWithManifest(projectID, profileID, channel, version string, manifest model.Manifest) (model.ReleaseVersion, error) {
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
		item.Manifest = manifest
		item.Status = "published"
		item.PublishedAt = now
		return *item, nil
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
	now := time.Now().UTC()
	manifest := model.Manifest{
		SchemaVersion: "1.0",
		ProjectID:     projectID,
		ProfileID:     profileID,
		Channel:       channel,
		Version:       version,
		CreatedAt:     now.Format(time.RFC3339),
		Files:         []model.ManifestFile{},
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
	r.releases = append(r.releases, release)
	return release, nil
}

func (r *MemoryRepository) UpdateVersionStatus(projectID, versionID, status string) (model.ReleaseVersion, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return model.ReleaseVersion{}, errors.New("status обязателен")
	}
	for i := range r.releases {
		if r.releases[i].ProjectID == projectID && r.releases[i].ID == versionID {
			if r.releases[i].Status == "published" {
				return model.ReleaseVersion{}, ErrImmutable
			}
			r.releases[i].Status = status
			return r.releases[i], nil
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
			r.releases[i].Manifest = manifest
			return r.releases[i], nil
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
	if file.Required == false {
		file.Required = true
	}
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
	for _, item := range r.providerCredentials {
		if item.UserID == userID && item.Provider == provider {
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
	identity, err := r.GetAuthIdentity(item.Provider, item.Subject)
	if err != nil || identity.UserID != item.UserID || identity.ID != item.IdentityID {
		return model.ProviderCredential{}, fmt.Errorf("provider credential identity mismatch")
	}
	now := time.Now().UTC()
	for i := range r.providerCredentials {
		existing := r.providerCredentials[i]
		if existing.Provider == item.Provider && existing.Subject == item.Subject && existing.UserID != item.UserID {
			return model.ProviderCredential{}, ErrConflict
		}
		if existing.UserID == item.UserID && existing.Provider == item.Provider {
			item.ID = existing.ID
			item.CreatedAt = existing.CreatedAt
			item.UpdatedAt = now
			r.providerCredentials[i] = item
			return item, nil
		}
	}
	if item.ID == "" {
		item.ID = "provider-credential-" + item.Provider + "-" + item.UserID
	}
	item.CreatedAt = now
	item.UpdatedAt = now
	r.providerCredentials = append(r.providerCredentials, item)
	return item, nil
}

func (r *MemoryRepository) DeleteProviderCredential(userID, provider string) error {
	userID = strings.TrimSpace(userID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	for i, item := range r.providerCredentials {
		if item.UserID == userID && item.Provider == provider {
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
			if existing.UserID != item.UserID {
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
	for _, item := range r.minecraftJoins {
		if item.UsernameNormalized == name && item.ServerID == sid && item.ExpiresAt.After(now) {
			return item, nil
		}
	}
	return model.MinecraftJoin{}, ErrNotFound
}
