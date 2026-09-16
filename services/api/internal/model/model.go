package model

import "time"

// Project описывает Minecraft-проект, который использует NeverLauncher.
type Project struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Homepage       string    `json:"homepage"`
	Repository     string    `json:"repository"`
	DefaultChannel string    `json:"defaultChannel"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// Profile описывает клиентский профиль проекта.
type Profile struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Loader      string    `json:"loader"`
	Preset      string    `json:"preset"`
	IsDefault   bool      `json:"isDefault"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ReleaseChannel описывает канал релиза: dev, beta или stable.
type ReleaseChannel struct {
	ID          string `json:"id"`
	ProjectID   string `json:"projectId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protected   bool   `json:"protected"`
}

// ReleaseVersion описывает опубликованную версию клиентского профиля.
type ReleaseVersion struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	ProfileID   string    `json:"profileId"`
	Channel     string    `json:"channel"`
	Version     string    `json:"version"`
	Status      string    `json:"status"`
	Manifest    Manifest  `json:"manifest"`
	PublishedAt time.Time `json:"publishedAt"`
}

// FileObject описывает файл клиентской сборки.
type FileObject struct {
	ID         string   `json:"id"`
	ProjectID  string   `json:"projectId"`
	VersionID  string   `json:"versionId"`
	Path       string   `json:"path"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	URL        string   `json:"url"`
	Required   bool     `json:"required"`
	Executable bool     `json:"executable,omitempty"`
	TargetOS   []string `json:"targetOs,omitempty"`
}

// User описывает пользователя backend/admin panel.
type User struct {
	ID                string            `json:"id"`
	Email             string            `json:"email"`
	DisplayName       string            `json:"displayName"`
	RoleID            string            `json:"roleId"`
	Status            string            `json:"status"`
	ProjectRoles      map[string]string `json:"projectRoles,omitempty"`
	PasswordHash      string            `json:"-"`
	PasswordUpdatedAt time.Time         `json:"passwordUpdatedAt,omitempty"`
	LastLoginAt       time.Time         `json:"lastLoginAt,omitempty"`
	DisabledAt        time.Time         `json:"disabledAt,omitempty"`
	CreatedAt         time.Time         `json:"createdAt"`
	UpdatedAt         time.Time         `json:"updatedAt"`
}

// AuthIdentity связывает канонического Never user с subject конкретного auth provider.
// Внешний provider никогда не заменяет User: federation core всегда разрешает identity
// в локальный User до выпуска Never session/token.
type AuthIdentity struct {
	ID                  string         `json:"id"`
	UserID              string         `json:"userId"`
	Provider            string         `json:"provider"`
	Subject             string         `json:"subject"`
	Email               string         `json:"email,omitempty"`
	Username            string         `json:"username,omitempty"`
	DisplayName         string         `json:"displayName,omitempty"`
	Claims              map[string]any `json:"claims,omitempty"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
	LastAuthenticatedAt time.Time      `json:"lastAuthenticatedAt,omitempty"`
}

// Role описывает роль пользователя в проекте.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// AdminSession описывает сессию панели управления с Bearer-токеном доступа.
type AdminSession struct {
	Token            string    `json:"token"`
	RefreshToken     string    `json:"refreshToken,omitempty"`
	SessionID        string    `json:"sessionId,omitempty"`
	User             User      `json:"user"`
	ExpiresAt        time.Time `json:"expiresAt"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt,omitempty"`
}

// Manifest — минимальная структура манифеста, которую backend отдаёт desktop client.
type Manifest struct {
	SchemaVersion string         `json:"schemaVersion"`
	ProjectID     string         `json:"projectId"`
	ProfileID     string         `json:"profileId"`
	Channel       string         `json:"channel"`
	Version       string         `json:"version"`
	CreatedAt     string         `json:"createdAt"`
	Minecraft     MinecraftInfo  `json:"minecraft"`
	Runtime       RuntimeInfo    `json:"runtime"`
	Directories   Directories    `json:"directories,omitempty"`
	Files         []ManifestFile `json:"files"`
	Signature     *SignatureInfo `json:"signature,omitempty"`
}

// SignatureInfo описывает подпись манифеста Ed25519.
type SignatureInfo struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signedAt"`
}

// AuditEvent описывает запись журнала безопасности и административных действий.
type AuditEvent struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
}

type MinecraftInfo struct {
	Version       string   `json:"version"`
	Loader        string   `json:"loader"`
	LoaderVersion string   `json:"loaderVersion,omitempty"`
	MainClass     string   `json:"mainClass,omitempty"`
	GameArgs      []string `json:"gameArgs,omitempty"`
}

type RuntimeInfo struct {
	Java    JavaInfo      `json:"java"`
	JVMArgs []string      `json:"jvmArgs,omitempty"`
	Memory  MemoryInfo    `json:"memory,omitempty"`
	Launch  RuntimeLaunch `json:"launch,omitempty"`
}

type JavaInfo struct {
	MajorVersion    int    `json:"majorVersion"`
	Distribution    string `json:"distribution"`
	AllowCustomPath bool   `json:"allowCustomPath,omitempty"`
}

type RuntimeLaunch struct {
	MainClass           string          `json:"mainClass,omitempty"`
	ClasspathStrategy   string          `json:"classpathStrategy,omitempty"`
	NativesDirectory    string          `json:"nativesDirectory,omitempty"`
	VersionMetadataPath string          `json:"versionMetadataPath,omitempty"`
	Features            map[string]bool `json:"features,omitempty"`
	OfflineMode         bool            `json:"offlineMode,omitempty"`
}

type MemoryInfo struct {
	MinimumMb     int `json:"minimumMb,omitempty"`
	RecommendedMb int `json:"recommendedMb,omitempty"`
	MaximumMb     int `json:"maximumMb,omitempty"`
}

type Directories struct {
	Game      string `json:"game,omitempty"`
	Assets    string `json:"assets,omitempty"`
	Libraries string `json:"libraries,omitempty"`
	Natives   string `json:"natives,omitempty"`
}

type ManifestFile struct {
	Path       string   `json:"path"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	URL        string   `json:"url"`
	Required   bool     `json:"required"`
	Executable bool     `json:"executable"`
	TargetOS   []string `json:"targetOs,omitempty"`
}

// TelemetryEvent описывает минимальное событие телеметрии без персональных данных.
type TelemetryEvent struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"projectId"`
	ProfileID       string    `json:"profileId"`
	LauncherVersion string    `json:"launcherVersion"`
	ProfileVersion  string    `json:"profileVersion"`
	Event           string    `json:"event"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
}

// CrashReport описывает локальный отчёт об ошибке запуска, отправленный пользователем добровольно.
type CrashReport struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"projectId"`
	ProfileID       string    `json:"profileId"`
	LauncherVersion string    `json:"launcherVersion"`
	ProfileVersion  string    `json:"profileVersion"`
	Message         string    `json:"message"`
	Log             string    `json:"log,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
}

// ProviderCredential stores an opaque external-provider credential only after it
// has been encrypted by the auth service. Plaintext provider tokens must never be
// persisted by Repository implementations or exposed through API models.
type ProviderCredential struct {
	ID                    string    `json:"id"`
	UserID                string    `json:"userId"`
	IdentityID            string    `json:"identityId"`
	Provider              string    `json:"provider"`
	Subject               string    `json:"subject"`
	EncryptedRefreshToken string    `json:"-"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
	LastRefreshedAt       time.Time `json:"lastRefreshedAt,omitempty"`
}

// MinecraftProfile is the stable Minecraft identity owned by a canonical Never user.
// UUID/name are independent from mutable email and from any external provider subject.
type MinecraftProfile struct {
	UserID    string    `json:"userId"`
	UUID      string    `json:"uuid"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// MinecraftSession is an opaque Minecraft/Yggdrasil session derived from a Never
// session. AccessTokenHash is the only persisted representation of the bearer token.
type MinecraftSession struct {
	ID              string    `json:"id"`
	UserID          string    `json:"userId"`
	NeverSessionID  string    `json:"neverSessionId"`
	ProfileUUID     string    `json:"profileUuid"`
	ClientToken     string    `json:"clientToken,omitempty"`
	AccessTokenHash string    `json:"-"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	LastSeenAt      time.Time `json:"lastSeenAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	RevokedAt       time.Time `json:"revokedAt,omitempty"`
	RevokedReason   string    `json:"revokedReason,omitempty"`
}

// MinecraftJoin is the short-lived proof created by the client /join call and
// consumed by a Minecraft server through /hasJoined.
type MinecraftJoin struct {
	Username           string    `json:"username"`
	UsernameNormalized string    `json:"-"`
	ProfileUUID        string    `json:"profileUuid"`
	UserID             string    `json:"userId"`
	MinecraftSessionID string    `json:"minecraftSessionId"`
	ServerID           string    `json:"serverId"`
	IP                 string    `json:"ip,omitempty"`
	CreatedAt          time.Time `json:"createdAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
}
