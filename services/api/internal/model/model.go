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
	SchemaVersion    string    `json:"schemaVersion,omitempty"`
	Revision         int64     `json:"revision,omitempty"`
	Digest           string    `json:"digest,omitempty"`
	ID               string    `json:"id"`
	ProjectID        string    `json:"projectId"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Loader           string    `json:"loader"`
	MinecraftVersion string    `json:"minecraftVersion,omitempty"`
	LoaderVersion    string    `json:"loaderVersion,omitempty"`
	JavaMajor        int       `json:"javaMajor,omitempty"`
	Preset           string    `json:"preset"`
	IsDefault        bool      `json:"isDefault"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
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
	Mirrors    []string `json:"mirrors,omitempty"`
	Required   bool     `json:"required"`
	Executable bool     `json:"executable,omitempty"`
	TargetOS   []string `json:"targetOs,omitempty"`
	Ownership  string   `json:"ownership,omitempty"`
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

// AuthIdentity связывает канонического пользователя Never с идентификатором внешнего провайдера аутентификации.
// Внешний провайдер не заменяет User: ядро федерации сначала сопоставляет внешнюю идентичность
// с локальным User, а затем выдаёт сеанс и токен Never.
type AuthIdentity struct {
	ID                  string         `json:"id"`
	UserID              string         `json:"userId"`
	Provider            string         `json:"provider"`
	Issuer              string         `json:"issuer"`
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
	SchemaVersion         string                   `json:"schemaVersion"`
	ProjectID             string                   `json:"projectId"`
	ProfileID             string                   `json:"profileId"`
	Channel               string                   `json:"channel"`
	Version               string                   `json:"version"`
	GameReleaseGeneration uint64                   `json:"gameReleaseGeneration,omitempty"`
	TrustEpoch            uint64                   `json:"trustEpoch,omitempty"`
	RollbackSource        *GameRollbackSource02311 `json:"rollbackSource,omitempty"`
	CreatedAt             string                   `json:"createdAt"`
	Minecraft             MinecraftInfo            `json:"minecraft"`
	Runtime               RuntimeInfo              `json:"runtime"`
	Directories           Directories              `json:"directories,omitempty"`
	Files                 []ManifestFile           `json:"files"`
	FileRules             []FileRule               `json:"fileRules,omitempty"`
	ProfileSnapshot       *ProfileSnapshot         `json:"profileSnapshot,omitempty"`
	ComponentCatalog      *ComponentCatalog0241    `json:"componentCatalog,omitempty"`
	Signature             *SignatureInfo           `json:"signature,omitempty"`
}

// GameRollbackSource02311 binds a newly authorized release generation to the
// historical *signed* manifest whose content is intentionally being restored.
type GameRollbackSource02311 struct {
	Version               string `json:"version"`
	ManifestSHA256        string `json:"manifestSha256"`
	GameReleaseGeneration uint64 `json:"gameReleaseGeneration"`
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
	ID            string    `json:"id"`
	Actor         string    `json:"actor"`
	Action        string    `json:"action"`
	Target        string    `json:"target"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"userAgent"`
	CreatedAt     time.Time `json:"createdAt"`
	CorrelationID string    `json:"correlationId,omitempty"`
	ReasonCode    string    `json:"reasonCode,omitempty"`
	JobID         string    `json:"jobId,omitempty"`
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
	MajorVersion            int    `json:"majorVersion"`
	MinimumMajorVersion     int    `json:"minimumMajorVersion,omitempty"`
	RecommendedMajorVersion int    `json:"recommendedMajorVersion,omitempty"`
	MaximumMajorVersion     int    `json:"maximumMajorVersion,omitempty"`
	Distribution            string `json:"distribution"`
	AllowCustomPath         bool   `json:"allowCustomPath,omitempty"`
}

type RuntimeLaunch struct {
	MainClass            string          `json:"mainClass,omitempty"`
	ClasspathStrategy    string          `json:"classpathStrategy,omitempty"`
	NativesDirectory     string          `json:"nativesDirectory,omitempty"`
	VersionMetadataPath  string          `json:"versionMetadataPath,omitempty"`
	ClasspathEntries     []string        `json:"classpathEntries,omitempty"`
	ModulepathEntries    []string        `json:"modulepathEntries,omitempty"`
	MainModule           string          `json:"mainModule,omitempty"`
	EnvironmentAllowlist []string        `json:"environmentAllowlist,omitempty"`
	Features             map[string]bool `json:"features,omitempty"`
	OfflineMode          bool            `json:"offlineMode,omitempty"`
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
	Mirrors    []string `json:"mirrors,omitempty"`
	Required   bool     `json:"required"`
	Executable bool     `json:"executable"`
	TargetOS   []string `json:"targetOs,omitempty"`
	Ownership  string   `json:"ownership,omitempty"`
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

// ProviderCredential хранит непрозрачные внешние учётные данные только
// после шифрования сервисом аутентификации. Реализации Repository не
// должны сохранять открытые токены или раскрывать их через модели API.
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

// TrustedDevice — каноническая идентичность устройства пользователя
// Never. PublicKey хранит сырой открытый Ed25519-ключ в base64url;
// ответы API намеренно показывают только KeyFingerprint.
type TrustedDevice struct {
	ID                       string          `json:"id"`
	UserID                   string          `json:"userId"`
	Name                     string          `json:"name"`
	Status                   string          `json:"status"`
	TrustState               string          `json:"trustState"`
	Assurance                string          `json:"assurance"`
	KeyAlgorithm             string          `json:"keyAlgorithm"`
	KeyBinding               string          `json:"keyBinding"`
	HardwareProvider         string          `json:"hardwareProvider,omitempty"`
	RemoteHardwareProvenance string          `json:"remoteHardwareProvenance"`
	AttestationState         string          `json:"attestationState"`
	AttestationMethod        string          `json:"attestationMethod,omitempty"`
	AttestedAt               time.Time       `json:"attestedAt,omitempty"`
	AttestationExpiresAt     time.Time       `json:"attestationExpiresAt,omitempty"`
	PublicKey                string          `json:"-"`
	KeyFingerprint           string          `json:"keyFingerprint"`
	Platform                 string          `json:"platform,omitempty"`
	ClientVersion            string          `json:"clientVersion,omitempty"`
	CreatedAt                time.Time       `json:"createdAt"`
	UpdatedAt                time.Time       `json:"updatedAt"`
	LastSeenAt               time.Time       `json:"lastSeenAt,omitempty"`
	LastVerifiedAt           time.Time       `json:"lastVerifiedAt,omitempty"`
	LastIP                   string          `json:"lastIp,omitempty"`
	LastUserAgent            string          `json:"lastUserAgent,omitempty"`
	RevokedAt                time.Time       `json:"revokedAt,omitempty"`
	RevokedReason            string          `json:"revokedReason,omitempty"`
	ReplacedAt               time.Time       `json:"replacedAt,omitempty"`
	ReplacedByDeviceID       string          `json:"replacedByDeviceId,omitempty"`
	ReplacementReason        string          `json:"replacementReason,omitempty"`
	TrustAssessment          TrustAssessment `json:"trustAssessment"`
}

// DeviceHardwareEvidence is persisted only after successful TPM Certify verification.
// A legacy client-provided provenance field is never authoritative.
type DeviceHardwareEvidence struct {
	UserID          string    `json:"-"`
	DeviceID        string    `json:"deviceId"`
	SessionID       string    `json:"-"`
	BindingEpoch    int64     `json:"bindingEpoch"`
	KeyFingerprint  string    `json:"keyFingerprint"`
	RootID          string    `json:"rootId"`
	RootFingerprint string    `json:"rootFingerprint"`
	AKFingerprint   string    `json:"akFingerprint"`
	ChallengeID     string    `json:"-"`
	VerifiedAt      time.Time `json:"verifiedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// MeasuredBootEvidence0315 is ONLY evidence of approved TPM PCR measurements.
// It does not authenticate the running JVM or raise Guard assurance.
type MeasuredBootEvidence0315 struct {
	UserID          string    `json:"-"`
	DeviceID        string    `json:"deviceId"`
	SessionID       string    `json:"-"`
	BindingEpoch    int64     `json:"bindingEpoch"`
	KeyFingerprint  string    `json:"-"`
	RootID          string    `json:"rootId"`
	RootFingerprint string    `json:"-"`
	AKFingerprint   string    `json:"-"`
	PolicyID        string    `json:"policyId"`
	PolicyHash      string    `json:"policyHash"`
	PCRDigest       string    `json:"pcrDigest"`
	ChallengeID     string    `json:"-"`
	VerifiedAt      time.Time `json:"verifiedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// DeviceChallenge — краткосрочный одноразовый запрос доказательства
// владения ключом. Хранится только SHA-256 переданного challenge.
type DeviceChallenge struct {
	ID            string         `json:"id"`
	UserID        string         `json:"userId"`
	DeviceID      string         `json:"deviceId"`
	Purpose       string         `json:"purpose"`
	ChallengeHash string         `json:"-"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	ExpiresAt     time.Time      `json:"expiresAt"`
	ConsumedAt    time.Time      `json:"consumedAt,omitempty"`
}

// DeviceRevocationResult — авторитетный результат отзыва доверенного
// устройства. RevokedSessionIDs — внутреннее свидетельство каскада
// для HTTP в тестовом пути памяти и не сериализуется клиентам.
type DeviceRevocationResult struct {
	Device                   TrustedDevice `json:"device"`
	AlreadyRevoked           bool          `json:"alreadyRevoked"`
	RevokedSessions          int           `json:"revokedSessions"`
	RevokedRefreshFamilies   int           `json:"revokedRefreshFamilies"`
	RevokedMinecraftSessions int           `json:"revokedMinecraftSessions"`
	InvalidatedChallenges    int           `json:"invalidatedChallenges"`
	RevokedSessionIDs        []string      `json:"-"`
	CascadeHandled           bool          `json:"-"`
}

// DeviceKeyReplacementResult создаётся атомарным путём PostgreSQL
// при ротации или восстановлении. Текущий сеанс перепривязывается
// до отзыва старого устройства, поэтому он сохраняется, а все
// другие привязанные к старому устройству сеансы отзываются.
type DeviceKeyReplacementResult struct {
	OldDevice                TrustedDevice `json:"oldDevice"`
	NewDevice                TrustedDevice `json:"newDevice"`
	RevokedSessions          int           `json:"revokedSessions"`
	RevokedRefreshFamilies   int           `json:"revokedRefreshFamilies"`
	RevokedMinecraftSessions int           `json:"revokedMinecraftSessions"`
	InvalidatedChallenges    int           `json:"invalidatedChallenges"`
	RevokedSessionIDs        []string      `json:"-"`
}

// DeviceRevocationBatch возвращается операцией отзыва других устройств и показывает
// весь серверный каскад без раскрытия секретов сеансов и refresh-токенов.
type DeviceRevocationBatch struct {
	Devices                  []TrustedDevice `json:"devices"`
	RevokedDevices           int             `json:"revokedDevices"`
	AlreadyRevoked           int             `json:"alreadyRevoked"`
	RevokedSessions          int             `json:"revokedSessions"`
	RevokedRefreshFamilies   int             `json:"revokedRefreshFamilies"`
	RevokedMinecraftSessions int             `json:"revokedMinecraftSessions"`
	InvalidatedChallenges    int             `json:"invalidatedChallenges"`
	RevokedSessionIDs        []string        `json:"-"`
	CascadeHandled           bool            `json:"-"`
}

// MinecraftProfile — устойчивая идентичность Minecraft у канонического пользователя
// Never. UUID и имя не зависят от изменяемого email и субъектов внешних провайдеров.
type MinecraftProfile struct {
	UserID          string    `json:"userId"`
	UUID            string    `json:"uuid"`
	Name            string    `json:"name"`
	Issuer          string    `json:"issuer"`
	Realm           string    `json:"realm"`
	Subject         string    `json:"subject"`
	IdentityVersion string    `json:"identityVersion"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// MinecraftSession — непрозрачный сеанс Minecraft/Yggdrasil на основе сеанса
// Never. AccessTokenHash — единственная сохраняемая форма bearer-токена.
type MinecraftSession struct {
	ID                     string    `json:"id"`
	UserID                 string    `json:"userId"`
	NeverSessionID         string    `json:"neverSessionId"`
	ProfileUUID            string    `json:"profileUuid"`
	TrustedDeviceID        string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch           int64     `json:"bindingEpoch"`
	ClientToken            string    `json:"clientToken,omitempty"`
	AccessTokenHash        string    `json:"-"`
	IntegrityVerified      bool      `json:"integrityVerified"`
	GuardAttestationSHA256 string    `json:"guardAttestationSha256,omitempty"`
	GuardEvidenceSHA256    string    `json:"guardEvidenceSha256,omitempty"`
	GuardSHA256            string    `json:"guardSha256,omitempty"`
	LauncherSHA256         string    `json:"launcherSha256,omitempty"`
	LauncherVersion        string    `json:"launcherVersion,omitempty"`
	IntegrityVerifiedAt    time.Time `json:"integrityVerifiedAt,omitempty"`
	Status                 string    `json:"status"`
	CreatedAt              time.Time `json:"createdAt"`
	LastSeenAt             time.Time `json:"lastSeenAt"`
	ExpiresAt              time.Time `json:"expiresAt"`
	RevokedAt              time.Time `json:"revokedAt,omitempty"`
	RevokedReason          string    `json:"revokedReason,omitempty"`
}

// MinecraftJoin — краткосрочное доказательство, создаваемое
// запросом клиента /join и погашаемое сервером через /hasJoined.
type MinecraftJoin struct {
	Username           string    `json:"username"`
	UsernameNormalized string    `json:"-"`
	ProfileUUID        string    `json:"profileUuid"`
	UserID             string    `json:"userId"`
	MinecraftSessionID string    `json:"minecraftSessionId"`
	ServerID           string    `json:"serverId"`
	IP                 string    `json:"ip,omitempty"`
	TicketVersion      int       `json:"ticketVersion"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"createdAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
	ConsumedAt         time.Time `json:"consumedAt,omitempty"`
}

// ServerBridgeNode — авторитетная идентичность игрового или прокси-узла; protocol_version
// хранит согласованное сетевое поколение v2/v3. С 0.14.2 запросы аутентифицируются
// Ed25519-ключом; закрытый ключ никогда не пересекает границу узел/бэкенд. Старые
// поля токена остаются внутренними для безопасной миграции 0.14.1.
type ServerBridgeNode struct {
	ID                         string                 `json:"id"`
	Name                       string                 `json:"name"`
	Kind                       string                 `json:"kind"`
	ProjectID                  string                 `json:"projectId"`
	ProfileID                  string                 `json:"profileId,omitempty"`
	Fingerprint                string                 `json:"fingerprint,omitempty"`
	TokenHash                  string                 `json:"-"` // Устаревшие учётные данные 0.14.1, не используются авторизацией 0.14.2.
	TokenPrefix                string                 `json:"-"`
	KeyAlgorithm               string                 `json:"keyAlgorithm"`
	PublicKey                  string                 `json:"-"`
	KeyFingerprint             string                 `json:"keyFingerprint"`
	IdentityEpoch              int64                  `json:"identityEpoch"`
	IdentityRotatedAt          time.Time              `json:"identityRotatedAt,omitempty"`
	Status                     string                 `json:"status"`
	ProtocolVersion            int                    `json:"protocolVersion"`
	PluginVersion              string                 `json:"pluginVersion,omitempty"`
	PluginSHA256               string                 `json:"pluginSha256,omitempty"`
	IntegrityStatus            string                 `json:"integrityStatus,omitempty"`
	IntegrityVerifiedAt        time.Time              `json:"integrityVerifiedAt,omitempty"`
	LastHeartbeatAt            time.Time              `json:"lastHeartbeatAt,omitempty"`
	CreatedAt                  time.Time              `json:"createdAt"`
	RotatedAt                  time.Time              `json:"rotatedAt,omitempty"`
	RuntimeID                  string                 `json:"runtimeId,omitempty"`
	RuntimeEpoch               int64                  `json:"runtimeEpoch,omitempty"`
	RuntimePreviousID          string                 `json:"runtimePreviousId,omitempty"`
	RuntimeTransition          string                 `json:"runtimeTransition,omitempty"`
	RuntimeReplacementDetected bool                   `json:"runtimeReplacementDetected,omitempty"`
	RuntimeStartedAt           time.Time              `json:"runtimeStartedAt,omitempty"`
	RuntimeFirstSeenAt         time.Time              `json:"runtimeFirstSeenAt,omitempty"`
	RuntimeLastSeenAt          time.Time              `json:"runtimeLastSeenAt,omitempty"`
	RuntimeUptimeSeconds       int64                  `json:"runtimeUptimeSeconds,omitempty"`
	RuntimeProcessID           int64                  `json:"runtimeProcessId,omitempty"`
	Hostname                   string                 `json:"hostname,omitempty"`
	NodeName                   string                 `json:"nodeName,omitempty"`
	MinecraftVersion           string                 `json:"minecraftVersion,omitempty"`
	JavaVersion                string                 `json:"javaVersion,omitempty"`
	JavaVendor                 string                 `json:"javaVendor,omitempty"`
	JavaVMName                 string                 `json:"javaVmName,omitempty"`
	RuntimePlatform            string                 `json:"runtimePlatform,omitempty"`
	LoaderName                 string                 `json:"loaderName,omitempty"`
	LoaderVersion              string                 `json:"loaderVersion,omitempty"`
	ServerBrand                string                 `json:"serverBrand,omitempty"`
	RuntimeCapabilities        []string               `json:"runtimeCapabilities,omitempty"`
	RuntimeIdentityDigest      string                 `json:"runtimeIdentityDigest,omitempty"`
	Telemetry                  *ServerBridgeTelemetry `json:"telemetry,omitempty"`
}

// ServerBridgeRoutingSnapshot — подписанное объявление маршрутов, привязанное к работающему
// процессу. Принимается только от узлов Protocol v3 и используется для защищённой передачи.
type ServerBridgeRoutingSnapshot struct {
	RuntimeID            string    `json:"runtimeId"`
	ObservedAtUnixMillis int64     `json:"observedAtUnixMillis"`
	State                string    `json:"state"`
	AcceptingConnections bool      `json:"acceptingConnections"`
	PlayersOnline        int       `json:"playersOnline"`
	CapacityMax          int       `json:"capacityMax"`
	Health               string    `json:"health"`
	Revision             int64     `json:"revision"`
	Digest               string    `json:"digest"`
	Signature            string    `json:"signature"`
	ObservedAt           time.Time `json:"observedAt,omitempty"`
}

// ServerBridgeTelemetry — один ограниченный снимок телеметрии проверенной JVM.
type ServerBridgeTelemetry struct {
	Sequence                    int64    `json:"sequence"`
	SampledAtUnixMillis         int64    `json:"sampledAtUnixMillis"`
	WindowMillis                int64    `json:"windowMillis"`
	RuntimeID                   string   `json:"runtimeId"`
	RuntimeEpoch                int64    `json:"runtimeEpoch"`
	TPS                         *float64 `json:"tps,omitempty"`
	MSPT                        *float64 `json:"mspt,omitempty"`
	TickHealth                  string   `json:"tickHealth"`
	PlayersOnline               *int     `json:"playersOnline,omitempty"`
	PlayersMax                  *int     `json:"playersMax,omitempty"`
	HeapUsedBytes               int64    `json:"heapUsedBytes"`
	HeapCommittedBytes          int64    `json:"heapCommittedBytes"`
	HeapMaxBytes                int64    `json:"heapMaxBytes"`
	NonHeapUsedBytes            int64    `json:"nonHeapUsedBytes"`
	NonHeapCommittedBytes       int64    `json:"nonHeapCommittedBytes"`
	GCCollections               int64    `json:"gcCollections"`
	GCCollectionTimeMillis      int64    `json:"gcCollectionTimeMillis"`
	GCCollectionsDelta          int64    `json:"gcCollectionsDelta"`
	GCCollectionTimeDeltaMillis int64    `json:"gcCollectionTimeDeltaMillis"`
	ThreadCount                 int      `json:"threadCount"`
	DaemonThreadCount           int      `json:"daemonThreadCount"`
	PeakThreadCount             int      `json:"peakThreadCount"`
	LoadedWorlds                *int     `json:"loadedWorlds,omitempty"`
	LoadedDimensions            *int     `json:"loadedDimensions,omitempty"`
	LoadedChunks                *int64   `json:"loadedChunks,omitempty"`
	EntityCount                 *int64   `json:"entityCount,omitempty"`
	SamplingBudgetExceeded      bool     `json:"samplingBudgetExceeded"`
	Metrics                     []string `json:"metrics"`
	ProcessID                   *int64   `json:"processId,omitempty"`
	ProcessCPUTimeNanos         *int64   `json:"processCpuTimeNanos,omitempty"`
	ProcessCPULoad              *float64 `json:"processCpuLoad,omitempty"`
	HostTotalMemoryBytes        *int64   `json:"hostTotalMemoryBytes,omitempty"`
	HostFreeMemoryBytes         *int64   `json:"hostFreeMemoryBytes,omitempty"`
}

// ServerBridgeEvent — упорядоченное событие с индивидуальной подписью, привязанное к подтверждённой эпохе выполнения.
type ServerBridgeEvent struct {
	Sequence             int64             `json:"sequence"`
	EventID              string            `json:"eventId"`
	RuntimeID            string            `json:"runtimeId"`
	Type                 string            `json:"type"`
	OccurredAtUnixMillis int64             `json:"occurredAtUnixMillis"`
	Payload              map[string]string `json:"payload"`
	PayloadSHA256        string            `json:"payloadSha256"`
	Signature            string            `json:"signature"`
}

// ServerBridgeEventAppendResult — подтверждение (ACK) непрерывной последовательности событий, сохранённое в PostgreSQL.
type ServerBridgeEventAppendResult struct {
	AckSequence int64 `json:"ackSequence"`
	Inserted    int   `json:"inserted"`
}

// ServerBridgeControlCommand — сохраняемая команда Backend→Bridge, привязанная к активному процессу. Payload
// содержит только проверенные аргументы платформы; команды оболочки и argv не сохраняются и не выполняются.
type ServerBridgeControlCommand struct {
	ID               string            `json:"id"`
	ServerID         string            `json:"serverId"`
	RuntimeEpoch     int64             `json:"runtimeEpoch"`
	RuntimeID        string            `json:"runtimeId"`
	Type             string            `json:"type"`
	Payload          map[string]string `json:"payload"`
	PayloadSHA256    string            `json:"payloadSha256"`
	RequestDigest    string            `json:"requestDigest"`
	RequestedBy      string            `json:"requestedBy"`
	IdempotencyKey   string            `json:"idempotencyKey"`
	Status           string            `json:"status"`
	Attempt          int               `json:"attempt"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	ExpiresAt        time.Time         `json:"expiresAt"`
	DeliverySequence int64             `json:"deliverySequence"`
	LeaseOwner       string            `json:"leaseOwner,omitempty"`
	LeaseToken       string            `json:"-"`
	LeaseUntil       time.Time         `json:"leaseUntil,omitempty"`
	CompletedAt      time.Time         `json:"completedAt,omitempty"`
	Result           map[string]string `json:"result,omitempty"`
	Error            string            `json:"error,omitempty"`
}

// ServerBridgeRuntimeIdentity — неизменяемая идентификация процесса, подтверждённая ключом Ed25519 узла.
type ServerBridgeRuntimeIdentity struct {
	RuntimeID           string
	StartedAt           time.Time
	StartedAtUnixMillis int64
	UptimeSeconds       int64
	ProcessID           int64
	Hostname            string
	NodeName            string
	MinecraftVersion    string
	JavaVersion         string
	JavaVendor          string
	JavaVMName          string
	Platform            string
	LoaderName          string
	LoaderVersion       string
	ServerBrand         string
	Capabilities        []string
	NodeKeyFingerprint  string
	IdentitySignature   string
	IdentityDigest      string
}

// ServerBridgeRuntimeTransition описывает изменения после сохранения подписанного heartbeat процесса.
type ServerBridgeRuntimeTransition struct {
	RuntimeID           string    `json:"runtimeId"`
	RuntimeEpoch        int64     `json:"runtimeEpoch"`
	PreviousRuntimeID   string    `json:"previousRuntimeId,omitempty"`
	Transition          string    `json:"transition"`
	ReplacementDetected bool      `json:"replacementDetected"`
	StartedAt           time.Time `json:"startedAt"`
	FirstSeenAt         time.Time `json:"firstSeenAt"`
	LastSeenAt          time.Time `json:"lastSeenAt"`
}

// ServerBridgeJoinTicket — краткоживущий одноразовый токен авторизации ServerBridge, связанный с согласованным
// протоколом узла v2/v3. Успешная проверка на сервере атомарно поглощает токен, исключая повторное использование.
type ServerBridgeJoinTicket struct {
	ID                     string    `json:"id"`
	TicketVersion          int       `json:"ticketVersion"`
	Username               string    `json:"username"`
	UsernameNormalized     string    `json:"-"`
	UUID                   string    `json:"uuid"`
	UserID                 string    `json:"userId"`
	SessionID              string    `json:"sessionId"`
	ServerID               string    `json:"serverId"`
	ProjectID              string    `json:"projectId"`
	ProfileID              string    `json:"profileId"`
	Channel                string    `json:"channel"`
	AccessTokenHash        string    `json:"-"`
	TrustedDeviceID        string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch           int64     `json:"bindingEpoch"`
	MinecraftSessionID     string    `json:"minecraftSessionId,omitempty"`
	IdentityRealm          string    `json:"identityRealm,omitempty"`
	OfficialProof          string    `json:"-"`
	OnlineModeVerified     bool      `json:"onlineModeVerified,omitempty"` // Verified snapshot; never includes a bearer.
	SessionCorrelationID   string    `json:"sessionCorrelationId,omitempty"`
	ProtocolVersion        int       `json:"protocolVersion"`
	IssuedIdentityEpoch    int64     `json:"issuedIdentityEpoch"`
	IssuedKeyFingerprint   string    `json:"issuedKeyFingerprint"`
	Status                 string    `json:"status"`
	CreatedAt              time.Time `json:"createdAt"`
	ExpiresAt              time.Time `json:"expiresAt"`
	ConsumedAt             time.Time `json:"consumedAt,omitempty"`
	RedeemedIdentityEpoch  int64     `json:"redeemedIdentityEpoch,omitempty"`
	RedeemedKeyFingerprint string    `json:"redeemedKeyFingerprint,omitempty"`
	RedeemedNonceHash      string    `json:"redeemedNonceHash,omitempty"`
	RedeemedByIP           string    `json:"redeemedByIp,omitempty"`
}

// ServerBridgeJoinRedemption — аутентифицированное подтверждение узла, сохраняемое после
// использования одноразового токена подключения. Одноразовый номер запроса уже проверен
// хранилищем защиты от повторов подписанных запросов до передачи доказательства в репозиторий.
type ServerBridgeJoinRedemption struct {
	NodeID               string
	IdentityEpoch        int64
	KeyFingerprint       string
	NonceHash            string
	RemoteIP             string
	SessionCorrelationID string
	TrustReason          string
	IntegrityReason      string
	VerifiedAt           time.Time
	OnlineModeVerified   bool
}

// ServerBridgeHandoff — краткоживущие одноразовые учётные данные для передачи от прокси к
// серверной части. Создаются только после поглощения прокси токена подключения лаунчера и
// криптографически привязываются к обеим текущим идентичностям узлов. Проверка серверной
// частью атомарно поглощает их, поэтому исходный токен лаунчера не используется повторно.
type ServerBridgeHandoff struct {
	ID                       string    `json:"id"`
	Username                 string    `json:"username"`
	UsernameNormalized       string    `json:"-"`
	UUID                     string    `json:"uuid"`
	UserID                   string    `json:"userId"`
	SessionID                string    `json:"sessionId"`
	SourceNodeID             string    `json:"sourceNodeId"`
	TargetNodeID             string    `json:"targetNodeId"`
	BackendName              string    `json:"backendName,omitempty"`
	ProjectID                string    `json:"projectId"`
	ProfileID                string    `json:"profileId"`
	Channel                  string    `json:"channel"`
	TrustedDeviceID          string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch             int64     `json:"bindingEpoch"`
	MinecraftSessionID       string    `json:"minecraftSessionId,omitempty"`
	IdentityRealm            string    `json:"identityRealm,omitempty"`
	OfficialProof            string    `json:"-"`
	SourceOnlineModeVerified bool      `json:"-"`
	SessionCorrelationID     string    `json:"sessionCorrelationId,omitempty"`
	TransferSequence         int64     `json:"transferSequence,omitempty"`
	SourceIdentityEpoch      int64     `json:"sourceIdentityEpoch"`
	SourceKeyFingerprint     string    `json:"sourceKeyFingerprint"`
	TargetIdentityEpoch      int64     `json:"targetIdentityEpoch"`
	TargetKeyFingerprint     string    `json:"targetKeyFingerprint"`
	ProtocolVersion          int       `json:"protocolVersion"`
	RequireRoutingProof      bool      `json:"-"`
	SourceRuntimeID          string    `json:"sourceRuntimeId,omitempty"`
	SourceRuntimeEpoch       int64     `json:"sourceRuntimeEpoch,omitempty"`
	SourceRoutingRevision    int64     `json:"sourceRoutingRevision,omitempty"`
	SourceRoutingDigest      string    `json:"sourceRoutingDigest,omitempty"`
	SourceRoutingSignature   string    `json:"sourceRoutingSignature,omitempty"`
	TargetRuntimeID          string    `json:"targetRuntimeId,omitempty"`
	TargetRuntimeEpoch       int64     `json:"targetRuntimeEpoch,omitempty"`
	TargetRoutingRevision    int64     `json:"targetRoutingRevision,omitempty"`
	TargetRoutingDigest      string    `json:"targetRoutingDigest,omitempty"`
	TargetRoutingSignature   string    `json:"targetRoutingSignature,omitempty"`
	Status                   string    `json:"status"`
	CreatedAt                time.Time `json:"createdAt"`
	ExpiresAt                time.Time `json:"expiresAt"`
	ConsumedAt               time.Time `json:"consumedAt,omitempty"`
	RedeemedNonceHash        string    `json:"redeemedNonceHash,omitempty"`
	RedeemedByIP             string    `json:"redeemedByIp,omitempty"`
}

// ServerBridgePlayerSession — авторитетное состояние игрового сеанса на протяжении взаимодействия лаунчера, прокси и серверного
// узла. Один идентификатор корреляции соответствует одному логическому подключению игрока; новое подключение с тем же сеансом
// Never/Minecraft аннулирует предыдущую топологию и отключает прежнее соединение, предотвращая клонирование сеанса.
type ServerBridgePlayerSession struct {
	CorrelationID       string    `json:"correlationId"`
	PlayerUUID          string    `json:"playerUuid"`
	Username            string    `json:"username"`
	UserID              string    `json:"userId"`
	NeverSessionID      string    `json:"neverSessionId"`
	MinecraftSessionID  string    `json:"minecraftSessionId,omitempty"`
	TrustedDeviceID     string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch        int64     `json:"bindingEpoch"`
	ProjectID           string    `json:"projectId"`
	ProfileID           string    `json:"profileId"`
	Channel             string    `json:"channel"`
	Status              string    `json:"status"`
	ProxyNodeID         string    `json:"proxyNodeId,omitempty"`
	ProxyRuntimeID      string    `json:"proxyRuntimeId,omitempty"`
	ProxyRuntimeEpoch   int64     `json:"proxyRuntimeEpoch,omitempty"`
	BackendNodeID       string    `json:"backendNodeId,omitempty"`
	BackendRuntimeID    string    `json:"backendRuntimeId,omitempty"`
	BackendRuntimeEpoch int64     `json:"backendRuntimeEpoch,omitempty"`
	TransferSequence    int64     `json:"transferSequence"`
	RecheckRequired     bool      `json:"recheckRequired"`
	TrustReason         string    `json:"trustReason,omitempty"`
	IntegrityReason     string    `json:"integrityReason,omitempty"`
	LastVerifiedAt      time.Time `json:"lastVerifiedAt,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
	InvalidatedAt       time.Time `json:"invalidatedAt,omitempty"`
	InvalidatedReason   string    `json:"invalidatedReason,omitempty"`
}

// ServerBridgeTransferHop — один упорядоченный переход прокси → серверная часть внутри связанного игрового сеанса.
type ServerBridgeTransferHop struct {
	CorrelationID      string    `json:"correlationId"`
	Sequence           int64     `json:"sequence"`
	HandoffID          string    `json:"handoffId"`
	SourceNodeID       string    `json:"sourceNodeId"`
	TargetNodeID       string    `json:"targetNodeId"`
	SourceRuntimeID    string    `json:"sourceRuntimeId,omitempty"`
	SourceRuntimeEpoch int64     `json:"sourceRuntimeEpoch,omitempty"`
	TargetRuntimeID    string    `json:"targetRuntimeId,omitempty"`
	TargetRuntimeEpoch int64     `json:"targetRuntimeEpoch,omitempty"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"createdAt"`
	ConsumedAt         time.Time `json:"consumedAt,omitempty"`
}

// ServerBridgeTopologyEdge фиксирует наблюдавшийся маршрут прокси → серверная часть. Связи
// определяются по аутентифицированным передачам; администраторам не требуется изменять
// настройки прокси или сервера для поддержки параллельного графа маршрутизации NeverLauncher.
type ServerBridgeTopologyEdge struct {
	SourceNodeID         string    `json:"sourceNodeId"`
	TargetNodeID         string    `json:"targetNodeId"`
	BackendName          string    `json:"backendName"`
	ProjectID            string    `json:"projectId"`
	ProfileID            string    `json:"profileId"`
	Status               string    `json:"status"`
	SourceHealth         string    `json:"sourceHealth,omitempty"`
	TargetHealth         string    `json:"targetHealth,omitempty"`
	TargetState          string    `json:"targetState,omitempty"`
	TargetPlayers        int       `json:"targetPlayers,omitempty"`
	TargetCapacity       int       `json:"targetCapacity,omitempty"`
	AcceptingConnections bool      `json:"acceptingConnections"`
	TargetRuntimeID      string    `json:"targetRuntimeId,omitempty"`
	TargetRuntimeEpoch   int64     `json:"targetRuntimeEpoch,omitempty"`
	RoutingRevision      int64     `json:"routingRevision,omitempty"`
	LastSeenAt           time.Time `json:"lastSeenAt"`
	CreatedAt            time.Time `json:"createdAt"`
}

// ServerBridgeNetworkState carries a signed node observation alongside the independent
// PostgreSQL operator admission ceiling. A server may report ready while policy denies admissions.
type ServerBridgeNetworkState struct {
	NodeID                   string     `json:"nodeId"`
	RuntimeID                string     `json:"runtimeId"`
	RuntimeEpoch             int64      `json:"runtimeEpoch"`
	State                    string     `json:"state"`
	Health                   string     `json:"health"`
	AcceptingConnections     bool       `json:"acceptingConnections"`
	PlayersOnline            int        `json:"playersOnline"`
	CapacityMax              int        `json:"capacityMax"`
	OperatorCapacityMax      *int       `json:"operatorCapacityMax"`
	OperatorCapacityRevision int64      `json:"operatorCapacityRevision"`
	EffectiveCapacityMax     int        `json:"effectiveCapacityMax"`
	AvailableSlots           int        `json:"availableSlots"`
	ReservedSlots            int        `json:"reservedSlots"`
	Routable                 bool       `json:"routable"`
	Reason                   string     `json:"reason"`
	RoutingRevision          int64      `json:"routingRevision"`
	ObservedAt               *time.Time `json:"observedAt"`
	LastHeartbeatAt          *time.Time `json:"lastHeartbeatAt"`
	OperatorUpdatedAt        *time.Time `json:"operatorUpdatedAt,omitempty"`
	OperatorUpdatedBy        string     `json:"operatorUpdatedBy,omitempty"`
	Source                   string     `json:"source"`
}

// ServerBridgeRouteTarget — серверная часть, в данный момент допустимая для подключения через прокси.
type ServerBridgeRouteTarget struct {
	NodeID          string    `json:"nodeId"`
	BackendName     string    `json:"backendName"`
	Kind            string    `json:"kind"`
	ProjectID       string    `json:"projectId"`
	ProfileID       string    `json:"profileId"`
	RuntimeID       string    `json:"runtimeId"`
	RuntimeEpoch    int64     `json:"runtimeEpoch"`
	Health          string    `json:"health"`
	State           string    `json:"state"`
	PlayersOnline   int       `json:"playersOnline"`
	CapacityMax     int       `json:"capacityMax"`
	AvailableSlots  int       `json:"availableSlots"`
	RoutingRevision int64     `json:"routingRevision"`
	RoutingDigest   string    `json:"routingDigest"`
	ObservedAt      time.Time `json:"observedAt"`
	LastHeartbeatAt time.Time `json:"lastHeartbeatAt"`
}

// ServerBridgeMaintenanceResult — результат одного прохода обслуживания, безопасного для
// режима высокой доступности. LeaseAcquired имеет значение false, если блокировка транзакции
// PostgreSQL уже занята другим экземпляром API, что ожидаемо в конфигурации active/active.
type ServerBridgeMaintenanceResult struct {
	LeaseAcquired             bool      `json:"leaseAcquired"`
	ExpiredNoncesDeleted      int64     `json:"expiredNoncesDeleted"`
	JoinTicketsInvalidated    int64     `json:"joinTicketsInvalidated"`
	HandoffsExpired           int64     `json:"handoffsExpired"`
	TopologyEdgesDisabled     int64     `json:"topologyEdgesDisabled"`
	TopologyEdgesPurged       int64     `json:"topologyEdgesPurged"`
	TerminalJoinTicketsPurged int64     `json:"terminalJoinTicketsPurged"`
	TerminalHandoffsPurged    int64     `json:"terminalHandoffsPurged"`
	TelemetrySamplesPurged    int64     `json:"telemetrySamplesPurged"`
	EventStreamRowsPurged     int64     `json:"eventStreamRowsPurged"`
	ControlCommandsPurged     int64     `json:"controlCommandsPurged"`
	PlayerSessionsInvalidated int64     `json:"playerSessionsInvalidated"`
	PlayerSessionsPurged      int64     `json:"playerSessionsPurged"`
	CompletedAt               time.Time `json:"completedAt"`
}

// ServerBridgeHAStatus — получаемый из базы данных снимок состояния, общий для всех
// реплик API. Умышленно содержит только агрегированные эксплуатационные показатели.
type ServerBridgeHAStatus struct {
	ObservedAt            time.Time `json:"observedAt"`
	FreshnessSeconds      int       `json:"freshnessSeconds"`
	NodesTotal            int64     `json:"nodesTotal"`
	NodesActive           int64     `json:"nodesActive"`
	NodesFresh            int64     `json:"nodesFresh"`
	NodesStale            int64     `json:"nodesStale"`
	TopologyActive        int64     `json:"topologyActive"`
	TopologyFresh         int64     `json:"topologyFresh"`
	TopologyStale         int64     `json:"topologyStale"`
	ActiveJoinTickets     int64     `json:"activeJoinTickets"`
	ExpiredJoinBacklog    int64     `json:"expiredJoinBacklog"`
	ActiveHandoffs        int64     `json:"activeHandoffs"`
	ExpiredHandoffBacklog int64     `json:"expiredHandoffBacklog"`
	ExpiredNonceBacklog   int64     `json:"expiredNonceBacklog"`
}

// ServerBridgeTexture — сохраняемый профиль текстур, используемый сеансами ServerBridge.
type ServerBridgeTexture struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	SkinURL   string    `json:"skinUrl,omitempty"`
	CapeURL   string    `json:"capeUrl,omitempty"`
	Model     string    `json:"model"`
	UpdatedAt time.Time `json:"updatedAt"`
}
