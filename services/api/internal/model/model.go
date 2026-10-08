package model

import "time"

// Проект описывает Minecraft-проект, который использует NeverLauncher.
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

// Профиль описывает клиентский профиль проекта.
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

// ReleaseChannel описывает канал релиза: dev, beta или стабильный.
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

// Пользователь описывает пользователя backend/admin panel.
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

// AuthIdentity связывает канонического Никогда пользователь с субъект конкретного аутентификация провайдер.
// Внешний провайдер никогда не заменяет Пользователь: федерация ядро всегда разрешает идентичность
// в локальный Пользователь до выпуска Никогда session/token.
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

// Роль описывает роль пользователя в проекте.
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

// Манифест — минимальная структура манифеста, которую серверная часть отдаёт настольное приложение клиент.
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

// ProviderCredential хранит непрозрачный внешний-провайдер учётные данные только после это
// имеет был зашифрованный через аутентификация служба. Открытый текст провайдер токены должен никогда быть
// сохранённый через Репозиторий реализация или предоставлять через API модель.
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

// TrustedDevice является канонический устройство идентичность регистрировать к один Никогда пользователь.
// PublicKey содержит сырой Ed25519 открытый ключ байты encoded как основа64URL в хранилище;
// API ответы намеренно предоставлять только KeyFingerprint.
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

// DeviceChallenge является краткоживущий, одноразовый доказательство владения запрос.
// Только SHA-256 сетевой запрос является сохранённый.
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

// DeviceRevocationResult является авторитетный результат доверенное устройство отзыв.
// RevokedSessionIDs является внутренний каскад свидетельство используется через HTTP слой в 
// в памяти процесса test/runtime путь и является никогда сериализованный к клиенты.
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

// DeviceKeyReplacementResult является созданный через атомарный PostgreSQL замена
// путь используется через ключ rotation/recovery. текущий сессия является rebound до 
// старый устройство является отозванный, так это переживает пока каждый другой сессия по-прежнему привязанный
// к старый идентичность является отозванный.
type DeviceKeyReplacementResult struct {
	OldDevice                TrustedDevice `json:"oldDevice"`
	NewDevice                TrustedDevice `json:"newDevice"`
	RevokedSessions          int           `json:"revokedSessions"`
	RevokedRefreshFamilies   int           `json:"revokedRefreshFamilies"`
	RevokedMinecraftSessions int           `json:"revokedMinecraftSessions"`
	InvalidatedChallenges    int           `json:"invalidatedChallenges"`
	RevokedSessionIDs        []string      `json:"-"`
}

// DeviceRevocationBatch является возвращён через "отзыв другой устройства" и сохраняет 
// whole на стороне сервера каскад observable без предоставлять refresh/session секреты.
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

// MinecraftProfile является стабильный Minecraft идентичность принадлежащий через канонический Никогда пользователь.
// UUID/имя являются независимый из изменяемый электронная почта и из любой внешний провайдер субъект.
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

// MinecraftSession является непрозрачный Minecraft/Yggdrasil сессия производный из Никогда
// сессия. AccessTokenHash является только сохранённый representation bearer токен.
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

// MinecraftJoin является краткоживущий доказательство создан через клиент /подключение вызов и
// использованный через Minecraft сервер через /hasJoined.
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

// ServerBridgeNode является авторитетный ServerBridge идентичность game/proxy узел; протокол_версия tracks согласовывать v2/v3 сетевой генерация.
// Since 0.14.2 узел запросы являются аутентифицировать через Ed25519 открытый ключ; закрытый
// ключ материал никогда crosses node/backend граница. Устаревший токен fields оставаться
// внутренний только так 0.14.1 схема может быть мигрировать безопасно.
type ServerBridgeNode struct {
	ID                         string                 `json:"id"`
	Name                       string                 `json:"name"`
	Kind                       string                 `json:"kind"`
	ProjectID                  string                 `json:"projectId"`
	ProfileID                  string                 `json:"profileId,omitempty"`
	Fingerprint                string                 `json:"fingerprint,omitempty"`
	TokenHash                  string                 `json:"-"` // legacy 0.14.1 credential, never used by 0.14.2 auth
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

// ServerBridgeRoutingSnapshot является подписанный привязанный к среде выполнения маршрутизация advertisement.
// Это является принят только из Протокол v3 узлы и является используется для отказ с блокировкой передача маршрутизация.
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

// ServerBridgeTelemetry является один ограниченный телеметрия снимок привязанный к один проверен JVM среда выполнения.
type ServerBridgeTelemetry struct {
	Sequence                    int64    `json:"sequence"`
	SampledAtUnixMillis         int64    `json:"sampledAtUnixMillis"`
	WindowMillis                int64    `json:"windowMillis"`
	RuntimeID                   string   `json:"runtimeId"`
	RuntimeEpoch                int64    `json:"runtimeEpoch"`
	TPS                         *float64 `json:"tps,omitempty"`
	MSPT                        *float64 `json:"mspt,omitempty"`
	TickHealth                  string   `json:"tickHealth"`
	PlayersOnline               int      `json:"playersOnline"`
	PlayersMax                  int      `json:"playersMax"`
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
}

// ServerBridgeEvent является один упорядоченный, individually подписанный событие привязанный к проверен среда выполнения эпоха.
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

// ServerBridgeEventAppendResult является долговременный contiguous ACK возвращён через PostgreSQL.
type ServerBridgeEventAppendResult struct {
	AckSequence int64 `json:"ackSequence"`
	Inserted    int   `json:"inserted"`
}

// ServerBridgeControlCommand является долговременный Backend->Мост команда привязанный к активный среда выполнения.
// Полезная нагрузка содержит только проверен платформа arguments; нет оболочка program/argv является ever сохранённый или executed.
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

// ServerBridgeRuntimeIdentity является неизменяемый процесс идентичность attested через узел Ed25519 ключ.
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

// ServerBridgeRuntimeTransition описывает что изменён когда подписанный среда выполнения сигнал состояния был сохранённый.
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

// ServerBridgeJoinTicket является краткоживущий одноразовый ServerBridge авторизация привязанный к согласовывать v2/v3 узел протокол.
// успешный на стороне сервера валидация атомарно использовать это, предотвращать повторное воспроизведение.
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

// ServerBridgeJoinRedemption является аутентифицировать узел доказательство сохранённый когда 
// одноразовый подключение билет является использованный. запрос одноразовое значение имеет уже пройден 
// подписанный-запрос повторное воспроизведение хранилище до этот доказательство reaches репозиторий.
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
}

// ServerBridgeHandoff является краткоживущий одноразовый прокси-к-серверная часть учётные данные.
// Это является minted только после прокси имеет использованный лаунчер подключение билет и является
// cryptographically привязанный к оба текущий узел идентичности. Серверная часть валидация
// атомарно использовать это, так исходный лаунчер билет является никогда повторное воспроизведение.
type ServerBridgeHandoff struct {
	ID                     string    `json:"id"`
	Username               string    `json:"username"`
	UsernameNormalized     string    `json:"-"`
	UUID                   string    `json:"uuid"`
	UserID                 string    `json:"userId"`
	SessionID              string    `json:"sessionId"`
	SourceNodeID           string    `json:"sourceNodeId"`
	TargetNodeID           string    `json:"targetNodeId"`
	BackendName            string    `json:"backendName,omitempty"`
	ProjectID              string    `json:"projectId"`
	ProfileID              string    `json:"profileId"`
	Channel                string    `json:"channel"`
	TrustedDeviceID        string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch           int64     `json:"bindingEpoch"`
	MinecraftSessionID     string    `json:"minecraftSessionId,omitempty"`
	SessionCorrelationID   string    `json:"sessionCorrelationId,omitempty"`
	TransferSequence       int64     `json:"transferSequence,omitempty"`
	SourceIdentityEpoch    int64     `json:"sourceIdentityEpoch"`
	SourceKeyFingerprint   string    `json:"sourceKeyFingerprint"`
	TargetIdentityEpoch    int64     `json:"targetIdentityEpoch"`
	TargetKeyFingerprint   string    `json:"targetKeyFingerprint"`
	ProtocolVersion        int       `json:"protocolVersion"`
	RequireRoutingProof    bool      `json:"-"`
	SourceRuntimeID        string    `json:"sourceRuntimeId,omitempty"`
	SourceRuntimeEpoch     int64     `json:"sourceRuntimeEpoch,omitempty"`
	SourceRoutingRevision  int64     `json:"sourceRoutingRevision,omitempty"`
	SourceRoutingDigest    string    `json:"sourceRoutingDigest,omitempty"`
	SourceRoutingSignature string    `json:"sourceRoutingSignature,omitempty"`
	TargetRuntimeID        string    `json:"targetRuntimeId,omitempty"`
	TargetRuntimeEpoch     int64     `json:"targetRuntimeEpoch,omitempty"`
	TargetRoutingRevision  int64     `json:"targetRoutingRevision,omitempty"`
	TargetRoutingDigest    string    `json:"targetRoutingDigest,omitempty"`
	TargetRoutingSignature string    `json:"targetRoutingSignature,omitempty"`
	Status                 string    `json:"status"`
	CreatedAt              time.Time `json:"createdAt"`
	ExpiresAt              time.Time `json:"expiresAt"`
	ConsumedAt             time.Time `json:"consumedAt,omitempty"`
	RedeemedNonceHash      string    `json:"redeemedNonceHash,omitempty"`
	RedeemedByIP           string    `json:"redeemedByIp,omitempty"`
}

// ServerBridgePlayerSession является авторитетный игровой жизненный цикл spanning лаунчер, прокси и серверная часть узлы.
// Один корреляция ID represents один logical игрок соединение; новый корреляция для одинаковый Never/Minecraft
// сессия инвалидирует и отключаться предыдущий топология, предотвращать сессия клонирование.
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

// ServerBridgeTransferHop является один упорядоченный прокси -> серверная часть hop в correlated игровой сессия.
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

// ServerBridgeTopologyEdge записывает наблюдаемый прокси -> серверная часть маршрут. Edges являются
// learned из аутентифицировать передачи; оператор делать не patch proxy/server
// конфигурация к maintain parallel маршрутизация graph в NeverLauncher.
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

// ServerBridgeRouteTarget является один серверная часть сейчас admissible для прокси.
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

// ServerBridgeMaintenanceResult является результат один HA-безопасный обслуживание успешно.
// LeaseAcquired является false когда другой API экземпляр владеет PostgreSQL рекомендательный
// транзакция блокировка, который является ожидаемый в active/active развёртывание.
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

// ServerBridgeHAStatus является база данных-производный работоспособность снимок общий через каждый
// API реплика. Это намеренно содержит агрегат эксплуатационный состояние только.
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

// ServerBridgeTexture является постоянный texture профиль используется через ServerBridge сессии.
type ServerBridgeTexture struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	SkinURL   string    `json:"skinUrl,omitempty"`
	CapeURL   string    `json:"capeUrl,omitempty"`
	Model     string    `json:"model"`
	UpdatedAt time.Time `json:"updatedAt"`
}
