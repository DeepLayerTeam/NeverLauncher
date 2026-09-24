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

// TrustedDevice is a canonical device identity registered to one Never user.
// PublicKey contains raw Ed25519 public key bytes encoded as base64url in storage;
// API responses intentionally expose only KeyFingerprint.
type TrustedDevice struct {
	ID                   string    `json:"id"`
	UserID               string    `json:"userId"`
	Name                 string    `json:"name"`
	Status               string    `json:"status"`
	TrustState           string    `json:"trustState"`
	Assurance            string    `json:"assurance"`
	KeyAlgorithm         string    `json:"keyAlgorithm"`
	KeyBinding           string    `json:"keyBinding"`
	HardwareProvider     string    `json:"hardwareProvider,omitempty"`
	AttestationState     string    `json:"attestationState"`
	AttestationMethod    string    `json:"attestationMethod,omitempty"`
	AttestedAt           time.Time `json:"attestedAt,omitempty"`
	AttestationExpiresAt time.Time `json:"attestationExpiresAt,omitempty"`
	PublicKey            string    `json:"-"`
	KeyFingerprint       string    `json:"keyFingerprint"`
	Platform             string    `json:"platform,omitempty"`
	ClientVersion        string    `json:"clientVersion,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
	LastSeenAt           time.Time `json:"lastSeenAt,omitempty"`
	LastVerifiedAt       time.Time `json:"lastVerifiedAt,omitempty"`
	LastIP               string    `json:"lastIp,omitempty"`
	LastUserAgent        string    `json:"lastUserAgent,omitempty"`
	RevokedAt            time.Time `json:"revokedAt,omitempty"`
	RevokedReason        string    `json:"revokedReason,omitempty"`
	ReplacedAt           time.Time `json:"replacedAt,omitempty"`
	ReplacedByDeviceID   string    `json:"replacedByDeviceId,omitempty"`
	ReplacementReason    string    `json:"replacementReason,omitempty"`
}

// DeviceChallenge is a short-lived, single-use proof-of-possession challenge.
// Only the SHA-256 of the wire challenge is persisted.
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

// DeviceRevocationResult is the authoritative result of a trusted-device revoke.
// RevokedSessionIDs is internal cascade evidence used by the HTTP layer in the
// in-memory test/runtime path and is never serialized to clients.
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

// DeviceKeyReplacementResult is produced by the atomic PostgreSQL replacement
// path used by key rotation/recovery. The current session is rebound before the
// old device is revoked, so it survives while every other session still bound
// to the old identity is revoked.
type DeviceKeyReplacementResult struct {
	OldDevice                TrustedDevice `json:"oldDevice"`
	NewDevice                TrustedDevice `json:"newDevice"`
	RevokedSessions          int           `json:"revokedSessions"`
	RevokedRefreshFamilies   int           `json:"revokedRefreshFamilies"`
	RevokedMinecraftSessions int           `json:"revokedMinecraftSessions"`
	InvalidatedChallenges    int           `json:"invalidatedChallenges"`
	RevokedSessionIDs        []string      `json:"-"`
}

// DeviceRevocationBatch is returned by "revoke other devices" and keeps the
// whole server-side cascade observable without exposing refresh/session secrets.
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
	TicketVersion      int       `json:"ticketVersion"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"createdAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
	ConsumedAt         time.Time `json:"consumedAt,omitempty"`
}

// ServerBridgeNode is the authoritative Protocol v2 identity of a game/proxy node.
// Since 0.14.2 node requests are authenticated by an Ed25519 public key; private
// key material never crosses the node/backend boundary. Legacy token fields remain
// internal only so the 0.14.1 schema can be migrated safely.
type ServerBridgeNode struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Kind                string    `json:"kind"`
	ProjectID           string    `json:"projectId"`
	ProfileID           string    `json:"profileId,omitempty"`
	Fingerprint         string    `json:"fingerprint,omitempty"`
	TokenHash           string    `json:"-"` // legacy 0.14.1 credential, never used by 0.14.2 auth
	TokenPrefix         string    `json:"-"`
	KeyAlgorithm        string    `json:"keyAlgorithm"`
	PublicKey           string    `json:"-"`
	KeyFingerprint      string    `json:"keyFingerprint"`
	IdentityEpoch       int64     `json:"identityEpoch"`
	IdentityRotatedAt   time.Time `json:"identityRotatedAt,omitempty"`
	Status              string    `json:"status"`
	ProtocolVersion     int       `json:"protocolVersion"`
	PluginVersion       string    `json:"pluginVersion,omitempty"`
	PluginSHA256        string    `json:"pluginSha256,omitempty"`
	IntegrityStatus     string    `json:"integrityStatus,omitempty"`
	IntegrityVerifiedAt time.Time `json:"integrityVerifiedAt,omitempty"`
	LastHeartbeatAt     time.Time `json:"lastHeartbeatAt,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	RotatedAt           time.Time `json:"rotatedAt,omitempty"`
}

// ServerBridgeJoinTicket is a short-lived one-time Protocol v2 authorization.
// A successful server-side validation atomically consumes it, preventing replay.
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

// ServerBridgeJoinRedemption is the authenticated node proof persisted when a
// one-time join ticket is consumed. The request nonce has already passed the
// Protocol v2 replay store before this proof reaches the repository.
type ServerBridgeJoinRedemption struct {
	NodeID         string
	IdentityEpoch  int64
	KeyFingerprint string
	NonceHash      string
	RemoteIP       string
}

// ServerBridgeHandoff is a short-lived one-time proxy-to-backend credential.
// It is minted only after a proxy has consumed the launcher join ticket and is
// cryptographically bound to both current node identities. Backend validation
// atomically consumes it, so the original launcher ticket is never replayed.
type ServerBridgeHandoff struct {
	ID                   string    `json:"id"`
	Username             string    `json:"username"`
	UsernameNormalized   string    `json:"-"`
	UUID                 string    `json:"uuid"`
	UserID               string    `json:"userId"`
	SessionID            string    `json:"sessionId"`
	SourceNodeID         string    `json:"sourceNodeId"`
	TargetNodeID         string    `json:"targetNodeId"`
	BackendName          string    `json:"backendName,omitempty"`
	ProjectID            string    `json:"projectId"`
	ProfileID            string    `json:"profileId"`
	Channel              string    `json:"channel"`
	TrustedDeviceID      string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch         int64     `json:"bindingEpoch"`
	MinecraftSessionID   string    `json:"minecraftSessionId,omitempty"`
	SourceIdentityEpoch  int64     `json:"sourceIdentityEpoch"`
	SourceKeyFingerprint string    `json:"sourceKeyFingerprint"`
	TargetIdentityEpoch  int64     `json:"targetIdentityEpoch"`
	TargetKeyFingerprint string    `json:"targetKeyFingerprint"`
	Status               string    `json:"status"`
	CreatedAt            time.Time `json:"createdAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
	ConsumedAt           time.Time `json:"consumedAt,omitempty"`
	RedeemedNonceHash    string    `json:"redeemedNonceHash,omitempty"`
	RedeemedByIP         string    `json:"redeemedByIp,omitempty"`
}

// ServerBridgeTopologyEdge records an observed proxy -> backend route. Edges are
// learned from authenticated handoffs; operators do not patch proxy/server
// configuration to maintain a parallel routing graph in NeverLauncher.
type ServerBridgeTopologyEdge struct {
	SourceNodeID string    `json:"sourceNodeId"`
	TargetNodeID string    `json:"targetNodeId"`
	BackendName  string    `json:"backendName"`
	ProjectID    string    `json:"projectId"`
	ProfileID    string    `json:"profileId"`
	Status       string    `json:"status"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
	CreatedAt    time.Time `json:"createdAt"`
}

// ServerBridgeMaintenanceResult is the result of one HA-safe maintenance pass.
// LeaseAcquired is false when another API instance owns the PostgreSQL advisory
// transaction lock, which is expected in active/active deployments.
type ServerBridgeMaintenanceResult struct {
	LeaseAcquired          bool      `json:"leaseAcquired"`
	ExpiredNoncesDeleted   int64     `json:"expiredNoncesDeleted"`
	JoinTicketsInvalidated int64     `json:"joinTicketsInvalidated"`
	HandoffsExpired        int64     `json:"handoffsExpired"`
	TopologyEdgesDisabled  int64     `json:"topologyEdgesDisabled"`
	CompletedAt            time.Time `json:"completedAt"`
}

// ServerBridgeHAStatus is a database-derived health snapshot shared by every
// API replica. It intentionally contains aggregate operational state only.
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

// ServerBridgeTexture is the persistent texture profile used by Protocol v2.
type ServerBridgeTexture struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	SkinURL   string    `json:"skinUrl,omitempty"`
	CapeURL   string    `json:"capeUrl,omitempty"`
	Model     string    `json:"model"`
	UpdatedAt time.Time `json:"updatedAt"`
}
