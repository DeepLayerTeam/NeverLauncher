package httpapi

import (
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
)

type RuntimeState struct {
	AuthSessions    *authSessionStore
	Security        *securityHardeningStore
	Passkeys        *passkeyStore117
	ServerBridge    *serverBridgeStore
	Maintenance     *maintenanceGate
	PackageMutation *sync.Mutex

	RateLimiter              ratelimit.Limiter
	RateLimitEnabled         bool
	RateLimitGlobalPerMinute int
	RateLimitAuthPerMinute   int
	RateLimitFailClosed      bool
	TrustedProxies           *trustedProxySet
}

func NewRuntimeState() *RuntimeState {
	return &RuntimeState{
		AuthSessions:             newAuthSessionStore111(),
		Security:                 &securityHardeningStore{mfa: map[string]mfaRecord{}, failedLogins: map[string]loginFailureRecord{}, passwordResets: map[string]oneTimeSecurityToken{}, emailTokens: map[string]oneTimeSecurityToken{}, emailVerified: map[string]bool{}},
		Passkeys:                 newPasskeyStore117(),
		ServerBridge:             &serverBridgeStore{servers: map[string]bridgeServerRecord{}, joins: map[string]bridgeJoinRecord{}, textures: map[string]bridgeTextureRecord{}, nodeNonces: map[string]time.Time{}},
		Maintenance:              &maintenanceGate{},
		PackageMutation:          &sync.Mutex{},
		RateLimiter:              ratelimit.NewMemory(),
		RateLimitEnabled:         true,
		RateLimitGlobalPerMinute: 1200,
		RateLimitAuthPerMinute:   20,
	}
}
