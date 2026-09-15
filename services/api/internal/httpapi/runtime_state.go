package httpapi

import (
	"sync"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
)

type RuntimeState struct {
	AuthSessions    *authSessionStore
	Security        *securityHardeningStore
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
		ServerBridge:             &serverBridgeStore{servers: map[string]bridgeServerRecord{}, joins: map[string]bridgeJoinRecord{}, textures: map[string]bridgeTextureRecord{}},
		Maintenance:              &maintenanceGate{},
		PackageMutation:          &sync.Mutex{},
		RateLimiter:              ratelimit.NewMemory(),
		RateLimitEnabled:         true,
		RateLimitGlobalPerMinute: 1200,
		RateLimitAuthPerMinute:   20,
	}
}
