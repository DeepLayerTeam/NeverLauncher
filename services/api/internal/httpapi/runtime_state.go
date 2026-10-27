package httpapi

import (
	"io"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/serverbridgeha"
)

type RuntimeState struct {
	productRuntimeCloser io.Closer
	AuthSessions         *authSessionStore
	Security             *securityHardeningStore
	Passkeys             *passkeyStore117
	ServerBridge         *serverBridgeStore
	Maintenance          *maintenanceGate
	PackageMutation      *sync.Mutex
	BackendLifecycle0289 *BackendLifecycle0289

	RateLimiter                    ratelimit.Limiter
	RateLimitEnabled               bool
	RateLimitGlobalPerMinute       int
	RateLimitAuthPerMinute         int
	RateLimitServerBridgePerMinute int
	RateLimitFailClosed            bool
	TrustedProxies                 *trustedProxySet
	ServerBridgeCoordinator        serverbridgeha.Coordinator
	ServerBridgeReplicaID          string
	ServerBridgeHARequired         bool
}

func NewRuntimeState() *RuntimeState {
	return &RuntimeState{
		AuthSessions:                   newAuthSessionStore111(),
		Security:                       &securityHardeningStore{mfa: map[string]mfaRecord{}, failedLogins: map[string]loginFailureRecord{}, passwordResets: map[string]oneTimeSecurityToken{}, emailTokens: map[string]oneTimeSecurityToken{}, emailVerified: map[string]bool{}},
		Passkeys:                       newPasskeyStore117(),
		ServerBridge:                   &serverBridgeStore{servers: map[string]bridgeServerRecord{}, joins: map[string]bridgeJoinRecord{}, textures: map[string]bridgeTextureRecord{}, nodeNonces: map[string]time.Time{}, controlCommands: map[string]model.ServerBridgeControlCommand{}, controlIdempotency: map[string]string{}, routing: map[string]model.ServerBridgeRoutingSnapshot{}},
		Maintenance:                    &maintenanceGate{},
		PackageMutation:                &sync.Mutex{},
		RateLimiter:                    ratelimit.NewMemory(),
		RateLimitEnabled:               true,
		RateLimitGlobalPerMinute:       1200,
		RateLimitAuthPerMinute:         20,
		RateLimitServerBridgePerMinute: 6000,
	}
}

// CloseProductRuntime releases the exclusive single-node SQLite owner lock.
// Call after HTTP requests and workers have stopped.
func (s *RuntimeState) CloseProductRuntime() error {
	if s == nil || s.productRuntimeCloser == nil {
		return nil
	}
	return s.productRuntimeCloser.Close()
}
