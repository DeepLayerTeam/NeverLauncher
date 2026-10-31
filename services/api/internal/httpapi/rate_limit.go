package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/ratelimit"
	"gitflic.ru/skif4er/launcher/services/api/internal/serverbridgeha"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecoord"
)

func (s *RuntimeState) ConfigureProductRuntime(cfg config.Config) error {
	trusted, err := newTrustedProxySet(cfg.TrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("invalid NEVERLAUNCHER_TRUSTED_PROXY_CIDRS: %w", err)
	}
	s.TrustedProxies = trusted
	s.ServerBridgeHARequired = cfg.ServerBridgeHARequired
	// A SQLite HTTP repository must never silently use an in-memory or Redis
	// coordinator: fencing, rate limits and command leases must survive restart.
	if strings.EqualFold(strings.TrimSpace(cfg.RepositoryDriver), "sqlite") {
		if strings.TrimSpace(cfg.SQLiteCoordinatorPath) == "" {
			return fmt.Errorf("SQLite HTTP backend requires durable SQLite coordinator path")
		}
		if filepath.Clean(cfg.SQLiteCoordinatorPath) == filepath.Clean(cfg.DatabaseDSN) {
			return fmt.Errorf("SQLite repository and coordinator require distinct lockable files")
		}
		if cfg.RateLimitEnabled && !cfg.RateLimitFailClosed {
			return fmt.Errorf("SQLite backend rate limiting must fail closed")
		}
	}
	s.ServerBridgeReplicaID = strings.TrimSpace(cfg.ServerBridgeReplicaID)
	if s.ServerBridgeReplicaID == "" {
		hostname, _ := os.Hostname()
		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			hostname = "unknown-host"
		}
		s.ServerBridgeReplicaID = fmt.Sprintf("%s-%d", hostname, os.Getpid())
	}

	// Explicit SQLite single-node path: both coordination and rate limiting
	// share one durable writer. No Redis fallback, no in-memory success path.
	if path := strings.TrimSpace(cfg.SQLiteCoordinatorPath); path != "" {
		if cfg.ServerBridgeHARequired {
			return fmt.Errorf("SQLite single-node cannot satisfy distributed ServerBridge HA")
		}
		if cfg.RateLimitEnabled && !cfg.RateLimitFailClosed {
			return fmt.Errorf("SQLite rate limiting must fail closed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		coordinator, openErr := sqlitecoord.Open(ctx, path)
		cancel()
		if openErr != nil {
			return fmt.Errorf("SQLite single-node coordinator unavailable: %w", openErr)
		}
		s.productRuntimeCloser = coordinator
		s.ServerBridgeCoordinator = coordinator
		s.RateLimiter = coordinator
		s.RateLimitEnabled = cfg.RateLimitEnabled
		s.RateLimitGlobalPerMinute = cfg.RateLimitGlobalPerMinute
		s.RateLimitAuthPerMinute = cfg.RateLimitAuthPerMinute
		s.RateLimitServerBridgePerMinute = cfg.RateLimitServerBridgePerMinute
		s.RateLimitFailClosed = true
		return nil
	}

	// У ServerBridge HA собственный Redis-ограничитель. Он независим от rate limiting:
	// производственная доставка команд не должна молча переходить к локальному состоянию процесса.
	if strings.TrimSpace(cfg.RedisURL) != "" {
		coordinator, coordErr := serverbridgeha.NewRedis(cfg.RedisURL)
		if coordErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			coordErr = coordinator.Health(ctx)
			cancel()
		}
		if coordErr == nil {
			s.ServerBridgeCoordinator = coordinator
		} else if cfg.ServerBridgeHARequired {
			return fmt.Errorf("Redis ServerBridge HA coordinator is required but unavailable: %w", coordErr)
		}
	} else if cfg.ServerBridgeHARequired {
		return fmt.Errorf("Redis ServerBridge HA coordinator is required but NEVERLAUNCHER_REDIS_URL is empty")
	}

	s.RateLimitEnabled = cfg.RateLimitEnabled
	s.RateLimitGlobalPerMinute = cfg.RateLimitGlobalPerMinute
	s.RateLimitAuthPerMinute = cfg.RateLimitAuthPerMinute
	s.RateLimitServerBridgePerMinute = cfg.RateLimitServerBridgePerMinute
	s.RateLimitFailClosed = cfg.RateLimitFailClosed
	if !cfg.RateLimitEnabled {
		s.RateLimiter = ratelimit.NewMemory()
		return nil
	}

	redisLimiter, err := ratelimit.NewRedis(cfg.RedisURL)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = redisLimiter.Health(ctx)
		cancel()
	}
	if err == nil {
		s.RateLimiter = redisLimiter
		return nil
	}
	if cfg.RateLimitFailClosed {
		return fmt.Errorf("Redis rate limiter is required but unavailable: %w", err)
	}
	s.RateLimiter = ratelimit.NewMemory()
	return nil
}

func (s Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.State == nil || !s.State.RateLimitEnabled || strings.HasPrefix(r.URL.Path, "/health") || strings.HasPrefix(r.URL.Path, "/ready") || strings.HasPrefix(r.URL.Path, "/metrics") {
			next.ServeHTTP(w, r)
			return
		}
		limit := s.State.RateLimitGlobalPerMinute
		category := "global"
		if isServerBridgeTraffic0149(r) {
			limit = s.State.RateLimitServerBridgePerMinute
			category = "serverbridge"
		} else if isSensitiveAuthRoute(r) {
			limit = s.State.RateLimitAuthPerMinute
			category = "auth"
		}
		if limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		key := category + "|" + clientIP(r)
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		decision, err := s.State.RateLimiter.Allow(ctx, key, limit, time.Minute)
		cancel()
		if err != nil {
			if s.State.RateLimitFailClosed {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusServiceUnavailable, "rate limiter временно недоступен")
				return
			}
			w.Header().Set("X-RateLimit-Backend", "degraded")
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-RateLimit-Scope", category)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
		resetSeconds := int(decision.ResetAfter.Round(time.Second).Seconds())
		if resetSeconds < 1 {
			resetSeconds = 1
		}
		w.Header().Set("X-RateLimit-Reset", strconv.Itoa(resetSeconds))
		w.Header().Set("X-RateLimit-Backend", s.State.RateLimiter.Backend())
		if !decision.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(resetSeconds))
			writeError(w, http.StatusTooManyRequests, "слишком много запросов")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSensitiveAuthRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	path := r.URL.Path
	return strings.HasPrefix(path, "/authserver/") ||
		path == "/api/v1/auth/login" ||
		path == "/api/v1/admin/login" ||
		path == "/api/v1/install/bootstrap-admin" ||
		(strings.HasPrefix(path, "/api/v1/auth/providers/") && strings.HasSuffix(path, "/link/password")) ||
		strings.HasPrefix(path, "/api/v1/auth/passkeys/") ||
		strings.HasPrefix(path, "/api/v1/auth/oidc/") ||
		strings.HasPrefix(path, "/api/v1/auth/microsoft/") ||
		strings.Contains(path, "/password-reset") ||
		strings.Contains(path, "/email-verification")
}
