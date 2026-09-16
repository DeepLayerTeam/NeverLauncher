package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
)

func (s *RuntimeState) ConfigureProductRuntime(cfg config.Config) error {
	trusted, err := newTrustedProxySet(cfg.TrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("invalid NEVERLAUNCHER_TRUSTED_PROXY_CIDRS: %w", err)
	}
	s.TrustedProxies = trusted
	s.RateLimitEnabled = cfg.RateLimitEnabled
	s.RateLimitGlobalPerMinute = cfg.RateLimitGlobalPerMinute
	s.RateLimitAuthPerMinute = cfg.RateLimitAuthPerMinute
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
		if isSensitiveAuthRoute(r) {
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
	return path == "/api/v1/auth/login" ||
		path == "/api/v1/admin/login" ||
		path == "/api/v1/install/bootstrap-admin" ||
		strings.HasPrefix(path, "/api/v1/auth/passkeys/") ||
		strings.HasPrefix(path, "/api/v1/auth/oidc/") ||
		strings.HasPrefix(path, "/api/v1/auth/microsoft/") ||
		strings.Contains(path, "/password-reset") ||
		strings.Contains(path, "/email-verification")
}
