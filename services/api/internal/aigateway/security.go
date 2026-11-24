package aigateway

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrSensitive = errors.New("AI prompt contains a likely credential")
var ErrCoolingDown = errors.New("AI provider temporarily unavailable")
var ErrUpstreamRate = errors.New("AI provider rate limited")

// Conservative detection of recognizable credentials, not a general DLP system.
// Do not include the matching value in errors, audit events or logs.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:sk-(?:proj-|svcacct-)?[a-z0-9_-]{16,}|gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bBearer\s+[a-z0-9._~+/=-]{12,}`),
	regexp.MustCompile(`(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\\?["']?\s*[:=]\s*\\?["']?[^\s"'\\,;}{]{8,}`),
}

func sensitivePrompt(prompt, key string) bool {
	if len(key) >= 12 && strings.Contains(prompt, key) {
		return true
	}
	for _, pattern := range credentialPatterns {
		if pattern.MatchString(prompt) {
			return true
		}
	}
	return false
}

// A process-local admission gate. No POST is retried: even a failed response
// can have been billed. A bounded cooldown avoids repeatedly reserving budget
// when the provider is unhealthy. Existing in-flight calls are unaffected.
type providerGate struct {
	mu       sync.Mutex
	until    time.Time
	failures int
	probing  bool
}

func (g *providerGate) enter(now time.Time) (allowed, probe bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.until) || g.probing {
		return false, false
	}
	if !g.until.IsZero() {
		g.probing = true
		return true, true
	}
	return true, false
}
func (g *providerGate) abandon(probe bool) {
	if probe {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.probing = false
	}
}
func (g *providerGate) result(now time.Time, probe bool, err error, delay time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if probe {
		g.probing = false
	}
	if err == nil {
		if (probe && !now.Before(g.until)) || g.until.IsZero() {
			g.until = time.Time{}
			g.failures = 0
		}
		return
	}
	if !errors.Is(err, ErrProvider) && !errors.Is(err, ErrUpstreamRate) {
		return
	}
	g.failures++
	if errors.Is(err, ErrUpstreamRate) || probe || g.failures >= 3 {
		if delay < 30*time.Second {
			delay = 30 * time.Second
		}
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		if next := now.Add(delay); next.After(g.until) {
			g.until = next
		}
	}
}
func retryDelay(value string, now time.Time) time.Duration {
	if n, e := strconv.ParseInt(strings.TrimSpace(value), 10, 32); e == nil && n >= 0 {
		if n > 300 {
			n = 300
		}
		return time.Duration(n) * time.Second
	}
	if t, e := http.ParseTime(value); e == nil {
		return t.Sub(now)
	}
	return 0
}
