package extensionhost

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const defaultRequestsPerSecond03113 = 64
const defaultOutputBytes03113 int64 = 8 << 20
const maxConcurrentRequests03113 = 16

// Protected by processState.mu. Budgets are per INSTANCE, never per token/IP/
// connection, so reconnecting the SDK cannot reset enforcement.
type hostBudget03113 struct {
	window   time.Time
	requests int
	active   int
	rejected int64
	output   int64
}

func limits03113(policy *model.ExtensionSandboxPolicy) (int, int64) {
	rps, output := defaultRequestsPerSecond03113, defaultOutputBytes03113
	if policy != nil {
		if policy.MaxRequestsPerSecond > 0 && policy.MaxRequestsPerSecond < rps {
			rps = policy.MaxRequestsPerSecond
		}
		if policy.MaxOutputBytes > 0 && policy.MaxOutputBytes < output {
			output = policy.MaxOutputBytes
		}
	}
	return rps, output
}

func (b *hostBudget03113) admitLocked03113(now time.Time, policy *model.ExtensionSandboxPolicy) bool {
	if b.window.IsZero() || now.Sub(b.window) >= time.Second {
		b.window, b.requests = now, 0
	}
	rps, _ := limits03113(policy)
	if b.requests >= rps || b.active >= maxConcurrentRequests03113 {
		b.rejected++
		return false
	}
	b.requests++
	b.active++
	return true
}
func (b *hostBudget03113) chargeLocked03113(n int64, policy *model.ExtensionSandboxPolicy) bool {
	_, max := limits03113(policy)
	if n < 0 || b.output > max-n {
		return false
	}
	b.output += n
	return true
}

type boundedHostResponse03113 struct {
	http.ResponseWriter
	onWrite  func(int64) bool
	exceeded bool
}

func (w *boundedHostResponse03113) Write(p []byte) (int, error) {
	if !w.onWrite(int64(len(p))) {
		w.exceeded = true
		return 0, http.ErrAbortHandler
	}
	return w.ResponseWriter.Write(p)
}

// Applies to both TCP Host Protocol and the Windows/macOS private IPC proxies.
// Authentication still happens inside handlers. Unrecognized tokens do not
// consume a legitimate instance's quota.
func (s *Supervisor) limitedHostHandler03113(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		s.mu.RLock()
		st := s.tokens[token]
		s.mu.RUnlock()
		if st == nil || subtle.ConstantTimeCompare([]byte(token), []byte(st.token)) != 1 || st.manifest.Sandbox == nil || st.manifest.Sandbox.Mode != "isolated" {
			next.ServeHTTP(w, r)
			return
		}
		st.mu.Lock()
		allowed := st.budget.admitLocked03113(time.Now(), st.manifest.Sandbox)
		st.mu.Unlock()
		if !allowed {
			http.Error(w, "host-request-budget-exceeded", http.StatusTooManyRequests)
			return
		}
		defer func() { st.mu.Lock(); st.budget.active--; st.mu.Unlock() }()
		output := &boundedHostResponse03113{ResponseWriter: w, onWrite: func(n int64) bool {
			st.mu.Lock()
			ok := st.budget.chargeLocked03113(n, st.manifest.Sandbox)
			st.mu.Unlock()
			if !ok {
				go s.failProcess(st, "host-output-budget-exceeded", false)
			}
			return ok
		}}
		next.ServeHTTP(output, r)
	})
}
