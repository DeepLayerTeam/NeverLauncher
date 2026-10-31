package extensionhost

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestHostBudget03113RateAndOutput(t *testing.T) {
	policy := &model.ExtensionSandboxPolicy{Version: "1", Mode: "isolated", MaxRequestsPerSecond: 2, MaxOutputBytes: 8}
	st := &processState{token: "sandbox-secret", manifest: model.ExtensionManifest{Sandbox: policy}}
	s := &Supervisor{tokens: map[string]*processState{st.token: st}}
	handler := s.limitedHostHandler03113(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("OK")) }))
	do := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/test", nil)
		r.Header.Set("Authorization", "Bearer sandbox-secret")
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := do(); code != 200 {
		t.Fatal(code)
	}
	if code := do(); code != 200 {
		t.Fatal(code)
	}
	if code := do(); code != 429 {
		t.Fatalf("expected rate limit got %d", code)
	}
	st.mu.Lock()
	st.budget.window = time.Now().Add(-time.Second)
	st.mu.Unlock()
	if code := do(); code != 200 {
		t.Fatalf("window did not reset: %d", code)
	}
	st.mu.Lock()
	if st.budget.output != 6 || st.budget.rejected != 1 || st.budget.active != 0 {
		t.Fatalf("bad resource counters %+v", st.budget)
	}
	if st.budget.chargeLocked03113(3, policy) {
		t.Fatal("output budget bypassed")
	}
	if st.budget.output != 6 {
		t.Fatal("overflow changed accounted bytes")
	}
	st.mu.Unlock()
}
func TestHostBudget03113ConcurrentAndReset(t *testing.T) {
	p := &model.ExtensionSandboxPolicy{Mode: "isolated", MaxRequestsPerSecond: 64, MaxOutputBytes: 4096}
	var budget hostBudget03113
	now := time.Now()
	for i := 0; i < maxConcurrentRequests03113; i++ {
		if !budget.admitLocked03113(now, p) {
			t.Fatalf("slot %d denied", i)
		}
	}
	if budget.admitLocked03113(now, p) {
		t.Fatal("concurrent budget bypassed")
	}
	if budget.rejected != 1 {
		t.Fatal("rejection not counted")
	}
	budget.active--
	if !budget.admitLocked03113(now, p) {
		t.Fatal("released slot not reusable")
	}
	budget.active = 0
	for i := 0; i < 64-maxConcurrentRequests03113-1; i++ {
		if !budget.admitLocked03113(now, p) {
			t.Fatalf("rate slot %d", i)
		}
		budget.active--
	}
	if budget.admitLocked03113(now, p) {
		t.Fatal("per-second limit bypassed")
	}
	if !budget.admitLocked03113(now.Add(time.Second), p) {
		t.Fatal("new window not accepted")
	}
	if budget.chargeLocked03113(-1, p) {
		t.Fatal("negative output accepted")
	}
}
func TestHostBudget03113Race(t *testing.T) {
	p := &model.ExtensionSandboxPolicy{Mode: "isolated", MaxRequestsPerSecond: 64}
	st := &processState{manifest: model.ExtensionManifest{Sandbox: p}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.mu.Lock()
			if st.budget.admitLocked03113(time.Now(), p) {
				st.budget.chargeLocked03113(64, p)
				st.budget.active--
			}
			st.mu.Unlock()
		}()
	}
	wg.Wait()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.budget.output > defaultOutputBytes03113 || st.budget.active != 0 {
		t.Fatalf("bad budget: %+v", st.budget)
	}
}
func TestHostBudget03113UnauthenticatedDoesNotConsume(t *testing.T) {
	st := &processState{token: "real-token", manifest: model.ExtensionManifest{Sandbox: &model.ExtensionSandboxPolicy{Mode: "isolated", MaxRequestsPerSecond: 1}}}
	s := &Supervisor{tokens: map[string]*processState{"real-token": st}}
	handler := s.limitedHostHandler03113(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	request := func(token string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if request("not-a-token") != 204 {
		t.Fatal("auth middleware behavior changed")
	}
	if request("real-token") != 204 {
		t.Fatal("anonymous depleted instance budget")
	}
}
