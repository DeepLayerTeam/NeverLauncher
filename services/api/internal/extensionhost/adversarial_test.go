package extensionhost

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Независимые соединения и параллельные запросы разделяют счётчики одного
// изолированного расширения; переподключение не сбрасывает лимит экземпляра.
func TestAdversarialHostReconnectAndBurst03114(t *testing.T) {
	policy := &model.ExtensionSandboxPolicy{Mode: "isolated", MaxRequestsPerSecond: 8, MaxOutputBytes: 1024}
	state := &processState{token: "valid-token", manifest: model.ExtensionManifest{Sandbox: policy}}
	supervisor := &Supervisor{tokens: map[string]*processState{state.token: state}}
	handler := supervisor.limitedHostHandler03113(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	var wg sync.WaitGroup
	codes := make(chan int, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/v1/capability", nil)
			r.Header.Set("Authorization", "Bearer valid-token")
			handler.ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	accepted, rejected := 0, 0
	for code := range codes {
		if code == 200 {
			accepted++
		} else if code == 429 {
			rejected++
		} else {
			t.Fatalf("unexpected HTTP code %d", code)
		}
	}
	if accepted != 8 || rejected != 24 {
		t.Fatalf("instance limiter bypass: accepted=%d denied=%d", accepted, rejected)
	}
	state.mu.Lock()
	if state.budget.output != 16 || state.budget.active != 0 || state.budget.rejected != 24 {
		t.Fatalf("counters invalid: %+v", state.budget)
	}
	state.budget.window = time.Now().Add(-2 * time.Second)
	state.mu.Unlock()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/capability", nil)
	r.Header.Set("Authorization", "Bearer valid-token")
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("new window refused %d", w.Code)
	}
}
func TestAdversarialHostQuotaFailsClosed03114(t *testing.T) {
	policy := &model.ExtensionSandboxPolicy{Mode: "isolated", MaxRequestsPerSecond: 64, MaxOutputBytes: 5}
	st := &processState{token: "token", manifest: model.ExtensionManifest{Sandbox: policy}}
	s := &Supervisor{tokens: map[string]*processState{st.token: st}}
	handler := s.limitedHostHandler03113(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("OK")) }))
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer token")
		handler.ServeHTTP(w, r)
		if w.Body.String() != "OK" {
			t.Fatal(w.Body.String())
		}
	}
	st.mu.Lock()
	if st.budget.output != 4 {
		t.Fatalf("expected 4 billed bytes; got %d", st.budget.output)
	}
	st.mu.Unlock()
	// Не запрашивайте шестой байт через супервизор: истечение квоты намеренно
	// асинхронно запускает настоящее завершение процесса.
	st.mu.Lock()
	if st.budget.chargeLocked03113(2, policy) {
		t.Fatal("output over quota admitted")
	}
	st.mu.Unlock()
}
