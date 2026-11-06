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
		t.Fatalf("ожидалось ограничение частоты запросов, получено %d", code)
	}
	st.mu.Lock()
	st.budget.window = time.Now().Add(-time.Second)
	st.mu.Unlock()
	if code := do(); code != 200 {
		t.Fatalf("окно ограничения не сброшено: %d", code)
	}
	st.mu.Lock()
	if st.budget.output != 6 || st.budget.rejected != 1 || st.budget.active != 0 {
		t.Fatalf("неверные счётчики ресурсов: %+v", st.budget)
	}
	if st.budget.chargeLocked03113(3, policy) {
		t.Fatal("обойдён лимит размера вывода")
	}
	if st.budget.output != 6 {
		t.Fatal("переполнение изменило подсчёт учтённых байтов")
	}
	st.mu.Unlock()
}
func TestHostBudget03113ConcurrentAndReset(t *testing.T) {
	p := &model.ExtensionSandboxPolicy{Mode: "isolated", MaxRequestsPerSecond: 64, MaxOutputBytes: 4096}
	var budget hostBudget03113
	now := time.Now()
	for i := 0; i < maxConcurrentRequests03113; i++ {
		if !budget.admitLocked03113(now, p) {
			t.Fatalf("слот %d отклонён", i)
		}
	}
	if budget.admitLocked03113(now, p) {
		t.Fatal("обойдён лимит параллельных операций")
	}
	if budget.rejected != 1 {
		t.Fatal("отказ не учтён")
	}
	budget.active--
	if !budget.admitLocked03113(now, p) {
		t.Fatal("освобождённый слот недоступен для повторного использования")
	}
	budget.active = 0
	for i := 0; i < 64-maxConcurrentRequests03113-1; i++ {
		if !budget.admitLocked03113(now, p) {
			t.Fatalf("слот ограничения частоты %d", i)
		}
		budget.active--
	}
	if budget.admitLocked03113(now, p) {
		t.Fatal("обойдён посекундный лимит")
	}
	if !budget.admitLocked03113(now.Add(time.Second), p) {
		t.Fatal("Новое окно ошибочно не принято")
	}
	if budget.chargeLocked03113(-1, p) {
		t.Fatal("Отрицательное выходное значение ошибочно принято")
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
		t.Fatalf("неверный лимит ресурсов: %+v", st.budget)
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
		t.Fatal("поведение промежуточного обработчика авторизации изменилось")
	}
	if request("real-token") != 204 {
		t.Fatal("анонимный запрос исчерпал лимит экземпляра")
	}
}
