package officialminecraft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMojangProfileTransientRetry0427(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/minecraft/profile" {
			t.Errorf("Неожиданный путь %q", r.URL.Path)
		}
		n := calls.Add(1)
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"slow_down"}`))
			return
		}
		w.Write([]byte(`{"id":"123456781234123412341234567890ab","name":"Player"}`))
	}))
	defer server.Close()
	c := New()
	c.minecraft = server.URL
	p, err := c.Profile(context.Background(), "token")
	if err != nil || p.Name != "Player" || calls.Load() != 3 {
		t.Fatalf("повторная загрузка профиля: %+v %v; попыток=%d", p, err, calls.Load())
	}
}
func TestMojangWritesNeverAutomaticallyRetried0427(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"temporarily_unavailable"}`))
	}))
	defer server.Close()
	c := New()
	c.microsoft = server.URL
	_, err := c.Complete(context.Background(), "client", "device-code")
	if err == nil || !strings.Contains(err.Error(), "temporarily_unavailable") || calls.Load() != 1 {
		t.Fatalf("POST-запрос неожиданно повторён: %v %d", err, calls.Load())
	}
}

// MojangSupport никогда не должен превращать некорректную идентичность в
// аутентифицированную связь NeverLauncher, даже если внешний сервис вернул HTTP 200.
func TestMojangProfileIdentityValidation0496(t *testing.T) {
	for _, tc := range []struct{ name, id string }{
		{"ValidName", "123456781234123412341234567890ab"},
		{"with space", "123456781234123412341234567890ab"},
		{"control\nname", "123456781234123412341234567890ab"},
		{"a", "123456781234123412341234567890ab"},
		{"ValidName", "bad"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + tc.id + `","name":` + strconv.Quote(tc.name) + `}`))
		}))
		c := New()
		c.minecraft = srv.URL
		_, err := c.Profile(context.Background(), "token")
		srv.Close()
		shouldPass := tc.name == "ValidName" && len(tc.id) == 32
		if shouldPass != (err == nil) {
			t.Fatalf("проверка профиля: имя=%q, идентификатор=%q, ошибка=%v", tc.name, tc.id, err)
		}
	}
}
