//go:build !launcher_nopgx

package httpapi

import (
	"context"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Обязательны два независимых соединения PostgreSQL; локальный кэш процесса не
// защищает от одновременных OAuth-callback на HA-репликах API.
func TestBrowserNonceAcrossPostgresReplicas0525(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SECURITY_E2E_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	first := repository.NewSQLRepository("pgx", dsn, "https://launcher.example.test")
	second := repository.NewSQLRepository("pgx", dsn, "https://launcher.example.test")
	installer, ok := first.(*repository.SQLRepository)
	if !ok {
		t.Fatal("SQL repository unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := installer.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := randomURLToken115(32)
	if err != nil {
		t.Fatal(err)
	}
	tx := oidcTransaction115{ProviderID: "oidc-prod-test", State: state, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	servers := []Server{{Repo: first}, {Repo: second}}
	var wg sync.WaitGroup
	accepted := make(chan bool, len(servers))
	for _, srv := range servers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			allowed := s.claimBrowserTransaction0525(rec, httptest.NewRequest("POST", "/", nil), tx)
			if !allowed && rec.Code != 401 {
				t.Errorf("Отклонено с HTTP %d, ожидался 401", rec.Code)
			}
			accepted <- allowed
		}(srv)
	}
	wg.Wait()
	close(accepted)
	count := 0
	for ok := range accepted {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("PostgreSQL принял %d одновременных завершений браузерной авторизации", count)
	}
}
