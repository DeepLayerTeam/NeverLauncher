//go:build !launcher_nopgx

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"sync/atomic"
)

// This test talks to an actual PostgreSQL 16 server and two independent API
// listeners, repositories, session DB connections and Federation cores. No
// in-memory state is shared between replicas. CI must set the DSN explicitly.
func TestSecurityRealAuthPostgresTwoReplicas02912(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SECURITY_E2E_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_SECURITY_E2E_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	firstRepo := repository.NewSQLRepository("pgx", dsn, "https://api.example.test")
	secondRepo := repository.NewSQLRepository("pgx", dsn, "https://api.example.test")
	// The canonical catalogue must be applied through the production repository.
	if r, ok := firstRepo.(*repository.SQLRepository); ok {
		if _, err := r.ApplyMigrations(ctx); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("SQL repository initialization failed")
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ids := [2]string{"auth-e2e-a-" + suffix, "auth-e2e-b-" + suffix}
	issuers := [2]string{"https://issuer-a.example.test", "https://issuer-b.example.test"}
	for i, id := range ids {
		if _, err := firstRepo.SaveUser(model.User{ID: id, Email: id + "@example.test", RoleID: "player", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		if _, err := firstRepo.SaveAuthIdentity(model.AuthIdentity{UserID: id, Provider: "issuer-e2e", Issuer: issuers[i], Subject: "same-subject", Email: "shared@example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{Environment: "test", RepositoryDriver: "postgres", SQLDriver: "pgx", DatabaseDSN: dsn, PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-security-e2e"}
	type replica struct {
		server *httptest.Server
		state  *RuntimeState
	}
	newReplica := func(repo repository.Repository) replica {
		t.Helper()
		state := NewRuntimeState()
		if err := ConfigureAuthCore111(cfg, state); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = state.AuthSessions.persistent.db.Close() })
		core := federation.New(repo)
		if err := core.Register(dualIssuerConnector02912{calls: &atomic.Int64{}}); err != nil {
			t.Fatal(err)
		}
		if err := core.ConfigureRouting(federation.RoutingConfig{Version: 1, DefaultProvider: "issuer-e2e"}); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer((Server{Version: "0.29.12", Config: cfg, Repo: repo, State: state, Federation: core}).Handler())
		t.Cleanup(server.Close)
		return replica{server, state}
	}
	a := newReplica(firstRepo)
	b := newReplica(secondRepo)
	client := &http.Client{Timeout: 10 * time.Second}
	login := func(base, secret string, expect int) authHTTPResult02912 {
		t.Helper()
		data := securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, fmt.Sprintf(`{"identifier":"shared@example.test","password":%q}`, secret), "", expect)
		var result authHTTPResult02912
		if expect == http.StatusOK {
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	first := login(a.server.URL, "valid-password-issuer-a", http.StatusOK)
	second := login(b.server.URL, "valid-password-issuer-b", http.StatusOK)
	if first.Data.User.ID != ids[0] || second.Data.User.ID != ids[1] {
		t.Fatalf("issuer crossed accounts: %s %s", first.Data.User.ID, second.Data.User.ID)
	}
	securityHTTP02912(t, client, b.server.URL+"/api/v1/auth/sessions", http.MethodGet, "", first.Data.Tokens.AccessToken, http.StatusOK)
	rotatedBody := securityHTTP02912(t, client, b.server.URL+"/api/v1/auth/refresh", http.MethodPost, fmt.Sprintf(`{"refreshToken":%q}`, first.Data.Tokens.RefreshToken), "", http.StatusOK)
	var rotated authHTTPResult02912
	if err := json.Unmarshal(rotatedBody, &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Data.Tokens.RefreshToken == first.Data.Tokens.RefreshToken || rotated.Data.Tokens.RefreshToken == "" {
		t.Fatal("cross-replica refresh did not rotate")
	}
	securityHTTP02912(t, client, a.server.URL+"/api/v1/auth/refresh", http.MethodPost, fmt.Sprintf(`{"refreshToken":%q}`, first.Data.Tokens.RefreshToken), "", http.StatusUnauthorized)
	securityHTTP02912(t, client, b.server.URL+"/api/v1/auth/sessions", http.MethodGet, "", rotated.Data.Tokens.AccessToken, http.StatusUnauthorized)
	securityHTTP02912(t, client, a.server.URL+"/api/v1/auth/sessions", http.MethodGet, "", second.Data.Tokens.AccessToken, http.StatusOK)
	banStore, ok := firstRepo.(repository.ProtectionBanStore)
	if !ok {
		t.Fatal("production ban repository required")
	}
	if err := banStore.SetProtectionBan(ctx, repository.ProtectionBan{UserID: ids[1], Actor: ids[0], Reason: "cross-replica security e2e"}); err != nil {
		t.Fatal(err)
	}
	securityHTTP02912(t, client, b.server.URL+"/api/v1/auth/sessions", http.MethodGet, "", second.Data.Tokens.AccessToken, http.StatusUnauthorized)
	login(b.server.URL, "valid-password-issuer-b", http.StatusForbidden)
	if _, err := banStore.RevokeProtectionBan(ctx, ids[1], ids[0]); err != nil {
		t.Fatal(err)
	}
	third := login(b.server.URL, "valid-password-issuer-b", http.StatusOK)
	if third.Data.Tokens.RefreshToken == second.Data.Tokens.RefreshToken {
		t.Fatal("unban resurrected old token")
	}
	securityHTTP02912(t, client, a.server.URL+"/api/v1/auth/sessions", http.MethodGet, "", second.Data.Tokens.AccessToken, http.StatusUnauthorized)
}
