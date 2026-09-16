package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

const http114Secret = "0123456789abcdef0123456789abcdef-http114"

func TestFederationCore114RegistersAndAuthenticatesHTTPProvider(t *testing.T) {
	t.Setenv("NL_HTTP_114_SECRET", http114Secret)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !verifyHTTP114Request(r, body) {
			t.Errorf("invalid HTTP connector request signature")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/health" {
			writeHTTP114Signed(w, r, http.StatusOK, map[string]any{"protocolVersion": "neverlauncher-http-auth/1", "issuer": "cms-fixture", "status": "ok"})
			return
		}
		if r.URL.Path != "/authenticate" {
			writeHTTP114Signed(w, r, http.StatusNotFound, map[string]any{"protocolVersion": "neverlauncher-http-auth/1", "issuer": "cms-fixture", "error": map[string]any{"code": "identity_not_found"}})
			return
		}
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
		}
		if request["identifier"] != "player@example.test" || request["password"] != "secret" {
			writeHTTP114Signed(w, r, http.StatusUnauthorized, map[string]any{"protocolVersion": "neverlauncher-http-auth/1", "issuer": "cms-fixture", "error": map[string]any{"code": "invalid_credentials"}})
			return
		}
		writeHTTP114Signed(w, r, http.StatusOK, map[string]any{
			"protocolVersion": "neverlauncher-http-auth/1", "issuer": "cms-fixture", "subject": "cms-user-42",
			"email": "player@example.test", "username": "player", "displayName": "HTTP Player",
			"groups": []string{"vip"}, "roles": []string{"member"}, "authMethods": []string{"password"},
			"providerToken": "must-never-become-never-token",
		})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	caPath := t.TempDir() + "/http114-ca.pem"
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	providers, err := json.Marshal([]map[string]any{{
		"id": "cms", "displayName": "CMS", "baseUrl": server.URL, "issuer": "cms-fixture",
		"hostAllowlist": []string{parsed.Hostname()}, "allowedCidrs": []string{"127.0.0.1/32", "::1/128"},
		"hmac":         map[string]any{"keyId": "fixture-key", "secretEnv": "NL_HTTP_114_SECRET"},
		"mtls":         map[string]any{"caFile": caPath},
		"provisioning": map[string]any{"mode": "jit", "defaultRole": "player"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	repo := repository.NewMemoryRepository("https://neverlauncher.example.test")
	core, err := NewFederationCore114(context.Background(), repo, config.Config{AuthHTTPProvidersJSON: string(providers)})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	result, err := core.AuthenticatePassword(context.Background(), "cms", authconnector.PasswordRequest{Identifier: "player@example.test", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Provider.ID != "cms" || result.Identity.Subject != "cms-user-42" || result.User.Email != "player@example.test" {
		t.Fatalf("unexpected federation result: %+v", result)
	}
	if result.User.PasswordHash != "" {
		t.Fatal("HTTP JIT user unexpectedly received a local password hash")
	}
	linked, err := repo.GetAuthIdentity("cms", "cms-user-42")
	if err != nil || linked.UserID != result.User.ID {
		t.Fatalf("HTTP identity was not persisted: %+v err=%v", linked, err)
	}
}

func verifyHTTP114Request(r *http.Request, body []byte) bool {
	timestamp := r.Header.Get("X-NeverLauncher-Timestamp")
	nonce := r.Header.Get("X-NeverLauncher-Nonce")
	provided, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-NeverLauncher-Signature"), "v1="))
	if err != nil || r.Header.Get("X-NeverLauncher-Key-Id") != "fixture-key" {
		return false
	}
	sum := sha256.Sum256(body)
	canonical := strings.ToUpper(r.Method) + "\n" + r.URL.EscapedPath() + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(http114Secret))
	_, _ = mac.Write([]byte(canonical))
	return hmac.Equal(mac.Sum(nil), provided)
}

func writeHTTP114Signed(w http.ResponseWriter, r *http.Request, status int, value any) {
	body, _ := json.Marshal(value)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := r.Header.Get("X-NeverLauncher-Nonce")
	sum := sha256.Sum256(body)
	canonical := "RESPONSE\n" + strconv.Itoa(status) + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(http114Secret))
	_, _ = mac.Write([]byte(canonical))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-NeverLauncher-Key-Id", "fixture-key")
	w.Header().Set("X-NeverLauncher-Timestamp", timestamp)
	w.Header().Set("X-NeverLauncher-Nonce", nonce)
	w.Header().Set("X-NeverLauncher-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
