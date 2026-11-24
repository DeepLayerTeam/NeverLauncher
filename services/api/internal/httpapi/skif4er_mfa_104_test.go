package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

type skiMFAFixture104 struct{ oidcFixtureConnector115 }

func (skiMFAFixture104) Metadata() authconnector.Metadata {
	m := (oidcFixtureConnector115{}).Metadata()
	m.ID = "skif4er-id"
	return m
}

func TestSkif4erMFA104Lifecycle(t *testing.T) {
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: strings.Repeat("k", 40)}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	core := federation.New(repo)
	if err := core.RegisterWithPolicy(skiMFAFixture104{}, federation.ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	s := Server{Version: "1.0.4", Config: cfg, Repo: repo, Federation: core, State: NewRuntimeState()}
	s.State.RateLimitEnabled = false
	h := s.Handler()
	call := func(path string, body any, bearer string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var result map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		data, _ := result["data"].(map[string]any)
		return w, data
	}
	const base = "/api/v1/auth/oidc/skif4er-id"
	callback := func() map[string]any {
		t.Helper()
		w, b := call(base+"/begin", map[string]string{"deviceId": "desktop-client"}, "")
		if w.Code != 200 {
			t.Fatalf("begin %d %s", w.Code, w.Body)
		}
		return map[string]any{"code": "fixture-code", "state": b["state"], "transaction": b["transaction"]}
	}
	w, first := call(base+"/complete", callback(), "")
	if w.Code != 200 {
		t.Fatalf("initial login %d %s", w.Code, w.Body)
	}
	user := first["user"].(map[string]any)["id"].(string)
	tokens := first["tokens"].(map[string]any)
	oldAccess := tokens["accessToken"].(string)
	secret, err := generateTOTPSecret902()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.State.Security.startTOTPEnrollment(user, secret); err != nil {
		t.Fatal(err)
	}
	if !s.State.Security.finishTOTPEnrollment(user, currentTOTPCode902(secret, time.Now())) {
		t.Fatal("enroll TOTP")
	}
	// Old single-factor access and refresh cannot bypass the newly enabled MFA.
	if _, err = s.verifyAdminToken(oldAccess); err == nil {
		t.Fatal("old single-factor session accepted")
	}
	w, _ = call("/api/v1/auth/refresh", map[string]any{"refreshToken": tokens["refreshToken"]}, "")
	if w.Code != 401 {
		t.Fatalf("old refresh %d %s", w.Code, w.Body)
	}
	cb := callback()
	w, pending := call(base+"/complete", cb, "")
	if w.Code != 202 || pending["method"] != "totp-or-recovery" || pending["tokens"] != nil {
		t.Fatalf("MFA pending %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("MFA response is cacheable")
	}
	w, _ = call(base+"/complete", cb, "")
	if w.Code != 401 {
		t.Fatalf("callback replay %d", w.Code)
	}
	proof := map[string]any{"transactionToken": pending["transactionToken"], "totp": currentTOTPCode902(secret, time.Now())}
	w, complete := call(base+"/mfa/complete", proof, "")
	if w.Code != 200 {
		t.Fatalf("complete MFA %d %s", w.Code, w.Body)
	}
	tokens = complete["tokens"].(map[string]any)
	w, _ = call(base+"/mfa/complete", proof, "")
	if w.Code != 401 {
		t.Fatalf("MFA replay %d", w.Code)
	}
	// A fresh OIDC callback cannot reuse the same verified TOTP code.
	w, pending = call(base+"/complete", callback(), "")
	if w.Code != 202 {
		t.Fatalf("second challenge %d", w.Code)
	}
	proof["transactionToken"] = pending["transactionToken"]
	w, _ = call(base+"/mfa/complete", proof, "")
	if w.Code != 401 {
		t.Fatalf("TOTP reuse %d", w.Code)
	}
	w, rotated := call("/api/v1/auth/refresh", map[string]any{"refreshToken": tokens["refreshToken"]}, "")
	if w.Code != 200 {
		t.Fatalf("MFA refresh %d %s", w.Code, w.Body)
	}
	next := rotated["tokens"].(map[string]any)
	w, _ = call("/api/v1/auth/logout", map[string]any{}, next["accessToken"].(string))
	if w.Code != 200 {
		t.Fatalf("logout %d %s", w.Code, w.Body)
	}
	w, _ = call("/api/v1/auth/refresh", map[string]any{"refreshToken": next["refreshToken"]}, "")
	if w.Code != 401 {
		t.Fatalf("revoked refresh %d", w.Code)
	}
	recovery, err := s.State.Security.generateRecoveryCodes(user, 1)
	if err != nil {
		t.Fatal(err)
	}
	w, pending = call(base+"/complete", callback(), "")
	if w.Code != 202 {
		t.Fatalf("recovery challenge %d %s", w.Code, w.Body)
	}
	recoveryProof := map[string]any{"transactionToken": pending["transactionToken"], "recoveryCode": recovery[0]}
	w, _ = call(base+"/mfa/complete", recoveryProof, "")
	if w.Code != 200 {
		t.Fatalf("recovery MFA %d %s", w.Code, w.Body)
	}
	if s.State.Security.consumeRecoveryCode(user, recovery[0]) {
		t.Fatal("recovery code still valid after login")
	}

}

func TestSkif4erMFA104InvalidTOTPSecret(t *testing.T) {
	if verifyTOTPCode902("invalid!", "000000", time.Now()) {
		t.Fatal("invalid Base32 secret must never validate")
	}
}
