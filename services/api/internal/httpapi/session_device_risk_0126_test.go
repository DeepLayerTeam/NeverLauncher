package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

type boundSession0126 struct {
	PreBindAccess string
	Access        string
	Refresh       string
	DeviceID      string
	SessionID     string
	UserID        string
	BindingEpoch  int64
	Private       ed25519.PrivateKey
}

func registerBoundSession0126(t *testing.T, h http.Handler) boundSession0126 {
	t.Helper()
	pre, refresh := deviceTrustLogin0121(t, h, "risk-binding-test")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", pre, map[string]any{
		"name": "Risk-bound workstation", "platform": "linux", "clientVersion": "0.12.6",
	})
	if code != http.StatusOK {
		t.Fatalf("register begin status=%d body=%#v", code, out)
	}
	begin := deviceTrustData0121(t, out)
	payload, _ := begin["signingPayload"].(string)
	code, out = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", pre, map[string]any{
		"challengeId": begin["challengeId"], "deviceId": begin["deviceId"], "challenge": begin["challenge"],
		"publicKey": base64.RawURLEncoding.EncodeToString(pub),
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload))),
	})
	if code != http.StatusCreated {
		t.Fatalf("register complete status=%d body=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	session, _ := data["session"].(map[string]any)
	access, _ := data["accessToken"].(string)
	device, _ := data["device"].(map[string]any)
	epoch, _ := session["bindingEpoch"].(float64)
	result := boundSession0126{
		PreBindAccess: pre,
		Access:        access,
		Refresh:       refresh,
		DeviceID:      device["id"].(string),
		SessionID:     session["id"].(string),
		UserID:        session["userId"].(string),
		BindingEpoch:  int64(epoch),
		Private:       priv,
	}
	if result.Access == "" || result.BindingEpoch < 2 {
		t.Fatalf("binding epoch/access token not rotated after bind: %#v", data)
	}
	return result
}

func refreshProof0126(session boundSession0126, refresh string) string {
	payload := sessionRefreshProofPayload0126(refresh, authSessionRecord{
		ID:              session.SessionID,
		UserID:          session.UserID,
		TrustedDeviceID: session.DeviceID,
		BindingEpoch:    session.BindingEpoch,
	})
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(session.Private, []byte(payload)))
}

func TestSessionDeviceBindingInvalidatesPreBindTokenAndRequiresRefreshProof0126(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-session-device-risk", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.6", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	bound := registerBoundSession0126(t, h)

	code, _ := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", bound.PreBindAccess, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("access token minted before device binding survived binding_epoch change: %d", code)
	}

	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": bound.Refresh})
	if code != http.StatusPreconditionRequired {
		t.Fatalf("bound refresh succeeded without device proof: status=%d body=%#v", code, out)
	}

	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	wrongPayload := sessionRefreshProofPayload0126(bound.Refresh, authSessionRecord{ID: bound.SessionID, UserID: bound.UserID, TrustedDeviceID: bound.DeviceID, BindingEpoch: bound.BindingEpoch})
	wrongSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(wrongPrivate, []byte(wrongPayload)))
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": bound.Refresh, "deviceId": bound.DeviceID, "deviceSignature": wrongSig})
	if code != http.StatusPreconditionRequired {
		t.Fatalf("wrong refresh device proof was accepted or consumed token: %d", code)
	}

	proof := refreshProof0126(bound, bound.Refresh)
	code, out = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": bound.Refresh, "deviceId": bound.DeviceID, "deviceSignature": proof})
	if code != http.StatusOK {
		t.Fatalf("valid bound refresh failed: status=%d body=%#v", code, out)
	}
	rotated := deviceTrustData0121(t, out)
	tokens, _ := rotated["tokens"].(map[string]any)
	newRefresh, _ := tokens["refreshToken"].(string)
	if newRefresh == "" || newRefresh == bound.Refresh {
		t.Fatalf("refresh token was not rotated: %#v", tokens)
	}

	// Replaying the consumed token still triggers the pre-existing family-wide
	// reuse response. The freshly issued replacement must then be unusable.
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": bound.Refresh, "deviceId": bound.DeviceID, "deviceSignature": proof})
	if code != http.StatusUnauthorized {
		t.Fatalf("consumed refresh replay was not rejected: %d", code)
	}
	newProof := refreshProof0126(bound, newRefresh)
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": newRefresh, "deviceId": bound.DeviceID, "deviceSignature": newProof})
	if code != http.StatusUnauthorized {
		t.Fatalf("refresh family survived replay compromise: %d", code)
	}
}

func TestSessionRiskUserAgentDriftIsPersistedAndRequiresStepUp0126(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-session-risk-drift", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.6", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	bound := registerBoundSession0126(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+bound.Access)
	req.Header.Set("User-Agent", "NeverLauncher-DeviceTrust-Test/0.12.6-drift")
	req.RemoteAddr = "203.0.113.10:4242"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ordinary request should remain available for step-up recovery: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	data := deviceTrustData0121(t, out)
	items, _ := data["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("unexpected session list: %#v", data)
	}
	session, _ := items[0].(map[string]any)
	if session["riskAction"] != "step-up" || session["riskState"] != "elevated" || session["riskScore"].(float64) < 35 {
		t.Fatalf("user-agent drift did not become an enforceable risk decision: %#v", session)
	}

	// A token may otherwise contain a fresh phishing-resistant auth result, but
	// a newer risk event must force a new ceremony before sensitive operations.
	now := time.Now().UTC()
	claims := authClaims{AuthStrength: "phishing-resistant", AuthTime: now.Add(-time.Minute).Unix(), RiskState: "elevated", RiskScore: 35, RiskAction: "step-up", RiskUpdatedAt: now.Unix()}
	riskRR := httptest.NewRecorder()
	if !(Server{}).writeRiskRequirement0126(riskRR, claims) || riskRR.Code != http.StatusPreconditionRequired {
		t.Fatalf("risk decision did not enforce step-up: status=%d body=%s", riskRR.Code, riskRR.Body.String())
	}
}

func TestRefreshProofCanonicalPayloadDoesNotContainRefreshSecret0126(t *testing.T) {
	rec := authSessionRecord{ID: "sess-1", UserID: "user-1", TrustedDeviceID: "device-1", BindingEpoch: 7}
	secret := "nlr_super-secret-refresh-token"
	payload := sessionRefreshProofPayload0126(secret, rec)
	if bytes.Contains([]byte(payload), []byte(secret)) {
		t.Fatal("refresh secret leaked into signed canonical payload")
	}
	if !bytes.Contains([]byte(payload), []byte("binding-epoch=7\n")) || !bytes.Contains([]byte(payload), []byte("refresh-token-sha256=")) {
		t.Fatalf("canonical payload is missing binding material: %q", payload)
	}
}

func TestSessionRiskActionPrecedence0126(t *testing.T) {
	state, score, action := evaluateRiskReasons0126([]string{"user-agent-changed", "device-attestation-stale"})
	if state != "elevated" || score != 75 || action != "reattest" {
		t.Fatalf("stale device attestation must outrank account step-up: state=%s score=%d action=%s", state, score, action)
	}
	state, score, action = evaluateRiskReasons0126([]string{"device-attestation-stale", "trusted-device-revoked"})
	if state != "compromised" || score != 100 || action != "revoke" {
		t.Fatalf("revocation must outrank re-attestation: state=%s score=%d action=%s", state, score, action)
	}
}
