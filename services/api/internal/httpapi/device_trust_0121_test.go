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

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func deviceTrustRequest0121(t *testing.T, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "NeverLauncher-DeviceTrust-Test/0.12.1")
	req.RemoteAddr = "203.0.113.10:4242"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func deviceTrustData0121(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	v, ok := out["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data: %#v", out)
	}
	return v
}

func deviceTrustLogin0121(t *testing.T, h http.Handler, deviceID string) (string, string) {
	t.Helper()
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "admin@neverlauncher.local", "password": "admin", "deviceId": deviceID})
	if code != http.StatusOK {
		t.Fatalf("login status=%d body=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	tokens, ok := data["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("missing tokens: %#v", data)
	}
	access, _ := tokens["accessToken"].(string)
	refresh, _ := tokens["refreshToken"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("empty tokens: %#v", tokens)
	}
	return access, refresh
}

func TestDeviceTrustRegistrationBindingReplayAndRevocation0121(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.1", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access1, _ := deviceTrustLogin0121(t, h, "legacy-label-a")
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access1, map[string]any{"name": "Workstation", "platform": "linux", "clientVersion": "0.12.1"})
	if code != http.StatusOK {
		t.Fatalf("register begin status=%d body=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	challengeID, _ := begin["challengeId"].(string)
	deviceID, _ := begin["deviceId"].(string)
	challenge, _ := begin["challenge"].(string)
	payload, _ := begin["signingPayload"].(string)
	if challengeID == "" || deviceID == "" || challenge == "" || payload == "" {
		t.Fatalf("incomplete begin payload: %#v", begin)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(payload))
	completeBody := map[string]any{"challengeId": challengeID, "deviceId": deviceID, "challenge": challenge, "publicKey": base64.RawURLEncoding.EncodeToString(pub), "signature": base64.RawURLEncoding.EncodeToString(sig)}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access1, completeBody)
	if code != http.StatusCreated {
		t.Fatalf("register complete status=%d body=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	trustedAccess1, _ := complete["accessToken"].(string)
	if trustedAccess1 == "" {
		t.Fatalf("missing renewed access token: %#v", complete)
	}
	device, _ := complete["device"].(map[string]any)
	if device["trustState"] != "verified" || device["assurance"] != "proof-of-possession" || device["keyFingerprint"] == "" {
		t.Fatalf("bad device: %#v", device)
	}
	if _, leaks := device["publicKey"]; leaks {
		t.Fatalf("public key leaked in API device model: %#v", device)
	}

	code, replayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", trustedAccess1, completeBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("replayed registration challenge status=%d body=%#v", code, replayOut)
	}

	code, trustOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", trustedAccess1, nil)
	if code != http.StatusOK {
		t.Fatalf("trust status=%d body=%#v", code, trustOut)
	}
	trust := deviceTrustData0121(t, trustOut)
	if trust["deviceTrustState"] != "verified" || trust["trustedDeviceId"] != deviceID {
		t.Fatalf("session not device-bound: %#v", trust)
	}

	access2, refresh2 := deviceTrustLogin0121(t, h, "legacy-label-b")
	code, verifyBeginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/verify/begin", access2, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("verify begin status=%d body=%#v", code, verifyBeginOut)
	}
	verifyBegin := deviceTrustData0121(t, verifyBeginOut)
	verifyChallengeID, _ := verifyBegin["challengeId"].(string)
	verifyChallenge, _ := verifyBegin["challenge"].(string)
	verifyPayload, _ := verifyBegin["signingPayload"].(string)
	verifySig := ed25519.Sign(priv, []byte(verifyPayload))
	code, verifyOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/verify/complete", access2, map[string]any{"challengeId": verifyChallengeID, "challenge": verifyChallenge, "signature": base64.RawURLEncoding.EncodeToString(verifySig)})
	if code != http.StatusOK {
		t.Fatalf("verify complete status=%d body=%#v", code, verifyOut)
	}
	trustedAccess2, _ := deviceTrustData0121(t, verifyOut)["accessToken"].(string)
	if trustedAccess2 == "" {
		t.Fatal("second bound access token missing")
	}

	code, listOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices", trustedAccess2, nil)
	if code != http.StatusOK {
		t.Fatalf("list devices status=%d body=%#v", code, listOut)
	}
	items, _ := deviceTrustData0121(t, listOut)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected one device: %#v", listOut)
	}

	code, revokeOut := deviceTrustRequest0121(t, h, http.MethodDelete, "/api/v1/auth/devices/"+deviceID, trustedAccess1, nil)
	if code != http.StatusOK {
		t.Fatalf("device revoke status=%d body=%#v", code, revokeOut)
	}

	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", trustedAccess2, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("bound session survived device revoke: %d", code)
	}
	code, refreshOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": refresh2})
	if code != http.StatusUnauthorized {
		t.Fatalf("refresh family survived device revoke: status=%d body=%#v", code, refreshOut)
	}
}

func TestDeviceTrustRejectsWrongSignatureAndDuplicateKey0121(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.1", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	access, _ := deviceTrustLogin0121(t, h, "client")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	register := func(name string, wrong bool) (int, map[string]any) {
		code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{"name": name})
		if code != http.StatusOK {
			t.Fatalf("begin: %d %#v", code, out)
		}
		d := deviceTrustData0121(t, out)
		payload, _ := d["signingPayload"].(string)
		signKey := priv
		if wrong {
			_, signKey, _ = ed25519.GenerateKey(rand.Reader)
		}
		sig := ed25519.Sign(signKey, []byte(payload))
		return deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{"challengeId": d["challengeId"], "deviceId": d["deviceId"], "challenge": d["challenge"], "publicKey": base64.RawURLEncoding.EncodeToString(pub), "signature": base64.RawURLEncoding.EncodeToString(sig)})
	}
	code, out := register("Bad proof", true)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong signature accepted: %d %#v", code, out)
	}
	code, out = register("First", false)
	if code != http.StatusCreated {
		t.Fatalf("first registration failed: %d %#v", code, out)
	}
	newAccess, _ := deviceTrustData0121(t, out)["accessToken"].(string)
	access = newAccess
	code, out = register("Duplicate key", false)
	if code != http.StatusConflict {
		t.Fatalf("duplicate key accepted: %d %#v", code, out)
	}
}
