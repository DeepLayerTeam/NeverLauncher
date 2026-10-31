package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func deviceTrustFixture0432(t *testing.T) (http.Handler, repository.Repository) {
	t.Helper()
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust-0432", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.43.2", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	return h, repo
}

func registerDevice0432(t *testing.T, h http.Handler, access, name string) (string, string, ed25519.PrivateKey) {
	t.Helper()
	code, body := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{"name": name, "platform": "linux", "clientVersion": "0.43.2"})
	if code != http.StatusOK {
		t.Fatalf("begin registration: %d %#v", code, body)
	}
	begin := deviceTrustData0121(t, body)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(begin["signingPayload"].(string))))
	code, body = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "deviceId": begin["deviceId"],
		"publicKey": base64.RawURLEncoding.EncodeToString(pub), "signature": signature,
	})
	if code != http.StatusCreated {
		t.Fatalf("complete registration: %d %#v", code, body)
	}
	data := deviceTrustData0121(t, body)
	return data["accessToken"].(string), begin["deviceId"].(string), priv
}

func TestDeviceTrustExistingBindingCannotBeReplacedWithoutRecovery0432(t *testing.T) {
	h, _ := deviceTrustFixture0432(t)
	firstAccess, _ := deviceTrustLogin0121(t, h, "device-a")
	boundAccess, deviceA, _ := registerDevice0432(t, h, firstAccess, "Device A")
	secondAccess, _ := deviceTrustLogin0121(t, h, "device-b")
	_, deviceB, _ := registerDevice0432(t, h, secondAccess, "Device B")

	for _, tc := range []struct{ name, path string }{
		{"register", "/api/v1/auth/devices/register/begin"},
		{"verify-other", "/api/v1/auth/devices/" + deviceB + "/verify/begin"},
		{"verify-same", "/api/v1/auth/devices/" + deviceA + "/verify/begin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := deviceTrustRequest0121(t, h, http.MethodPost, tc.path, boundAccess, map[string]any{"name": "Attempted silent replacement"})
			if code != http.StatusConflict {
				t.Fatalf("bound session allowed silent rebind: %d %#v", code, body)
			}
		})
	}
	code, body := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", boundAccess, nil)
	if code != http.StatusOK || deviceTrustData0121(t, body)["trustedDeviceId"] != deviceA {
		t.Fatalf("denied rebind changed existing binding: %d %#v", code, body)
	}
}

func TestDeviceTrustInflightProofCannotSwapAlreadyBoundSession0432(t *testing.T) {
	h, _ := deviceTrustFixture0432(t)
	firstAccess, _ := deviceTrustLogin0121(t, h, "first-device")
	_, deviceA, privateA := registerDevice0432(t, h, firstAccess, "Device A")
	// Obtain a valid session-binding challenge while the second session is unbound.
	fresh, _ := deviceTrustLogin0121(t, h, "still-unbound")
	code, beginResponse := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceA+"/verify/begin", fresh, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("verify/begin: %d %#v", code, beginResponse)
	}
	begin := deviceTrustData0121(t, beginResponse)
	bound, deviceB, _ := registerDevice0432(t, h, fresh, "Device B")
	// The old challenge is authentic and signed with A's real key. Only the
	// atomic session transition prevents a switch away from B.
	proof := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateA, []byte(begin["signingPayload"].(string))))
	code, rejected := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceA+"/verify/complete", bound, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "signature": proof,
	})
	if code != http.StatusConflict {
		t.Fatalf("valid stale proof unexpectedly replaced B: %d %#v", code, rejected)
	}
	code, status := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", bound, nil)
	if code != http.StatusOK || deviceTrustData0121(t, status)["trustedDeviceId"] != deviceB {
		t.Fatalf("pending proof altered current binding: %d %#v", code, status)
	}
}

func TestDeviceTrustBindingCASAndRefreshEpoch0432(t *testing.T) {
	sessions := newAuthSessionStore111()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	user := model.User{ID: "user-0432", Email: "test@example.test", RoleID: "admin"}
	session, refresh, err := sessions.create(user, req, "desktop")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := sessions.previewRefresh0126(refresh)
	if err != nil {
		t.Fatal(err)
	}
	const contestants = 12
	var wg sync.WaitGroup
	results := make(chan error, contestants)
	for i := 0; i < contestants; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := sessions.bindTrustedDevice121(session.ID, session.UserID, fmt.Sprintf("device-%d", i), time.Now().UTC())
			results <- e
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
			continue
		}
		if !errors.Is(e, errSessionBindingChanged0432) {
			t.Fatalf("unexpected CAS error: %v", e)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent binding succeeded %d times, want exactly one", successes)
	}
	current, ok := sessions.get(session.ID, session.UserID)
	if !ok || current.BindingEpoch != preview.BindingEpoch+1 || current.TrustedDeviceID == "" {
		t.Fatalf("invalid binding epoch: %#v", current)
	}
	if _, _, err := sessions.rotateExpected0432(refresh, &preview, req); !errors.Is(err, errSessionBindingChanged0432) {
		t.Fatalf("stale preview rotated bound refresh token: %v", err)
	}
	// Epoch rejection must not consume refresh token. The legitimate caller
	// can retry with an updated device-bound snapshot and a real key proof.
	if refreshed, err := sessions.previewRefresh0126(refresh); err != nil || !sameDeviceBinding0432(current, refreshed) {
		t.Fatalf("CAS failure consumed refresh token: %v %#v", err, refreshed)
	}
	_, nextRefresh, err := sessions.rotateExpected0432(refresh, &current, req)
	if err != nil || nextRefresh == "" || nextRefresh == refresh {
		t.Fatalf("valid snapshot could not rotate: %v", err)
	}
	if _, err := sessions.bindTrustedDevice121(session.ID, session.UserID, "other", time.Now()); !errors.Is(err, errSessionBindingChanged0432) {
		t.Fatalf("second binding should require explicit replacement: %v", err)
	}
}

func TestDeviceTrustCompetingRegistrationChallengesDoNotLeaveActiveOrphans0432(t *testing.T) {
	h, _ := deviceTrustFixture0432(t)
	unbound, _ := deviceTrustLogin0121(t, h, "race-challenges")
	beginRegistration := func(name string) (map[string]any, ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		code, body := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", unbound, map[string]any{"name": name})
		if code != http.StatusOK {
			t.Fatalf("begin status=%d %#v", code, body)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return deviceTrustData0121(t, body), public, private
	}
	first, firstPublic, firstPrivate := beginRegistration("one")
	second, secondPublic, secondPrivate := beginRegistration("two")
	complete := func(access string, challenge map[string]any, public ed25519.PublicKey, private ed25519.PrivateKey) (int, map[string]any) {
		t.Helper()
		return deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
			"challengeId": challenge["challengeId"], "challenge": challenge["challenge"], "deviceId": challenge["deviceId"],
			"publicKey": base64.RawURLEncoding.EncodeToString(public),
			"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(challenge["signingPayload"].(string)))),
		})
	}
	code, body := complete(unbound, first, firstPublic, firstPrivate)
	if code != http.StatusCreated {
		t.Fatalf("first completion: %d %#v", code, body)
	}
	bound := deviceTrustData0121(t, body)["accessToken"].(string)
	code, body = complete(bound, second, secondPublic, secondPrivate)
	if code != http.StatusConflict {
		t.Fatalf("competing valid challenge bound second device: %d %#v", code, body)
	}
	code, status := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", bound, nil)
	if code != http.StatusOK || deviceTrustData0121(t, status)["trustedDeviceId"] != first["deviceId"] {
		t.Fatalf("first binding no longer authoritative: %d %#v", code, status)
	}
	// A losing registration may persist its candidate before the CAS, but the
	// API must leave it permanently revoked, not as another active key.
	firstDevice := first["deviceId"].(string)
	secondDevice := second["deviceId"].(string)
	code, listed := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices?status=active", bound, nil)
	if code != http.StatusOK {
		t.Fatalf("device inventory: %d %#v", code, listed)
	}
	active := deviceTrustData0121(t, listed)["items"].([]any)
	if len(active) != 1 || active[0].(map[string]any)["id"] != firstDevice {
		t.Fatalf("losing registered key remained active: %#v", active)
	}
	code, listed = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices?status=revoked", bound, nil)
	if code != http.StatusOK {
		t.Fatalf("revoked inventory: %d %#v", code, listed)
	}
	revoked := deviceTrustData0121(t, listed)["items"].([]any)
	if len(revoked) != 1 || revoked[0].(map[string]any)["id"] != secondDevice {
		t.Fatalf("losing registered key not revoked: %#v", revoked)
	}
}
