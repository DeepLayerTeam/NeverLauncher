package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestMacOSRecoveryRejectsReuseAndRequiresFreshPasskey0316(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-macos-0316-recover", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	state := NewRuntimeState()
	srv := Server{Version: "0.31.6", Config: cfg, Repo: repo, State: state, Storage: storage.NewLocalStorage(t.TempDir())}
	h := srv.Handler()
	old := registerSoftwareDevice0125(t, h, "mac-recovery", "MacBook (lost key)")
	oldPublic := old.Private.Public().(ed25519.PublicKey)
	payload := map[string]any{
		"oldDeviceId": old.ID, "name": "New MacBook identity", "platform": "macos", "clientVersion": "0.31.6",
		"publicKey": base64.RawURLEncoding.EncodeToString(oldPublic), "keyAlgorithm": "ed25519", "keyBinding": "software",
	}
	code, _ := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/key-recovery/begin", old.Access, payload)
	if code != http.StatusPreconditionRequired {
		t.Fatalf("missing fresh passkey: %d", code)
	}
	claims, err := srv.verifyAdminToken(old.Access)
	if err != nil {
		t.Fatal(err)
	}
	stepped, err := state.AuthSessions.stepUp(claims.SessionID, claims.Sub, []string{"passkey", "user-verification"}, "phishing-resistant", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	user, err := repo.GetUser(claims.Sub)
	if err != nil {
		t.Fatal(err)
	}
	access, err := srv.issueAccessTokenForSession(user, stepped)
	if err != nil {
		t.Fatal(err)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/key-recovery/begin", access, payload)
	if code != http.StatusConflict {
		t.Fatalf("re-enrolling same fingerprint accepted: %d", code)
	}

	newPublic, newPrivate := newReplacementKey0128(t)
	payload["publicKey"] = base64.RawURLEncoding.EncodeToString(newPublic)
	code, output := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/key-recovery/begin", access, payload)
	if code != http.StatusOK {
		t.Fatalf("valid recovery start: %d, %#v", code, output)
	}
	begin := deviceTrustData0121(t, output)
	signed := base64.RawURLEncoding.EncodeToString(ed25519.Sign(newPrivate, []byte(begin["signingPayload"].(string))))
	complete := map[string]any{"challengeId": begin["challengeId"], "challenge": begin["challenge"], "newSignature": signed}
	code, output = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+old.ID+"/key-recovery/complete", access, complete)
	if code != http.StatusOK {
		t.Fatalf("recovery complete: %d, %#v", code, output)
	}
	data := deviceTrustData0121(t, output)
	recovered := data["device"].(map[string]any)
	newID := recovered["id"].(string)
	if newID == old.ID || recovered["assurance"] != "proof-of-possession" || recovered["attestationState"] != "unattested" {
		t.Fatalf("new identity inherited old assurance or key: %#v", recovered)
	}
	previous, err := repo.GetTrustedDevice(claims.Sub, old.ID)
	if err != nil || previous.Status != "revoked" || previous.ReplacedByDeviceID != newID {
		t.Fatalf("old identity not tombstoned: %+v %v", previous, err)
	}
	// Consumed challenge cannot be used twice, nor can a revoked source be replaced again.
	replay, _ := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+old.ID+"/key-recovery/complete", access, complete)
	if replay == http.StatusOK {
		t.Fatal("recovery replay accepted")
	}
}
