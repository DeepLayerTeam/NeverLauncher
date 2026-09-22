package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func newReplacementKey0128(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func beginReplacement0128(t *testing.T, h http.Handler, path, access, oldDeviceID string, pub ed25519.PublicKey) map[string]any {
	t.Helper()
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, path, access, map[string]any{
		"oldDeviceId": oldDeviceID, "name": "Rotated workstation", "platform": "linux", "clientVersion": "0.12.8",
		"publicKey": base64.RawURLEncoding.EncodeToString(pub), "keyAlgorithm": "ed25519", "keyBinding": "software",
	})
	if code != http.StatusOK {
		t.Fatalf("replacement begin status=%d body=%#v", code, out)
	}
	return deviceTrustData0121(t, out)
}

func rotateBoundAccess0128(t *testing.T, h http.Handler, current boundAccess0127, _ string) boundAccess0127 {
	t.Helper()
	pub, priv := newReplacementKey0128(t)
	begin := beginReplacement0128(t, h, "/api/v1/auth/devices/key-rotation/begin", current.Access, current.DeviceID, pub)
	payload, _ := begin["signingPayload"].(string)
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+current.DeviceID+"/key-rotation/complete", current.Access, map[string]any{
		"challengeId":  begin["challengeId"],
		"challenge":    begin["challenge"],
		"oldSignature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(current.Private, []byte(payload))),
		"newSignature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload))),
	})
	if code != http.StatusOK {
		t.Fatalf("device key rotation complete=%d %#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	device, _ := data["device"].(map[string]any)
	session, _ := data["session"].(map[string]any)
	epoch, _ := session["bindingEpoch"].(float64)
	return boundAccess0127{Access: data["accessToken"].(string), DeviceID: device["id"].(string), BindingEpoch: int64(epoch), Private: priv}
}

func TestDeviceKeyRotationRequiresOldAndNewProofAndTombstonesOldIdentity0128(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-key-rotation", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.8", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	old := registerSoftwareDevice0125(t, h, "rotation-primary", "Rotation workstation")
	newPub, newPriv := newReplacementKey0128(t)
	begin := beginReplacement0128(t, h, "/api/v1/auth/devices/key-rotation/begin", old.Access, old.ID, newPub)
	payload, _ := begin["signingPayload"].(string)
	if payload == "" || begin["oldKeyProofRequired"] != true {
		t.Fatalf("rotation challenge incomplete: %#v", begin)
	}
	oldSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(old.Private, []byte(payload)))
	newSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(newPriv, []byte(payload)))

	// New-key proof alone must not authorize a continuity-preserving rotation.
	code, _ := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+old.ID+"/key-rotation/complete", old.Access, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "newSignature": newSig,
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("rotation without old-key proof accepted: %d", code)
	}

	// Burned challenge is intentional; begin a fresh ceremony and complete both proofs.
	begin = beginReplacement0128(t, h, "/api/v1/auth/devices/key-rotation/begin", old.Access, old.ID, newPub)
	payload, _ = begin["signingPayload"].(string)
	oldSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(old.Private, []byte(payload)))
	newSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(newPriv, []byte(payload)))
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+old.ID+"/key-rotation/complete", old.Access, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "oldSignature": oldSig, "newSignature": newSig,
	})
	if code != http.StatusOK {
		t.Fatalf("rotation complete status=%d body=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	newAccess, _ := data["accessToken"].(string)
	newDevice, _ := data["device"].(map[string]any)
	newID, _ := newDevice["id"].(string)
	if newAccess == "" || newID == "" || newID == old.ID || data["oldFingerprintPermanentTombstone"] != true {
		t.Fatalf("bad rotation result: %#v", data)
	}

	oldRow, err := repo.GetTrustedDevice("admin", old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldRow.Status != "revoked" || oldRow.ReplacedByDeviceID != newID || oldRow.ReplacementReason != "rotate" || oldRow.ReplacedAt.IsZero() {
		t.Fatalf("old identity not linked as replacement tombstone: %+v", oldRow)
	}
	if _, err := repo.GetTrustedDevice("admin", newID); err != nil {
		t.Fatalf("replacement device missing: %v", err)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", old.Access, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("pre-rotation access token survived binding epoch change: %d", code)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", newAccess, nil)
	if code != http.StatusOK {
		t.Fatalf("new access token unusable after rotation: %d", code)
	}
}

func TestDeviceKeyRecoveryRequiresFreshPhishingResistantAuthAndOnlyNewKeyProof0128(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-key-recovery", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	state := NewRuntimeState()
	srv := Server{Version: "0.12.8", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir()), State: state}
	h := srv.Handler()
	old := registerSoftwareDevice0125(t, h, "recovery-primary", "Lost-key workstation")
	newPub, newPriv := newReplacementKey0128(t)

	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/key-recovery/begin", old.Access, map[string]any{
		"oldDeviceId": old.ID, "name": "Recovered workstation", "platform": "linux", "clientVersion": "0.12.8",
		"publicKey": base64.RawURLEncoding.EncodeToString(newPub), "keyAlgorithm": "ed25519", "keyBinding": "software",
	})
	if code != http.StatusPreconditionRequired {
		t.Fatalf("recovery started without phishing-resistant step-up: status=%d body=%#v", code, out)
	}

	claims, err := srv.verifyAdminToken(old.Access)
	if err != nil {
		t.Fatal(err)
	}
	stepped, err := state.AuthSessions.stepUp(claims.SessionID, claims.Sub, []string{"passkey", "user-verification"}, "phishing-resistant", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := repo.GetUser(claims.Sub)
	freshAccess, err := srv.issueAccessTokenForSession(user, stepped)
	if err != nil {
		t.Fatal(err)
	}
	begin := beginReplacement0128(t, h, "/api/v1/auth/devices/key-recovery/begin", freshAccess, old.ID, newPub)
	payload, _ := begin["signingPayload"].(string)
	newSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(newPriv, []byte(payload)))
	code, out = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+old.ID+"/key-recovery/complete", freshAccess, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "newSignature": newSig,
	})
	if code != http.StatusOK {
		t.Fatalf("recovery complete status=%d body=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	newDevice, _ := data["device"].(map[string]any)
	newID, _ := newDevice["id"].(string)
	if newID == "" || data["mode"] != "recover" {
		t.Fatalf("bad recovery result: %#v", data)
	}
	oldRow, _ := repo.GetTrustedDevice("admin", old.ID)
	if oldRow.Status != "revoked" || oldRow.ReplacedByDeviceID != newID || oldRow.ReplacementReason != "recover" {
		t.Fatalf("recovery did not tombstone old identity: %+v", oldRow)
	}
}

func TestBoundSessionCannotBypassReplacementViaOrdinaryRegistration0128(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-key-hardening", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.8", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	bound := registerSoftwareDevice0125(t, h, "registration-bypass", "Bound workstation")
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", bound.Access, map[string]any{"name": "Bypass replacement"})
	if code != http.StatusConflict {
		t.Fatalf("bound session enrolled second key outside replacement flow: status=%d body=%#v", code, out)
	}
}
