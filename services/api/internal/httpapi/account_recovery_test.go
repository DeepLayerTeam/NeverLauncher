package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func TestRecoveryFromAlreadyRevokedDevice0435(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-account-recovery-0435", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	state := NewRuntimeState()
	srv := Server{Version: "0.43.5", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir()), State: state}
	h := srv.Handler()
	lost := registerSoftwareDevice0125(t, h, "compromised-recovery", "Lost workstation")
	if _, err := repo.RevokeTrustedDevice(context.Background(), "admin", lost.ID, "stolen-key"); err != nil {
		t.Fatal(err)
	}
	oldAccess, _ := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", lost.Access, nil)
	if oldAccess != http.StatusUnauthorized {
		t.Fatalf("Старый токен Bearer остался действителен после отзыва: %d", oldAccess)
	}

	independent, _ := deviceTrustLogin0121(t, h, "safe-new-browser")
	public, private := newReplacementKey0128(t)
	beginPath := "/api/v1/auth/devices/key-recovery/begin"
	beginRequest := map[string]any{"oldDeviceId": lost.ID, "name": "Fresh device", "platform": "linux", "clientVersion": "0.43.5", "publicKey": base64.RawURLEncoding.EncodeToString(public), "keyAlgorithm": "ed25519", "keyBinding": "software"}
	code, _ := deviceTrustRequest0121(t, h, http.MethodPost, beginPath, independent, beginRequest)
	if code != http.StatusPreconditionRequired {
		t.Fatalf("Допущено отсутствие нового подтверждения, устойчивого к фишингу: %d", code)
	}
	claims, err := srv.verifyAdminToken(independent)
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
	freshAccess, err := srv.issueAccessTokenForSession(user, stepped)
	if err != nil {
		t.Fatal(err)
	}
	code, body := deviceTrustRequest0121(t, h, http.MethodPost, beginPath, freshAccess, beginRequest)
	if code != http.StatusOK {
		t.Fatalf("Запись об отзыве не должна подлежать восстановлению: %d %#v", code, body)
	}
	begin := deviceTrustData0121(t, body)
	completePath := "/api/v1/auth/devices/" + lost.ID + "/key-recovery/complete"
	// Неверная подпись нового ключа расходует запрос, но не может присвоить отозванную
	// идентичность.
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, completePath, freshAccess, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "newSignature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(lost.Private, []byte(begin["signingPayload"].(string)))),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("Восстановление подписано старым скомпрометированным ключом: %d", code)
	}
	code, body = deviceTrustRequest0121(t, h, http.MethodPost, beginPath, freshAccess, beginRequest)
	if code != http.StatusOK {
		t.Fatalf("Новый запрос подтверждения восстановления: %d %#v", code, body)
	}
	begin = deviceTrustData0121(t, body)
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(begin["signingPayload"].(string))))
	code, body = deviceTrustRequest0121(t, h, http.MethodPost, completePath, freshAccess, map[string]any{
		"challengeId": begin["challengeId"], "challenge": begin["challenge"], "newSignature": signature,
	})
	if code != http.StatusOK {
		t.Fatalf("Проверенное восстановление не завершилось: %d %#v", code, body)
	}
	data := deviceTrustData0121(t, body)
	next := data["device"].(map[string]any)
	nextID := next["id"].(string)
	if nextID == lost.ID || next["assurance"] != "proof-of-possession" || next["attestationState"] != "unattested" {
		t.Fatalf("Восстановленный ключ унаследовал старую идентичность или уровень доверия: %#v", next)
	}
	old, err := repo.GetTrustedDevice("admin", lost.ID)
	if err != nil || old.Status != "revoked" || old.ReplacedByDeviceID != nextID || old.ReplacementReason != "recover" {
		t.Fatalf("Запись об отзыве старого ключа оказалась не постоянной: %+v %v", old, err)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", freshAccess, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("Токен Bearer, выданный до восстановления, сохранился после смены эпохи привязки: %d", code)
	}
	newAccess := data["accessToken"].(string)
	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", newAccess, nil)
	if code != http.StatusOK {
		t.Fatalf("Новый ключ не работает: %d", code)
	}
	independent2, _ := deviceTrustLogin0121(t, h, "second-safe-browser")
	claims2, err := srv.verifyAdminToken(independent2)
	if err != nil {
		t.Fatal(err)
	}
	step2, err := state.AuthSessions.stepUp(claims2.SessionID, claims2.Sub, []string{"passkey", "user-verification"}, "phishing-resistant", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	retry, err := srv.issueAccessTokenForSession(user, step2)
	if err != nil {
		t.Fatal(err)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, beginPath, retry, beginRequest)
	if code != http.StatusNotFound {
		t.Fatalf("Повторно использована уже закреплённая запись об отзыве: %d", code)
	}
}

func TestRecoveryCannotRebindUnrelatedTrustedDevice0435(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-recovery-isolation-0435", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	state := NewRuntimeState()
	srv := Server{Version: "0.43.5", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir()), State: state}
	h := srv.Handler()
	lost := registerSoftwareDevice0125(t, h, "lost-old-0435", "Lost device")
	safe := registerSoftwareDevice0125(t, h, "other-trusted-0435", "Safe device")
	if _, err := repo.RevokeTrustedDevice(context.Background(), "admin", lost.ID, "stolen"); err != nil {
		t.Fatal(err)
	}
	claims, err := srv.verifyAdminToken(safe.Access)
	if err != nil {
		t.Fatal(err)
	}
	stepped, err := state.AuthSessions.stepUp(claims.SessionID, claims.Sub, []string{"passkey", "user-verification"}, "phishing-resistant", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := repo.GetUser(claims.Sub)
	access, err := srv.issueAccessTokenForSession(user, stepped)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := newReplacementKey0128(t)
	code, _ := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/key-recovery/begin", access, map[string]any{
		"oldDeviceId": lost.ID, "publicKey": base64.RawURLEncoding.EncodeToString(public), "keyAlgorithm": "ed25519", "keyBinding": "software",
	})
	if code != http.StatusConflict {
		t.Fatalf("Восстановление заменило другое активное привязанное устройство: %d", code)
	}
	current, err := repo.GetTrustedDevice("admin", safe.ID)
	if err != nil || current.Status != "active" {
		t.Fatalf("Изменено постороннее устройство: %+v %v", current, err)
	}
}
