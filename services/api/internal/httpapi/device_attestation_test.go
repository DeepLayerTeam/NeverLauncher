package httpapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func registerHardwareDevice0124(t *testing.T, h http.Handler, access string, priv *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	publicKey := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{
		"name":             "Attested TPM workstation",
		"platform":         "linux",
		"clientVersion":    "0.12.4",
		"keyAlgorithm":     "p256",
		"keyBinding":       "hardware",
		"hardwareProvider": "test-tpm-2.0",
	})
	if code != http.StatusOK {
		t.Fatalf("Начало регистрации: статус=%d, тело=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	payload, _ := begin["signingPayload"].(string)
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
		"challengeId": begin["challengeId"],
		"deviceId":    begin["deviceId"],
		"challenge":   begin["challenge"],
		"publicKey":   base64.RawURLEncoding.EncodeToString(publicKey),
		"signature":   signP256P1363Test0123(t, priv, payload),
	})
	if code != http.StatusCreated {
		t.Fatalf("Завершение регистрации: статус=%d, тело=%#v", code, completeOut)
	}
	data := deviceTrustData0121(t, completeOut)
	device, _ := data["device"].(map[string]any)
	deviceID, _ := device["id"].(string)
	trustedAccess, _ := data["accessToken"].(string)
	if deviceID == "" || trustedAccess == "" {
		t.Fatalf("Неполные данные зарегистрированного устройства: %#v", data)
	}
	if device["attestationState"] != "unattested" || device["assurance"] != "proof-of-possession" {
		t.Fatalf("Регистрация не должна преждевременно подтверждать аппаратную идентичность: %#v", device)
	}
	return deviceID, trustedAccess
}

func TestDeviceChallengeResponseAttestation0124(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-attestation", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.4", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access, _ := deviceTrustLogin0121(t, h, "attestation-primary")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, trustedAccess := registerHardwareDevice0124(t, h, access, priv)

	// Другой сеанс входа ещё не подтвердил или не привязал устройство и
	// не может запрашивать серверную аттестацию за привязанный сеанс.
	unboundAccess, _ := deviceTrustLogin0121(t, h, "attestation-unbound")
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", unboundAccess, map[string]any{})
	if code != http.StatusConflict {
		t.Fatalf("Непривязанная сессия получила запрос аттестации: статус=%d ответ=%#v", code, out)
	}

	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", trustedAccess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("Начало аттестации: статус=%d, тело=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	payload, _ := begin["signingPayload"].(string)
	if payload == "" || begin["attestationMethod"] != deviceAttestationMethod0124 || begin["hardwareProvenance"] != "not-verified" {
		t.Fatalf("Некорректный контракт начала аттестации: %#v", begin)
	}
	completeBody := map[string]any{
		"challengeId": begin["challengeId"],
		"deviceId":    deviceID,
		"challenge":   begin["challenge"],
		"signature":   signP256P1363Test0123(t, priv, payload),
	}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", trustedAccess, completeBody)
	if code != http.StatusOK {
		t.Fatalf("Завершение аттестации: статус=%d, тело=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	attestedAccess, _ := complete["accessToken"].(string)
	device, _ := complete["device"].(map[string]any)
	if attestedAccess == "" || complete["attestationState"] != "verified" || complete["attestationMethod"] != deviceAttestationMethod0124 {
		t.Fatalf("Неполный результат аттестации: %#v", complete)
	}
	if device["attestationState"] != "verified" || device["attestationMethod"] != deviceAttestationMethod0124 || device["assurance"] != "challenge-response-attested" {
		t.Fatalf("Аттестация не сохранена в записи доверенного устройства: %#v", device)
	}
	if complete["hardwareProvenance"] != "not-verified" || complete["authorizationElevation"] != false || complete["phishingResistantElevation"] != false {
		t.Fatalf("Аттестация необоснованно расширила полномочия или сведения о производителе: %#v", complete)
	}

	// Запрос challenge расходуется до проверки подписи; поэтому повтор корректного
	// запроса и попытка злоумышленника после неверного доказательства всегда отклоняются.
	code, replayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", attestedAccess, completeBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("Принято повторное использование аттестации: статус=%d ответ=%#v", code, replayOut)
	}

	code, trustOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", attestedAccess, nil)
	if code != http.StatusOK {
		t.Fatalf("Доверие к устройству после аттестации: статус=%d, тело=%#v", code, trustOut)
	}
	trust := deviceTrustData0121(t, trustOut)
	if trust["deviceAttestationState"] != "verified" || trust["deviceAttestationMethod"] != deviceAttestationMethod0124 {
		t.Fatalf("Состояние сессии не отражает новую аттестацию: %#v", trust)
	}

	code, badBeginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", attestedAccess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("Начало повторной аттестации: статус=%d, тело=%#v", code, badBeginOut)
	}
	badBegin := deviceTrustData0121(t, badBeginOut)
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badBody := map[string]any{
		"challengeId": badBegin["challengeId"],
		"deviceId":    deviceID,
		"challenge":   badBegin["challenge"],
		"signature":   signP256P1363Test0123(t, otherPriv, badBegin["signingPayload"].(string)),
	}
	code, badOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", attestedAccess, badBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("Принята неверная подпись аттестации: статус=%d ответ=%#v", code, badOut)
	}
	badBody["signature"] = signP256P1363Test0123(t, priv, badBegin["signingPayload"].(string))
	code, badReplayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", attestedAccess, badBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("Повторно использован запрос с уже отклонённым подтверждением: статус=%d ответ=%#v", code, badReplayOut)
	}
}

func TestDeviceAttestationPayloadStableAcrossPostgresTimestampPrecision0124(t *testing.T) {
	raw := time.Date(2026, time.September, 27, 11, 29, 48, 822071312, time.UTC)
	now := canonicalDeviceAttestationTime0124(raw)
	if now.Nanosecond()%1000 != 0 {
		t.Fatalf("Метка времени аттестации не нормализована до микросекунд PostgreSQL: %s", now.Format(time.RFC3339Nano))
	}
	challenge := model.DeviceChallenge{
		CreatedAt: now,
		ExpiresAt: canonicalDeviceAttestationTime0124(now.Add(deviceAttestationChallengeTTL0124)),
	}
	device := model.TrustedDevice{
		ID: "dev-test", UserID: "user-test", KeyFingerprint: "fp", KeyAlgorithm: "p256",
		KeyBinding: "hardware", HardwareProvider: "test-provider",
	}
	validUntil := canonicalDeviceAttestationTime0124(now.Add(deviceAttestationValidity0124))
	beginPayload := deviceAttestationPayload0124("challenge", challenge, device, "session-test", validUntil)

	// Смоделируйте точную микросекундную точность PostgreSQL timestamptz после обратного чтения.
	fromPostgres := challenge
	fromPostgres.CreatedAt = challenge.CreatedAt.Truncate(time.Microsecond)
	fromPostgres.ExpiresAt = challenge.ExpiresAt.Truncate(time.Microsecond)
	completePayload := deviceAttestationPayload0124("challenge", fromPostgres, device, "session-test", validUntil)
	if beginPayload != completePayload {
		t.Fatalf("Данные аттестации изменились после записи и чтения времени в PostgreSQL:\nначало=%q\nзавершение=%q", beginPayload, completePayload)
	}
}

func TestDeviceAttestationFreshnessDowngradesExpired0124(t *testing.T) {
	now := time.Now().UTC()
	device := model.TrustedDevice{
		Assurance:            "challenge-response-attested",
		AttestationState:     "verified",
		AttestationMethod:    deviceAttestationMethod0124,
		AttestedAt:           now.Add(-13 * time.Hour),
		AttestationExpiresAt: now.Add(-time.Hour),
	}
	state, assurance := effectiveDeviceAttestation0124(device, now)
	if state != "expired" || assurance != "proof-of-possession" {
		t.Fatalf("Истёкшая аттестация не снизила уровень доверия: состояние=%s доверие=%s", state, assurance)
	}
}

func TestDeviceChallengeResponseAttestationRejectsSoftwareKey0124(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-attestation", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.4", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access, _ := deviceTrustLogin0121(t, h, "software-attestation")
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{"name": "Software device"})
	if code != http.StatusOK {
		t.Fatalf("Начало программной регистрации: статус=%d, тело=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
		"challengeId": begin["challengeId"],
		"deviceId":    begin["deviceId"],
		"challenge":   begin["challenge"],
		"publicKey":   base64.RawURLEncoding.EncodeToString(pub),
		"signature":   base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(begin["signingPayload"].(string)))),
	})
	if code != http.StatusCreated {
		t.Fatalf("Завершение программной регистрации: статус=%d, тело=%#v", code, completeOut)
	}
	data := deviceTrustData0121(t, completeOut)
	trustedAccess, _ := data["accessToken"].(string)
	device, _ := data["device"].(map[string]any)
	deviceID, _ := device["id"].(string)
	code, attestOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", trustedAccess, map[string]any{})
	if code != http.StatusConflict {
		t.Fatalf("Программный ключ допущен к аппаратной аттестации: статус=%d ответ=%#v", code, attestOut)
	}
}
