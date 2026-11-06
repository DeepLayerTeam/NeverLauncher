package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
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
	req.Header.Set("User-Agent", "Launcher-DeviceTrust-Test/0.12.1")
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
		t.Fatalf("Отсутствуют данные: %#v", out)
	}
	return v
}

func deviceTrustLogin0121(t *testing.T, h http.Handler, deviceID string) (string, string) {
	t.Helper()
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "admin@launcher.local", "password": "admin", "deviceId": deviceID})
	if code != http.StatusOK {
		t.Fatalf("Статус входа=%d тело ответа=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	tokens, ok := data["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("Отсутствуют токены: %#v", data)
	}
	access, _ := tokens["accessToken"].(string)
	refresh, _ := tokens["refreshToken"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("Пустые токены: %#v", tokens)
	}
	return access, refresh
}

func TestDeviceTrustRegistrationBindingReplayAndRevocation0121(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.1", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access1, _ := deviceTrustLogin0121(t, h, "legacy-label-a")
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access1, map[string]any{"name": "Workstation", "platform": "linux", "clientVersion": "0.12.1"})
	if code != http.StatusOK {
		t.Fatalf("Начало регистрации: статус=%d тело ответа=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	challengeID, _ := begin["challengeId"].(string)
	deviceID, _ := begin["deviceId"].(string)
	challenge, _ := begin["challenge"].(string)
	payload, _ := begin["signingPayload"].(string)
	if challengeID == "" || deviceID == "" || challenge == "" || payload == "" {
		t.Fatalf("Неполные данные начала регистрации: %#v", begin)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(payload))
	completeBody := map[string]any{"challengeId": challengeID, "deviceId": deviceID, "challenge": challenge, "publicKey": base64.RawURLEncoding.EncodeToString(pub), "signature": base64.RawURLEncoding.EncodeToString(sig)}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access1, completeBody)
	if code != http.StatusCreated {
		t.Fatalf("Завершение регистрации: статус=%d тело ответа=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	trustedAccess1, _ := complete["accessToken"].(string)
	if trustedAccess1 == "" {
		t.Fatalf("Отсутствует обновлённый токен доступа: %#v", complete)
	}
	device, _ := complete["device"].(map[string]any)
	if device["trustState"] != "verified" || device["assurance"] != "proof-of-possession" || device["keyFingerprint"] == "" {
		t.Fatalf("Некорректное устройство: %#v", device)
	}
	if _, leaks := device["publicKey"]; leaks {
		t.Fatalf("Публичный ключ неожиданно раскрыт в модели устройства API: %#v", device)
	}

	code, replayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", trustedAccess1, completeBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("Повторно использован запрос регистрации: статус=%d тело ответа=%#v", code, replayOut)
	}

	code, trustOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", trustedAccess1, nil)
	if code != http.StatusOK {
		t.Fatalf("Статус доверия=%d тело ответа=%#v", code, trustOut)
	}
	trust := deviceTrustData0121(t, trustOut)
	if trust["deviceTrustState"] != "verified" || trust["trustedDeviceId"] != deviceID {
		t.Fatalf("Сессия не привязана к устройству: %#v", trust)
	}

	access2, refresh2 := deviceTrustLogin0121(t, h, "legacy-label-b")
	code, verifyBeginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/verify/begin", access2, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("Начало проверки: статус=%d тело ответа=%#v", code, verifyBeginOut)
	}
	verifyBegin := deviceTrustData0121(t, verifyBeginOut)
	verifyChallengeID, _ := verifyBegin["challengeId"].(string)
	verifyChallenge, _ := verifyBegin["challenge"].(string)
	verifyPayload, _ := verifyBegin["signingPayload"].(string)
	verifySig := ed25519.Sign(priv, []byte(verifyPayload))
	code, verifyOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/verify/complete", access2, map[string]any{"challengeId": verifyChallengeID, "challenge": verifyChallenge, "signature": base64.RawURLEncoding.EncodeToString(verifySig)})
	if code != http.StatusOK {
		t.Fatalf("Завершение проверки: статус=%d тело ответа=%#v", code, verifyOut)
	}
	trustedAccess2, _ := deviceTrustData0121(t, verifyOut)["accessToken"].(string)
	if trustedAccess2 == "" {
		t.Fatal("Отсутствует второй привязанный токен доступа")
	}

	code, listOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices", trustedAccess2, nil)
	if code != http.StatusOK {
		t.Fatalf("Список устройств: статус=%d тело ответа=%#v", code, listOut)
	}
	items, _ := deviceTrustData0121(t, listOut)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("Ожидалось одно устройство: %#v", listOut)
	}

	code, revokeOut := deviceTrustRequest0121(t, h, http.MethodDelete, "/api/v1/auth/devices/"+deviceID, trustedAccess1, nil)
	if code != http.StatusOK {
		t.Fatalf("Отзыв устройства: статус=%d тело ответа=%#v", code, revokeOut)
	}

	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", trustedAccess2, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("Привязанная сессия сохранилась после отзыва устройства: %d", code)
	}
	code, refreshOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": refresh2})
	if code != http.StatusUnauthorized {
		t.Fatalf("Семейство токенов обновления сохранилось после отзыва устройства: статус=%d тело ответа=%#v", code, refreshOut)
	}
}

func TestDeviceTrustRejectsWrongSignatureAndDuplicateKey0121(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.1", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	access, _ := deviceTrustLogin0121(t, h, "client")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	register := func(name string, wrong bool) (int, map[string]any) {
		code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{"name": name})
		if code != http.StatusOK {
			t.Fatalf("Начало: %d %#v", code, out)
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
		t.Fatalf("Принята неверная подпись: %d %#v", code, out)
	}
	code, out = register("First", false)
	if code != http.StatusCreated {
		t.Fatalf("Первичная регистрация не удалась: %d %#v", code, out)
	}
	if newAccess, _ := deviceTrustData0121(t, out)["accessToken"].(string); newAccess == "" {
		t.Fatal("Первичная регистрация не вернула токен доступа")
	}
	// Версия 0.12.8 запрещает второй ключ из уже привязанного сеанса. Для проверки постоянного
	// запрета по отпечатку используйте новый непривязанный сеанс той же учётной записи.
	access, _ = deviceTrustLogin0121(t, h, "duplicate-key-unbound")
	code, out = register("Duplicate key", false)
	if code != http.StatusConflict {
		t.Fatalf("Принят повторный ключ: %d %#v", code, out)
	}
}

func signP256P1363Test0123(t *testing.T, priv *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(payload))
	r, ss, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestDeviceTrustHardwareP256RegistrationAndBinding0123(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.3", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access1, _ := deviceTrustLogin0121(t, h, "hardware-label-a")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access1, map[string]any{
		"name":             "TPM workstation",
		"platform":         "linux",
		"clientVersion":    "0.12.3",
		"keyAlgorithm":     "p256",
		"keyBinding":       "hardware",
		"hardwareProvider": "test-tpm-2.0",
	})
	if code != http.StatusOK {
		t.Fatalf("Начало регистрации аппаратного ключа: статус=%d тело ответа=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	payload, _ := begin["signingPayload"].(string)
	if payload == "" || begin["keyAlgorithm"] != "p256" || begin["keyBinding"] != "hardware" || begin["hardwareProvider"] != "test-tpm-2.0" {
		t.Fatalf("Некорректные данные начала регистрации аппаратного ключа: %#v", begin)
	}
	completeBody := map[string]any{
		"challengeId": begin["challengeId"],
		"deviceId":    begin["deviceId"],
		"challenge":   begin["challenge"],
		"publicKey":   base64.RawURLEncoding.EncodeToString(publicKey),
		"signature":   signP256P1363Test0123(t, priv, payload),
	}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access1, completeBody)
	if code != http.StatusCreated {
		t.Fatalf("Завершение регистрации аппаратного ключа: статус=%d тело ответа=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	device, _ := complete["device"].(map[string]any)
	if device["keyAlgorithm"] != "p256" || device["keyBinding"] != "hardware" || device["hardwareProvider"] != "test-tpm-2.0" {
		t.Fatalf("Потеряны метаданные аппаратной идентификации: %#v", device)
	}
	if device["assurance"] != "proof-of-possession" {
		t.Fatalf("Неподтверждённый аппаратный ключ не должен повышать уровень доверия: %#v", device)
	}
	if _, leaks := device["publicKey"]; leaks {
		t.Fatalf("Публичный ключ неожиданно раскрыт в модели устройства API: %#v", device)
	}
	deviceID, _ := device["id"].(string)
	if deviceID == "" {
		t.Fatalf("Отсутствует идентификатор аппаратного устройства: %#v", device)
	}

	access2, _ := deviceTrustLogin0121(t, h, "hardware-label-b")
	code, verifyBeginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/verify/begin", access2, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("Начало проверки аппаратного ключа: статус=%d тело ответа=%#v", code, verifyBeginOut)
	}
	verifyBegin := deviceTrustData0121(t, verifyBeginOut)
	verifyPayload, _ := verifyBegin["signingPayload"].(string)
	if verifyPayload == "" || verifyBegin["keyAlgorithm"] != "p256" || verifyBegin["keyBinding"] != "hardware" {
		t.Fatalf("Некорректные данные проверки аппаратного ключа: %#v", verifyBegin)
	}
	code, verifyOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/verify/complete", access2, map[string]any{
		"challengeId": verifyBegin["challengeId"],
		"challenge":   verifyBegin["challenge"],
		"signature":   signP256P1363Test0123(t, priv, verifyPayload),
	})
	if code != http.StatusOK {
		t.Fatalf("Завершение проверки аппаратного ключа: статус=%d тело ответа=%#v", code, verifyOut)
	}
	if access, _ := deviceTrustData0121(t, verifyOut)["accessToken"].(string); access == "" {
		t.Fatalf("Отсутствует токен сессии, привязанный к аппаратному устройству: %#v", verifyOut)
	}
}
