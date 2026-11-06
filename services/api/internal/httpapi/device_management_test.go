package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

type registeredDevice0125 struct {
	ID      string
	Access  string
	Refresh string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func registerSoftwareDevice0125(t *testing.T, h http.Handler, loginLabel, name string) registeredDevice0125 {
	t.Helper()
	access, refresh := deviceTrustLogin0121(t, h, loginLabel)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{
		"name": name, "platform": "linux", "clientVersion": "0.12.5",
	})
	if code != http.StatusOK {
		t.Fatalf("Начало регистрации: статус=%d, тело=%#v", code, out)
	}
	begin := deviceTrustData0121(t, out)
	payload, _ := begin["signingPayload"].(string)
	code, out = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
		"challengeId": begin["challengeId"], "deviceId": begin["deviceId"], "challenge": begin["challenge"],
		"publicKey": base64.RawURLEncoding.EncodeToString(pub), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload))),
	})
	if code != http.StatusCreated {
		t.Fatalf("Завершение регистрации: статус=%d, тело=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	trusted, _ := data["accessToken"].(string)
	device, _ := data["device"].(map[string]any)
	id, _ := device["id"].(string)
	if trusted == "" || id == "" {
		t.Fatalf("Неполный результат регистрации: %#v", data)
	}
	return registeredDevice0125{ID: id, Access: trusted, Refresh: refresh, Public: pub, Private: priv}
}

func TestDeviceManagementRevokeOthersAndChallengeInvalidation0125(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-management", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.5", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	primary := registerSoftwareDevice0125(t, h, "management-primary", "Primary workstation")
	secondary := registerSoftwareDevice0125(t, h, "management-secondary", "Secondary workstation")

	code, listOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices?status=active", primary.Access, nil)
	if code != http.StatusOK {
		t.Fatalf("Список активных: статус=%d, тело=%#v", code, listOut)
	}
	list := deviceTrustData0121(t, listOut)
	if list["currentDeviceId"] != primary.ID || int(list["count"].(float64)) != 2 {
		t.Fatalf("Неожиданный список управления устройствами: %#v", list)
	}
	items, _ := list["items"].([]any)
	current := 0
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if item["current"] == true {
			current++
		}
		if item["revocationPermanent"] != true {
			t.Fatalf("Устройство не предоставляет семантику постоянного отзыва: %#v", item)
		}
	}
	if current != 1 {
		t.Fatalf("Ожидалось одно текущее устройство, получено %d: %#v", current, items)
	}

	unboundAccess, _ := deviceTrustLogin0121(t, h, "management-unbound")
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/revoke-others", unboundAccess, map[string]any{})
	if code != http.StatusConflict {
		t.Fatalf("Непривязанная сессия отозвала устройства: статус=%d ответ=%#v", code, out)
	}

	// Оставьте ожидающий запрос подтверждения для второго устройства.
	// Отзыв должен погасить его до завершения процедуры старым ключом.
	code, challengeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+secondary.ID+"/verify/begin", unboundAccess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("Начало проверки: статус=%d, тело=%#v", code, challengeOut)
	}
	challenge := deviceTrustData0121(t, challengeOut)
	payload, _ := challenge["signingPayload"].(string)
	proof := base64.RawURLEncoding.EncodeToString(ed25519.Sign(secondary.Private, []byte(payload)))

	code, revokeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/revoke-others", primary.Access, map[string]any{"reason": "user-replaced-device"})
	if code != http.StatusOK {
		t.Fatalf("Отзыв других: статус=%d, тело=%#v", code, revokeOut)
	}
	revoked := deviceTrustData0121(t, revokeOut)
	if revoked["preservedDeviceId"] != primary.ID || int(revoked["revokedDevices"].(float64)) != 1 || int(revoked["revokedSessions"].(float64)) < 1 || int(revoked["invalidatedChallenges"].(float64)) < 1 {
		t.Fatalf("Неполная цепочка отзыва: %#v", revoked)
	}
	if revoked["reEnrollmentRequiresNewKey"] != true {
		t.Fatalf("Отсутствует предусмотренное поведение повторной регистрации: %#v", revoked)
	}

	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", secondary.Access, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("Вторичный токен доступа остался действителен после отзыва устройства: %d", code)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": secondary.Refresh})
	if code != http.StatusUnauthorized {
		t.Fatalf("Вторичное семейство токенов обновления сохранилось после отзыва устройства: %d", code)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+secondary.ID+"/verify/complete", unboundAccess, map[string]any{
		"challengeId": challenge["challengeId"], "challenge": challenge["challenge"], "signature": proof,
	})
	if code == http.StatusOK {
		t.Fatalf("Запрос подтверждения, созданный до отзыва, успешно завершился после отзыва: %d", code)
	}

	code, activeOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices?status=active", primary.Access, nil)
	if code != http.StatusOK || int(deviceTrustData0121(t, activeOut)["count"].(float64)) != 1 {
		t.Fatalf("Неверная фильтрация активных устройств: статус=%d ответ=%#v", code, activeOut)
	}
	code, revokedOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices?status=revoked", primary.Access, nil)
	if code != http.StatusOK || int(deviceTrustData0121(t, revokedOut)["count"].(float64)) != 1 {
		t.Fatalf("Неверная фильтрация отозванных устройств: статус=%d ответ=%#v", code, revokedOut)
	}

	// Отозванный отпечаток — постоянная отметка: тот же ключ больше нельзя зарегистрировать.
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", unboundAccess, map[string]any{"name": "Reuse revoked key"})
	if code != http.StatusOK {
		t.Fatalf("Неожиданный сбой при начале повторного использования: %d %#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	reusePayload, _ := begin["signingPayload"].(string)
	code, _ = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", unboundAccess, map[string]any{
		"challengeId": begin["challengeId"], "deviceId": begin["deviceId"], "challenge": begin["challenge"],
		"publicKey": base64.RawURLEncoding.EncodeToString(secondary.Public), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(secondary.Private, []byte(reusePayload))),
	})
	if code != http.StatusConflict {
		t.Fatalf("Отозванный ключ устройства зарегистрирован повторно: %d", code)
	}
}

func TestDeviceManagementSelfRevokeIsPermanentAndIdempotent0125(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-management-self", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.5", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	device := registerSoftwareDevice0125(t, h, "self-primary", "Self revoke workstation")

	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+device.ID+"/revoke", device.Access, map[string]any{"reason": "lost-device"})
	if code != http.StatusOK {
		t.Fatalf("Самостоятельный отзыв: статус=%d, тело=%#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	if data["alreadyRevoked"] != false || data["reEnrollmentRequiresNewKey"] != true || int(data["revokedSessions"].(float64)) < 1 {
		t.Fatalf("Некорректный результат самостоятельного отзыва: %#v", data)
	}
	code, _ = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices", device.Access, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("Сессия осталась активной после самостоятельного отзыва: %d", code)
	}

	fresh, _ := deviceTrustLogin0121(t, h, "post-revoke-unbound")
	code, out = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+device.ID+"/revoke", fresh, map[string]any{})
	if code != http.StatusOK || deviceTrustData0121(t, out)["alreadyRevoked"] != true {
		t.Fatalf("Повторный отзыв не является идемпотентным: статус=%d ответ=%#v", code, out)
	}

	code, out = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/devices?status=unknown", fresh, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("Принят недопустимый фильтр состояния: статус=%d ответ=%#v", code, out)
	}
}
