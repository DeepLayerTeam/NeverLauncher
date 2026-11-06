package httpapi

import (
	"context"
	"net/http"
	"testing"
)

// Имитирует независимую реплику API, которая первой отзывает устройство в
// устойчивом хранилище. Старый access-токен должен отклоняться ещё до
// локальной очистки сеанса.
func TestDirectDeviceRevocationDeniesStaleAccessAndRefresh0434(t *testing.T) {
	handler, repo := deviceTrustFixture0432(t)
	unbound, refresh := deviceTrustLogin0121(t, handler, "revocation-race")
	bound, id, _ := registerDevice0432(t, handler, unbound, "Revoked workstation")
	code, _ := deviceTrustRequest0121(t, handler, http.MethodGet, "/api/v1/auth/device-trust", bound, nil)
	if code != http.StatusOK {
		t.Fatalf("Токен до отзыва: %d", code)
	}
	device, err := repo.GetTrustedDeviceByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeTrustedDevice(context.Background(), device.UserID, id, "compromised"); err != nil {
		t.Fatalf("Отзыв доверенного устройства: %v", err)
	}
	code, _ = deviceTrustRequest0121(t, handler, http.MethodGet, "/api/v1/auth/device-trust", bound, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("Отозванный ключ сохранил доступ по Bearer-токену: %d", code)
	}
	code, _ = deviceTrustRequest0121(t, handler, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": refresh})
	if code != http.StatusUnauthorized {
		t.Fatalf("Отозванное устройство обновило старый сеанс: %d", code)
	}
}
