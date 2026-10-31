package httpapi

import (
	"context"
	"net/http"
	"testing"
)

// Simulates an independent API replica revoking the durable device first.
// The old access token must fail even before local session cleanup runs.
func TestDirectDeviceRevocationDeniesStaleAccessAndRefresh0434(t *testing.T) {
	handler, repo := deviceTrustFixture0432(t)
	unbound, refresh := deviceTrustLogin0121(t, handler, "revocation-race")
	bound, id, _ := registerDevice0432(t, handler, unbound, "Revoked workstation")
	code, _ := deviceTrustRequest0121(t, handler, http.MethodGet, "/api/v1/auth/device-trust", bound, nil)
	if code != http.StatusOK {
		t.Fatalf("pre-revoke token: %d", code)
	}
	device, err := repo.GetTrustedDeviceByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeTrustedDevice(context.Background(), device.UserID, id, "compromised"); err != nil {
		t.Fatalf("revoke trusted device: %v", err)
	}
	code, _ = deviceTrustRequest0121(t, handler, http.MethodGet, "/api/v1/auth/device-trust", bound, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked key retained bearer access: %d", code)
	}
	code, _ = deviceTrustRequest0121(t, handler, http.MethodPost, "/api/v1/auth/refresh", "", map[string]any{"refreshToken": refresh})
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked device refreshed the old session: %d", code)
	}
}
