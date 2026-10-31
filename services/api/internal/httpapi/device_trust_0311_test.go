package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func TestDeviceTrustBaselineStrictCannotBeSelfDeclared0311(t *testing.T) {
	now := time.Now().UTC()
	d := model.TrustedDevice{Status: "active", TrustState: "verified", KeyAlgorithm: "p256", KeyBinding: "hardware", HardwareProvider: "TPM", KeyFingerprint: strings.Repeat("f", 64), RemoteHardwareProvenance: "verified", AttestationState: "verified", AttestationMethod: "challenge-response-v1", AttestedAt: now.Add(-time.Minute), AttestationExpiresAt: now.Add(time.Hour)}
	clean := sanitizeTrustedDevice0121(d)
	if clean.RemoteHardwareProvenance != "not-verified" || clean.TrustAssessment.ProfileDecisions["strict"].Result != "deny" || clean.TrustAssessment.LocalHardwareBinding != "client-reported" {
		t.Fatalf("legacy self-declaration elevated: %+v", clean)
	}
}

func TestTrustProfileQueryRequiresBoundDevice0311(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-trust", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	srv := Server{Version: "0.31.1", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	access, _ := deviceTrustLogin0121(t, srv, "nonbound")
	code, data := deviceTrustRequest0121(t, srv, http.MethodGet, "/api/v1/auth/device-trust?requireProfile=strict", access, nil)
	if code != http.StatusForbidden {
		t.Fatalf("strict must deny, status=%d payload=%#v", code, data)
	}
	policy := deviceTrustData0121(t, data)["trustAssessment"].(map[string]any)["profileDecisions"].(map[string]any)
	if policy["strict"].(map[string]any)["result"] != "deny" {
		t.Fatalf("unexpected verdict %#v", policy)
	}
	code, _ = deviceTrustRequest0121(t, srv, http.MethodGet, "/api/v1/auth/device-trust?requireProfile=superuser", access, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid profile accepted, got %d", code)
	}
	code, _ = deviceTrustRequest0121(t, srv, http.MethodGet, "/api/v1/auth/device-trust", access, nil)
	if code != http.StatusOK {
		t.Fatalf("legacy status unexpectedly rejected: %d", code)
	}
}
