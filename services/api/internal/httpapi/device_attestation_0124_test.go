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

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
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
		t.Fatalf("register begin status=%d body=%#v", code, beginOut)
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
		t.Fatalf("register complete status=%d body=%#v", code, completeOut)
	}
	data := deviceTrustData0121(t, completeOut)
	device, _ := data["device"].(map[string]any)
	deviceID, _ := device["id"].(string)
	trustedAccess, _ := data["accessToken"].(string)
	if deviceID == "" || trustedAccess == "" {
		t.Fatalf("incomplete registered device: %#v", data)
	}
	if device["attestationState"] != "unattested" || device["assurance"] != "proof-of-possession" {
		t.Fatalf("registration must not pre-attest hardware identity: %#v", device)
	}
	return deviceID, trustedAccess
}

func TestDeviceChallengeResponseAttestation0124(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-attestation", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.4", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access, _ := deviceTrustLogin0121(t, h, "attestation-primary")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, trustedAccess := registerHardwareDevice0124(t, h, access, priv)

	// A different login session has not proven/bound the device yet and cannot
	// ask the server to attest on behalf of the bound session.
	unboundAccess, _ := deviceTrustLogin0121(t, h, "attestation-unbound")
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", unboundAccess, map[string]any{})
	if code != http.StatusConflict {
		t.Fatalf("unbound session obtained attestation challenge: status=%d body=%#v", code, out)
	}

	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", trustedAccess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("attest begin status=%d body=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	payload, _ := begin["signingPayload"].(string)
	if payload == "" || begin["attestationMethod"] != deviceAttestationMethod0124 || begin["hardwareProvenance"] != "not-remotely-verified" {
		t.Fatalf("bad attestation begin contract: %#v", begin)
	}
	completeBody := map[string]any{
		"challengeId": begin["challengeId"],
		"deviceId":    deviceID,
		"challenge":   begin["challenge"],
		"signature":   signP256P1363Test0123(t, priv, payload),
	}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", trustedAccess, completeBody)
	if code != http.StatusOK {
		t.Fatalf("attest complete status=%d body=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	attestedAccess, _ := complete["accessToken"].(string)
	device, _ := complete["device"].(map[string]any)
	if attestedAccess == "" || complete["attestationState"] != "verified" || complete["attestationMethod"] != deviceAttestationMethod0124 {
		t.Fatalf("attestation result incomplete: %#v", complete)
	}
	if device["attestationState"] != "verified" || device["attestationMethod"] != deviceAttestationMethod0124 || device["assurance"] != "challenge-response-attested" {
		t.Fatalf("attestation was not persisted into trusted device: %#v", device)
	}
	if complete["hardwareProvenance"] != "not-remotely-verified" || complete["authorizationElevation"] != false || complete["phishingResistantElevation"] != false {
		t.Fatalf("attestation overstated authorization/vendor semantics: %#v", complete)
	}

	// A challenge is consumed before signature verification, so both a normal
	// replay and an attacker retry after a bad proof fail closed.
	code, replayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", attestedAccess, completeBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("attestation replay accepted: status=%d body=%#v", code, replayOut)
	}

	code, trustOut := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/device-trust", attestedAccess, nil)
	if code != http.StatusOK {
		t.Fatalf("device trust after attestation status=%d body=%#v", code, trustOut)
	}
	trust := deviceTrustData0121(t, trustOut)
	if trust["deviceAttestationState"] != "verified" || trust["deviceAttestationMethod"] != deviceAttestationMethod0124 {
		t.Fatalf("session status does not expose fresh attestation: %#v", trust)
	}

	code, badBeginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", attestedAccess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("second attest begin status=%d body=%#v", code, badBeginOut)
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
		t.Fatalf("wrong attestation signature accepted: status=%d body=%#v", code, badOut)
	}
	badBody["signature"] = signP256P1363Test0123(t, priv, badBegin["signingPayload"].(string))
	code, badReplayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", attestedAccess, badBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("consumed bad-proof challenge reused: status=%d body=%#v", code, badReplayOut)
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
		t.Fatalf("expired attestation did not downgrade: state=%s assurance=%s", state, assurance)
	}
}

func TestDeviceChallengeResponseAttestationRejectsSoftwareKey0124(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-device-attestation", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.12.4", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()

	access, _ := deviceTrustLogin0121(t, h, "software-attestation")
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{"name": "Software device"})
	if code != http.StatusOK {
		t.Fatalf("software register begin status=%d body=%#v", code, beginOut)
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
		t.Fatalf("software register complete status=%d body=%#v", code, completeOut)
	}
	data := deviceTrustData0121(t, completeOut)
	trustedAccess, _ := data["accessToken"].(string)
	device, _ := data["device"].(map[string]any)
	deviceID, _ := device["id"].(string)
	code, attestOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", trustedAccess, map[string]any{})
	if code != http.StatusConflict {
		t.Fatalf("software key was allowed into attestation: status=%d body=%#v", code, attestOut)
	}
}
