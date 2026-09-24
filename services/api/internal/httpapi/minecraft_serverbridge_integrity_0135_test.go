package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

const (
	bridgeVelocityHash0135 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	bridgePaperHash0135    = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	bridgePurpurHash0135   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	guardHash0135          = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	launcherHash0135       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func integrityBridgeHandler0135(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Config{
		HTTPAddr:                   "127.0.0.1:0",
		PublicURL:                  "http://example.test",
		RepositoryDriver:           "memory",
		StorageDriver:              "local",
		StorageLocalPath:           t.TempDir(),
		BackupRoot:                 t.TempDir(),
		CORSAllowedOrigins:         []string{"http://example.test"},
		Environment:                "test",
		AuthTokenSecret:            "test-secret-for-0135-integrity",
		AuthTokenTTLHours:          1,
		WebAuthnRPID:               "example.test",
		WebAuthnRPName:             "NeverLauncher Test",
		WebAuthnOrigins:            []string{"http://example.test"},
		BridgeReleaseAllowlistJSON: `{"0.13.5":{"velocitySha256":["` + bridgeVelocityHash0135 + `"],"paperSha256":["` + bridgePaperHash0135 + `"],"purpurSha256":["` + bridgePurpurHash0135 + `"]}}`,
	}
	store := storage.NewLocalStorage(cfg.StorageLocalPath)
	return Server{Version: "0.13.5", Config: cfg, Repo: repository.NewMemoryRepository(cfg.PublicURL), Storage: store}.Handler()
}

func TestServerBridgeArtifactIntegrity0135RejectsUnmeasuredAndRevokedBoundary(t *testing.T) {
	h := integrityBridgeHandler0135(t)
	admin := loginAdmin(t, h)
	admin, _ = registerTestPasskey117(t, h, admin)

	register := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/register", strings.NewReader(`{"id":"paper-0135","name":"Paper 0135","kind":"paper","projectId":"demo-project","profileId":"vanilla"}`))
	register.Header.Set("Authorization", "Bearer "+admin)
	register.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, register)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register=%d %s", rr.Code, rr.Body.String())
	}
	var registered struct {
		Data struct {
			ServerToken string `json:"serverToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &registered); err != nil || registered.Data.ServerToken == "" {
		t.Fatalf("server token missing: %v %s", err, rr.Body.String())
	}

	heartbeat := func(hash string) *httptest.ResponseRecorder {
		body := `{"serverType":"paper","pluginVersion":"0.13.5","pluginSha256":"` + hash + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/paper-0135/heartbeat", strings.NewReader(body))
		req.Header.Set("X-NeverLauncher-Server-Token", registered.Data.ServerToken)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out
	}
	if bad := heartbeat(strings.Repeat("f", 64)); bad.Code != http.StatusPreconditionFailed || !strings.Contains(bad.Body.String(), "bridge_integrity_hash_rejected") {
		t.Fatalf("wrong jar hash accepted: %d %s", bad.Code, bad.Body.String())
	}
	if ok := heartbeat(bridgePaperHash0135); ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "bridge_integrity_verified") {
		t.Fatalf("allowlisted jar hash rejected: %d %s", ok.Code, ok.Body.String())
	}

	access, _ := deviceTrustLogin0121(t, h, "bridge-integrity-0135")
	bound := bindAccessToken0127(t, h, access, "Bridge integrity Linux device")
	join := httptest.NewRequest(http.MethodPost, "/api/v1/session/join", strings.NewReader(`{"serverId":"paper-0135","projectId":"demo-project","profileId":"vanilla","channel":"stable","username":"HashPlayer"}`))
	join.Header.Set("Authorization", "Bearer "+bound.Access)
	join.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(join)
	jv := httptest.NewRecorder()
	h.ServeHTTP(jv, join)
	if jv.Code != http.StatusOK {
		t.Fatalf("join=%d %s", jv.Code, jv.Body.String())
	}

	validate := func(includeMeasurement bool) *httptest.ResponseRecorder {
		body := `{"serverId":"paper-0135","username":"HashPlayer","projectId":"demo-project","profileId":"vanilla","channel":"stable"`
		if includeMeasurement {
			body += `,"pluginVersion":"0.13.5","pluginSha256":"` + bridgePaperHash0135 + `"`
		}
		body += `}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/validate-join", strings.NewReader(body))
		req.Header.Set("X-NeverLauncher-Server-Token", registered.Data.ServerToken)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out
	}
	if missing := validate(false); missing.Code != http.StatusPreconditionFailed || !strings.Contains(missing.Body.String(), "bridge_integrity_request_measurement_mismatch") {
		t.Fatalf("validate-join without current artifact measurement accepted: %d %s", missing.Code, missing.Body.String())
	}
	if valid := validate(true); valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"allowed":true`) {
		t.Fatalf("integrity-bound validate-join rejected: %d %s", valid.Code, valid.Body.String())
	}

	rotate := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/paper-0135/rotate-token", nil)
	rotate.Header.Set("Authorization", "Bearer "+admin)
	rv := httptest.NewRecorder()
	h.ServeHTTP(rv, rotate)
	if rv.Code != http.StatusOK {
		t.Fatalf("rotate=%d %s", rv.Code, rv.Body.String())
	}
	var rotated struct {
		Data struct {
			ServerToken string `json:"serverToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rv.Body.Bytes(), &rotated); err != nil || rotated.Data.ServerToken == "" {
		t.Fatalf("rotated token missing: %v %s", err, rv.Body.String())
	}
	hasJoined := httptest.NewRequest(http.MethodGet, "/api/v1/session/has-joined?username=HashPlayer&serverId=paper-0135", nil)
	hasJoined.Header.Set("X-NeverLauncher-Server-Token", rotated.Data.ServerToken)
	hv := httptest.NewRecorder()
	h.ServeHTTP(hv, hasJoined)
	if hv.Code != http.StatusPreconditionFailed || !strings.Contains(hv.Body.String(), "bridge_integrity_heartbeat_required") {
		t.Fatalf("token rotation failed to invalidate bridge measurement: %d %s", hv.Code, hv.Body.String())
	}
}

func TestMinecraftIntegritySnapshot0135IsReevaluatedAgainstCurrentReleasePolicy(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	_, err := repo.SaveTrustedDevice(context.Background(), model.TrustedDevice{
		ID: "win-device-0135", UserID: "user-0135", Name: "Windows device", Platform: "windows",
		PublicKey: "test-public-key", KeyFingerprint: strings.Repeat("1", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Environment:               "test",
		GuardReleaseAllowlistJSON: `{"0.13.5":{"guardSha256":["` + guardHash0135 + `"],"launcherSha256":["` + launcherHash0135 + `"],"requireAuthenticode":false}}`,
	}
	s := Server{Version: "0.13.5", Config: cfg, Repo: repo}
	now := time.Now().UTC()
	session := model.MinecraftSession{
		ID: "mc-0135", UserID: "user-0135", NeverSessionID: "never-session-0135", ProfileUUID: "00000000-0000-0000-0000-000000000135",
		TrustedDeviceID: "win-device-0135", BindingEpoch: 7, AccessTokenHash: strings.Repeat("2", 64), Status: "active",
		IntegrityVerified: true, GuardAttestationSHA256: strings.Repeat("3", 64), GuardEvidenceSHA256: strings.Repeat("4", 64),
		GuardSHA256: guardHash0135, LauncherSHA256: launcherHash0135, LauncherVersion: "0.13.5", IntegrityVerifiedAt: now.Add(-time.Second),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if _, err := repo.SaveMinecraftSession(session); err != nil {
		t.Fatal(err)
	}
	if decision := s.evaluateMinecraftIntegrity0135(session); !decision.Allowed || !decision.Required {
		t.Fatalf("valid integrity snapshot rejected: %+v", decision)
	}
	join := bridgeJoinRecord{UserID: session.UserID, SessionID: session.NeverSessionID, TrustedDeviceID: session.TrustedDeviceID, BindingEpoch: session.BindingEpoch, MinecraftSessionID: session.ID}
	if _, decision := s.evaluateServerBridgeJoinIntegrity0135(join); !decision.Allowed {
		t.Fatalf("ServerBridge rejected integrity-bound Minecraft session: %+v", decision)
	}

	// Removing the shipped hashes is an immediate revocation: an already issued
	// Minecraft credential and a previously created ServerBridge join must fail.
	s.Config.GuardReleaseAllowlistJSON = `{"0.13.5":{"guardSha256":["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],"launcherSha256":["` + launcherHash0135 + `"],"requireAuthenticode":false}}`
	if decision := s.evaluateMinecraftIntegrity0135(session); decision.Allowed || decision.Reason != "integrity_release_revoked" {
		t.Fatalf("revoked Guard release remained valid: %+v", decision)
	}
	if _, decision := s.evaluateServerBridgeJoinIntegrity0135(join); decision.Allowed || decision.Reason != "integrity_release_revoked" {
		t.Fatalf("ServerBridge failed live Guard release revocation: %+v", decision)
	}
}

func TestGuardIntegrityRequirementIncludesMacOS01310(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	_, err := repo.SaveTrustedDevice(context.Background(), model.TrustedDevice{
		ID: "mac-device-01310", UserID: "user-01310", Name: "macOS device", Platform: "darwin-arm64",
		PublicKey: "test-public-key", KeyFingerprint: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Version: "0.13.10", Config: config.Config{Environment: "test", GuardReleaseAllowlistJSON: `{}`}, Repo: repo}
	required, err := guardAttestationRequiredForDevice0135(s, "user-01310", "mac-device-01310")
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("macOS trusted device must require persisted Guard integrity for Minecraft/ServerBridge")
	}
}

func TestMinecraftIntegrityV2RejectsCrossProductArtifactPair0140(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	_, err := repo.SaveTrustedDevice(context.Background(), model.TrustedDevice{
		ID: "win-device-0140", UserID: "user-0140", Name: "Windows device", Platform: "windows-amd64",
		PublicKey: "test-public-key", KeyFingerprint: strings.Repeat("1", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	guardA := strings.Repeat("a", 64)
	launcherA := strings.Repeat("b", 64)
	guardB := strings.Repeat("c", 64)
	launcherB := strings.Repeat("d", 64)
	cfg := config.Config{Environment: "test", GuardReleaseAllowlistJSON: `{
		"schemaVersion":"2.0",
		"releases":{"0.14.0":{"protocolVersion":4,"platforms":{"windows":{
			"signingMode":"unsigned-development",
			"artifacts":[
				{"guardSha256":"` + guardA + `","launcherSha256":"` + launcherA + `","requireAuthenticode":false},
				{"guardSha256":"` + guardB + `","launcherSha256":"` + launcherB + `","requireAuthenticode":false}
			]
		}}}}
	}`}
	s := Server{Version: "0.14.0", Config: cfg, Repo: repo}
	now := time.Now().UTC()
	session := model.MinecraftSession{
		ID: "mc-0140", UserID: "user-0140", NeverSessionID: "never-session-0140", ProfileUUID: "00000000-0000-0000-0000-000000000140",
		TrustedDeviceID: "win-device-0140", BindingEpoch: 1, AccessTokenHash: strings.Repeat("2", 64), Status: "active",
		IntegrityVerified: true, GuardAttestationSHA256: strings.Repeat("3", 64), GuardEvidenceSHA256: strings.Repeat("4", 64),
		GuardSHA256: guardA, LauncherSHA256: launcherA, LauncherVersion: "0.14.0", IntegrityVerifiedAt: now.Add(-time.Second),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if decision := s.evaluateMinecraftIntegrity0135(session); !decision.Allowed {
		t.Fatalf("exact v2 artifact pair rejected: %+v", decision)
	}
	session.LauncherSHA256 = launcherB
	if decision := s.evaluateMinecraftIntegrity0135(session); decision.Allowed || decision.Reason != "integrity_release_revoked" {
		t.Fatalf("cross-product v2 artifact pair remained valid: %+v", decision)
	}
}
