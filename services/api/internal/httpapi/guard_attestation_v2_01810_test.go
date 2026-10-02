package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func makeGuardContinuousEvidence01810(t *testing.T) guardContinuousEvidence01810 {
	t.Helper()
	now := uint64(time.Now().UTC().UnixMilli())
	h := func(ch string) string { return strings.Repeat(ch, 64) }
	e := guardContinuousEvidence01810{
		Schema: guardContinuousEvidenceSchema01810, EvidenceVersion: 2, ProcessID: "runtime-01810", RuntimePID: 200,
		CollectedAtUnixMS: now, SensorProtocolVersion: 3, SensorAuthenticated: true, SensorLoadedBeforeMain: true,
		ModuleGuardVersion: 1, ModuleGuardHealthy: true, ModuleEventCount: 9, ModuleLastSequence: 9,
		ModuleEventChainSHA256: h("1"), ModuleSetSHA256: h("2"), HookEngineHealthy: true, HookSetSHA256: h("3"),
		MemoryIntegrityHealthy: true, CodeSetSHA256: h("4"), ExecutableMapSHA256: h("5"),
		ThreadProcessIntegrityHealthy: true, JobBound: true, ThreadSetSHA256: h("6"), ThreadOriginSetSHA256: h("7"), ProcessTreeSHA256: h("8"),
		DebugInstrumentationHealthy: true, DebugStateSHA256: h("9"), JVMAwareHealthy: true, JavaMajor: 21, JVMStateSHA256: h("a"),
		ContinuousGuardVersion: 1, ContinuousGuardHealthy: true, SensorHeartbeatCount: 3, GuardHeartbeatCount: 3, CrossCheckCount: 3,
		LastSensorSequence: 11, LastGuardSequence: 3, SensorEventChainSHA256: h("b"), LastCrossCheckSHA256: h("c"),
		LastSensorHeartbeatUnixMS: now, LastGuardHeartbeatUnixMS: now,
	}
	e.EvidenceSHA256 = recomputeGuardContinuousEvidenceSHA25601810(e)
	return e
}

func makeGuardAttestationV201810(t *testing.T, challengeID, challenge string) guardRemoteAttestationV201810 {
	t.Helper()
	continuous := makeGuardContinuousEvidence01810(t)
	base := makeGuardAttestation0134(t, challengeID, challenge)
	a := guardRemoteAttestationV201810{
		Schema: guardAttestationV2Schema01810, AttestationVersion: 2, ChallengeID: challengeID,
		ChallengeSHA256: deviceChallengeHash0121(challenge), CollectedAtUnixMS: continuous.CollectedAtUnixMS,
		BaseAttestation: base, ContinuousEvidence: continuous,
	}
	a.AttestationSHA256 = recomputeGuardAttestationV2SHA25601810(a)
	return a
}

func TestGuardAttestationV2ValidatesFreshContinuousEvidence01810(t *testing.T) {
	policy := guardReleasePolicy0134{GuardSHA256: []string{testGuardHash0134}, LauncherSHA256: []string{testLauncherHash0134}, RequireAuthenticode: true}
	a := makeGuardAttestationV201810(t, "v2-challenge", "v2-secret")
	now := time.Now().UTC()
	if err := validateGuardAttestationV201810(a, "v2-challenge", "v2-secret", policy, "windows", now, now.Add(-time.Second)); err != nil {
		t.Fatalf("fresh Attestation v2 rejected: %v", err)
	}
}

func TestGuardAttestationV2RejectsStaleAndDivergedContinuousEvidence01810(t *testing.T) {
	policy := guardReleasePolicy0134{GuardSHA256: []string{testGuardHash0134}, LauncherSHA256: []string{testLauncherHash0134}, RequireAuthenticode: true}
	a := makeGuardAttestationV201810(t, "v2-challenge", "v2-secret")
	now := time.Now().UTC()
	a.ContinuousEvidence.GuardHeartbeatCount++
	a.ContinuousEvidence.EvidenceSHA256 = recomputeGuardContinuousEvidenceSHA25601810(a.ContinuousEvidence)
	a.AttestationSHA256 = recomputeGuardAttestationV2SHA25601810(a)
	if err := validateGuardAttestationV201810(a, "v2-challenge", "v2-secret", policy, "windows", now, now.Add(-time.Second)); err == nil {
		t.Fatal("diverged Sensor/Guard heartbeat counters were accepted")
	}

	a = makeGuardAttestationV201810(t, "v2-challenge", "v2-secret")
	stale := uint64(now.Add(-10 * time.Second).UnixMilli())
	a.ContinuousEvidence.CollectedAtUnixMS = stale
	a.ContinuousEvidence.LastSensorHeartbeatUnixMS = stale
	a.ContinuousEvidence.LastGuardHeartbeatUnixMS = stale
	a.CollectedAtUnixMS = stale
	a.ContinuousEvidence.EvidenceSHA256 = recomputeGuardContinuousEvidenceSHA25601810(a.ContinuousEvidence)
	a.AttestationSHA256 = recomputeGuardAttestationV2SHA25601810(a)
	if err := validateGuardAttestationV201810(a, "v2-challenge", "v2-secret", policy, "windows", now, now.Add(-time.Second)); err == nil {
		t.Fatal("stale Continuous Guard evidence was accepted")
	}
}

func TestGuardAttestationV2EndpointIssuesOneTimeContinuousTicket01810(t *testing.T) {
	allowlist := `{"schemaVersion":"2.0","releases":{"0.18.10":{"protocolVersion":4,"platforms":{"windows":{"signingMode":"authenticode","artifacts":[{"guardSha256":"` + testGuardHash0134 + `","launcherSha256":"` + testLauncherHash0134 + `","requireAuthenticode":true}]}}}}}`
	cfg := config.Config{
		PublicURL: "https://api.example.test", Environment: "test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-guard-attestation-v2",
		AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api",
		WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"},
		GuardReleaseAllowlistJSON: allowlist,
	}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	server := Server{Version: "0.18.10", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}
	h := server.Handler()

	access, _ := deviceTrustLogin0121(t, h, "guard-attestation-v2-user")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, trustedAccess := registerWindowsHardwareDevice0134(t, h, access, priv)
	attestedAccess := attestHardwareDeviceForGuard0134(t, h, trustedAccess, deviceID, priv)
	claims := authClaimsFromToken0134(t, attestedAccess)
	device, err := repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil {
		t.Fatal(err)
	}

	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/guard-attest-v2/begin", attestedAccess, map[string]any{"launcherVersion": "0.18.10"})
	if code != http.StatusOK {
		t.Fatalf("v2 begin status=%d body=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	challengeID := begin["challengeId"].(string)
	challenge := begin["challenge"].(string)
	expiresAt := begin["expiresAt"].(string)
	attestation := makeGuardAttestationV201810(t, challengeID, challenge)
	payload := guardDeviceSigningPayloadV201810(challenge, claims, device, "0.18.10", attestation, expiresAt)
	body := map[string]any{
		"challengeId": challengeID, "challenge": challenge, "challengeExpiresAt": expiresAt,
		"launcherVersion": "0.18.10", "attestation": attestation, "signature": signP256P1363Test0123(t, priv, payload),
	}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/guard-attest-v2/complete", attestedAccess, body)
	if code != http.StatusOK {
		t.Fatalf("v2 complete status=%d body=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	ticket, _ := complete["continuousGuardTicket"].(string)
	if ticket == "" || complete["verified"] != true || complete["oneTime"] != true {
		t.Fatalf("incomplete v2 result: %#v", complete)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/join", nil)
	consumed, err := server.consumeGuardContinuousJoinTicket01810(req, claims, ticket)
	if err != nil {
		t.Fatalf("fresh Continuous Guard ticket rejected: %v", err)
	}
	minecraftSession := model.MinecraftSession{
		ID: "minecraft-01810", IntegrityVerified: true, LauncherVersion: "0.18.10",
		GuardSHA256: testGuardHash0134, LauncherSHA256: testLauncherHash0134,
	}
	if err := validateContinuousGuardTicketForMinecraftSession01810(consumed, minecraftSession); err != nil {
		t.Fatalf("Continuous Guard ticket did not bind to the verified Minecraft session: %v", err)
	}
	minecraftSession.GuardSHA256 = strings.Repeat("f", 64)
	if err := validateContinuousGuardTicketForMinecraftSession01810(consumed, minecraftSession); err == nil {
		t.Fatal("Continuous Guard ticket accepted a different Guard artifact hash")
	}
	if _, err := server.consumeGuardContinuousJoinTicket01810(req, claims, ticket); err == nil {
		t.Fatal("replayed Continuous Guard ticket was accepted")
	}
}
