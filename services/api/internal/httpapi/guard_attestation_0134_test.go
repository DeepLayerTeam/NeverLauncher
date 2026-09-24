package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func authClaimsFromToken0134(t *testing.T, token string) authClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid access token shape")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token claims: %v", err)
	}
	var claims authClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("decode access token claims json: %v", err)
	}
	if claims.Sub == "" || claims.SessionID == "" {
		t.Fatalf("access token is missing subject/session claims")
	}
	return claims
}

const (
	testGuardHash0134    = "4444444444444444444444444444444444444444444444444444444444444444"
	testLauncherHash0134 = "5555555555555555555555555555555555555555555555555555555555555555"
)

func makeGuardAttestation0134(t *testing.T, challengeID, challenge string) guardRemoteAttestation0134 {
	t.Helper()
	u := func(value uint32) *uint32 { return &value }
	process := func(pid uint32, imageHash, moduleHash string) guardProcessIntegrityEvidence0134 {
		return guardProcessIntegrityEvidence0134{
			PID: pid, ImagePath: `C:\\NeverLauncher\\binary.exe`, ImageSHA256: imageHash,
			ImageSize: 1024, ImageModifiedUnixMS: 1000, ProcessCreatedFiletime: 100,
			Authenticode: guardAuthenticodeEvidence0134{Trusted: true, Status: "0x00000000"},
			Mitigations: guardProcessMitigationEvidence0134{
				DEP: u(1), ASLR: u(1), DynamicCode: u(1), ExtensionPointDisable: u(1), ControlFlowGuard: u(1),
				BinarySignature: u(1), ImageLoad: u(7), ChildProcess: u(1), UserShadowStack: u(1), SEHOP: u(1),
				QueryFailures: []string{},
			},
			Modules: guardModuleSetEvidence0134{ModuleCount: 2, ModuleSetSHA256: moduleHash, NonSystemModuleNames: []string{}},
		}
	}
	now := uint64(time.Now().UTC().Unix())
	evidence := guardIntegrityEvidence0134{
		Schema: guardIntegritySchema0134, EvidenceVersion: 1, EvidenceID: strings.Repeat("a", 32), CollectedAtUnix: now,
		Boundary:     guardBoundaryEvidence0134{ExpectedParentPID: 100, ObservedParentPID: 100, ParentMatches: true},
		Guard:        process(101, testGuardHash0134, strings.Repeat("6", 64)),
		Launcher:     process(100, testLauncherHash0134, strings.Repeat("7", 64)),
		SessionProof: strings.Repeat("8", 64),
	}
	digest, err := recomputeGuardEvidenceSHA2560134(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.EvidenceSHA256 = digest
	a := guardRemoteAttestation0134{
		Schema: guardAttestationSchema0134, AttestationVersion: 1, ChallengeID: challengeID,
		ChallengeSHA256: deviceChallengeHash0121(challenge), CollectedAtUnix: now, Evidence: evidence,
		ProcessPolicy: guardProcessPolicyReport0134{
			Schema: guardProcessPolicySchema0134, PolicyVersion: 1, PID: 101, Enforced: true,
			DynamicCodeProhibited: true, ExtensionPointsDisabled: true, StrictHandleChecks: true,
			RemoteImagesBlocked: true, LowMandatoryLabelImagesBlocked: true, PreferSystem32Images: true,
			ChildProcessCreationBlocked: true,
		},
		SessionProof: strings.Repeat("9", 64),
	}
	a.AttestationSHA256 = recomputeGuardAttestationSHA2560134(a)
	return a
}

func registerWindowsHardwareDevice0134(t *testing.T, h http.Handler, access string, priv *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	publicKey := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{
		"name": "NeverGuard Windows attestation workstation", "platform": "Win32", "clientVersion": "0.13.4",
		"keyAlgorithm": "p256", "keyBinding": "hardware", "hardwareProvider": "test-windows-hardware-p256",
	})
	if code != http.StatusOK {
		t.Fatalf("register begin status=%d body=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	payload, _ := begin["signingPayload"].(string)
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
		"challengeId": begin["challengeId"], "deviceId": begin["deviceId"], "challenge": begin["challenge"],
		"publicKey": base64.RawURLEncoding.EncodeToString(publicKey), "signature": signP256P1363Test0123(t, priv, payload),
	})
	if code != http.StatusCreated {
		t.Fatalf("register complete status=%d body=%#v", code, completeOut)
	}
	data := deviceTrustData0121(t, completeOut)
	device, _ := data["device"].(map[string]any)
	deviceID, _ := device["id"].(string)
	trustedAccess, _ := data["accessToken"].(string)
	if deviceID == "" || trustedAccess == "" {
		t.Fatalf("incomplete registered Windows device: %#v", data)
	}
	return deviceID, trustedAccess
}

func attestHardwareDeviceForGuard0134(t *testing.T, h http.Handler, trustedAccess, deviceID string, priv *ecdsa.PrivateKey) string {
	t.Helper()
	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/begin", trustedAccess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("device attest begin status=%d body=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	payload := begin["signingPayload"].(string)
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/attest/complete", trustedAccess, map[string]any{
		"challengeId": begin["challengeId"], "deviceId": deviceID, "challenge": begin["challenge"],
		"signature": signP256P1363Test0123(t, priv, payload),
	})
	if code != http.StatusOK {
		t.Fatalf("device attest complete status=%d body=%#v", code, completeOut)
	}
	return deviceTrustData0121(t, completeOut)["accessToken"].(string)
}

func TestGuardAttestationBackendVerificationAndOneTimeLaunchTicket0134(t *testing.T) {
	allowlist := `{"0.13.4":{"guardSha256":["` + testGuardHash0134 + `"],"launcherSha256":["` + testLauncherHash0134 + `"],"requireAuthenticode":true}}`
	cfg := config.Config{
		PublicURL: "https://api.example.test", Environment: "test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-guard-attestation",
		AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "neverlauncher-api",
		WebAuthnRPID: "api.example.test", WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://api.example.test"},
		GuardReleaseAllowlistJSON: allowlist,
	}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	server := Server{Version: "0.13.4", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}
	h := server.Handler()

	access, _ := deviceTrustLogin0121(t, h, "guard-attestation-user")
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

	code, missingOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/minecraft/session", attestedAccess, map[string]any{"clientToken": "guard-missing"})
	if code != http.StatusPreconditionFailed {
		t.Fatalf("Windows Minecraft session without Guard ticket status=%d body=%#v", code, missingOut)
	}

	code, beginOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/guard-attest/begin", attestedAccess, map[string]any{"launcherVersion": "0.13.4"})
	if code != http.StatusOK {
		t.Fatalf("guard begin status=%d body=%#v", code, beginOut)
	}
	begin := deviceTrustData0121(t, beginOut)
	challengeID := begin["challengeId"].(string)
	challenge := begin["challenge"].(string)
	expiresAt := begin["expiresAt"].(string)
	attestation := makeGuardAttestation0134(t, challengeID, challenge)
	payload := guardDeviceSigningPayload0134(challenge, claims, device, "0.13.4", attestation, expiresAt)

	completeBody := map[string]any{
		"challengeId": challengeID, "challenge": challenge, "challengeExpiresAt": expiresAt,
		"launcherVersion": "0.13.4", "attestation": attestation,
		"signature": signP256P1363Test0123(t, priv, payload),
	}
	code, completeOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/"+deviceID+"/guard-attest/complete", attestedAccess, completeBody)
	if code != http.StatusOK {
		t.Fatalf("guard complete status=%d body=%#v", code, completeOut)
	}
	complete := deviceTrustData0121(t, completeOut)
	ticket, _ := complete["launchTicket"].(string)
	if ticket == "" || complete["verified"] != true || complete["oneTime"] != true {
		t.Fatalf("incomplete guard verification result: %#v", complete)
	}

	code, mcOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/minecraft/session", attestedAccess, map[string]any{"clientToken": "guard-client", "guardAttestationTicket": ticket})
	if code != http.StatusCreated {
		t.Fatalf("minecraft session with guard ticket status=%d body=%#v", code, mcOut)
	}
	code, replayOut := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/minecraft/session", attestedAccess, map[string]any{"clientToken": "guard-client-2", "guardAttestationTicket": ticket})
	if code != http.StatusPreconditionFailed {
		t.Fatalf("replayed Guard ticket accepted status=%d body=%#v", code, replayOut)
	}
}

func TestGuardAttestationRejectsReleaseHashOutsideAllowlist0134(t *testing.T) {
	policy := guardReleasePolicy0134{GuardSHA256: []string{strings.Repeat("1", 64)}, LauncherSHA256: []string{testLauncherHash0134}, RequireAuthenticode: true}
	a := makeGuardAttestation0134(t, "challenge-id", "challenge-secret")
	if err := validateGuardAttestation0134(a, "challenge-id", "challenge-secret", policy, "windows", time.Now().UTC(), time.Now().UTC().Add(-time.Second)); err == nil {
		t.Fatal("non-allowlisted NeverGuard image hash was accepted")
	}
}

func makeLinuxGuardAttestation0137(t *testing.T, challengeID, challenge string) guardRemoteAttestation0134 {
	t.Helper()
	process := func(pid uint32, imageHash, moduleHash string, pdeath bool) guardProcessIntegrityEvidence0134 {
		return guardProcessIntegrityEvidence0134{
			PID: pid, ImagePath: "/opt/neverlauncher/binary", ImageSHA256: imageHash,
			ImageSize: 2048, ImageModifiedUnixMS: 2000, ProcessCreatedFiletime: 12345,
			Authenticode: guardAuthenticodeEvidence0134{Trusted: false, Status: "not-applicable-linux"},
			Mitigations:  guardProcessMitigationEvidence0134{QueryFailures: []string{}},
			Modules:      guardModuleSetEvidence0134{ModuleCount: 3, ModuleSetSHA256: moduleHash, NonSystemModuleNames: []string{}},
			Linux:        &guardLinuxProcessSecurityEvidence0137{UID: 1000, GID: 1000, NoNewPrivs: true, SeccompMode: 2, DumpableDisabled: true, ParentDeathSignal: pdeath},
		}
	}
	now := uint64(time.Now().UTC().Unix())
	evidence := guardIntegrityEvidence0134{
		Schema: guardLinuxIntegritySchema0137, EvidenceVersion: 1, EvidenceID: strings.Repeat("b", 32), CollectedAtUnix: now,
		Boundary:     guardBoundaryEvidence0134{ExpectedParentPID: 200, ObservedParentPID: 200, ParentMatches: true},
		Guard:        process(201, testGuardHash0134, strings.Repeat("6", 64), true),
		Launcher:     process(200, testLauncherHash0134, strings.Repeat("7", 64), false),
		SessionProof: strings.Repeat("8", 64),
	}
	digest, err := recomputeGuardEvidenceSHA2560134(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.EvidenceSHA256 = digest
	a := guardRemoteAttestation0134{
		Schema: guardLinuxAttestationSchema0137, AttestationVersion: 1, ChallengeID: challengeID,
		ChallengeSHA256: deviceChallengeHash0121(challenge), CollectedAtUnix: now, Evidence: evidence,
		ProcessPolicy: guardProcessPolicyReport0134{
			Schema: guardLinuxProcessPolicySchema0137, PolicyVersion: 1, PID: 201, Enforced: true,
			Linux: &guardLinuxProcessPolicyDetails0137{NoNewPrivs: true, DumpableDisabled: true, CoreDumpsDisabled: true, PtraceRestricted: true, ParentDeathSignal: true, PrivateUmask: true},
		},
		SessionProof: strings.Repeat("9", 64),
	}
	a.AttestationSHA256 = recomputeGuardAttestationSHA2560134(a)
	return a
}

func TestLinuxGuardAttestationValidation0137(t *testing.T) {
	policy := guardReleasePolicy0134{GuardSHA256: []string{testGuardHash0134}, LauncherSHA256: []string{testLauncherHash0134}, RequireAuthenticode: true}
	a := makeLinuxGuardAttestation0137(t, "linux-challenge", "linux-secret")
	if err := validateGuardAttestation0134(a, "linux-challenge", "linux-secret", policy, "Linux x86_64", time.Now().UTC(), time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatalf("valid Linux Guard Attestation rejected: %v", err)
	}
	a.ProcessPolicy.Linux.NoNewPrivs = false
	a.AttestationSHA256 = recomputeGuardAttestationSHA2560134(a)
	if err := validateGuardAttestation0134(a, "linux-challenge", "linux-secret", policy, "linux", time.Now().UTC(), time.Now().UTC().Add(-time.Second)); err == nil {
		t.Fatal("Linux Guard Attestation without no_new_privs was accepted")
	}
}

func makeMacOSGuardAttestation0138(t *testing.T, challengeID, challenge string) guardRemoteAttestation0134 {
	t.Helper()
	process := func(pid uint32, imageHash, moduleHash string) guardProcessIntegrityEvidence0134 {
		return guardProcessIntegrityEvidence0134{
			PID: pid, ImagePath: "/Applications/NeverLauncher.app/Contents/MacOS/binary", ImageSHA256: imageHash,
			ImageSize: 4096, ImageModifiedUnixMS: 3000, ProcessCreatedFiletime: 987654,
			Authenticode: guardAuthenticodeEvidence0134{Trusted: true, Status: "macos-codesign-valid"},
			Mitigations:  guardProcessMitigationEvidence0134{QueryFailures: []string{}},
			Modules:      guardModuleSetEvidence0134{ModuleCount: 1, ModuleSetSHA256: moduleHash, NonSystemModuleNames: []string{}},
			MacOS: &guardMacOSProcessSecurityEvidence0138{
				UID: 501, GID: 20, ProcessGroupID: pid, CodeSignatureValid: true, HardenedRuntime: true, LibraryValidation: true,
			},
		}
	}
	now := uint64(time.Now().UTC().Unix())
	evidence := guardIntegrityEvidence0134{
		Schema: guardMacOSIntegritySchema0138, EvidenceVersion: 1, EvidenceID: strings.Repeat("c", 32), CollectedAtUnix: now,
		Boundary:     guardBoundaryEvidence0134{ExpectedParentPID: 300, ObservedParentPID: 300, ParentMatches: true},
		Guard:        process(301, testGuardHash0134, strings.Repeat("a", 64)),
		Launcher:     process(300, testLauncherHash0134, strings.Repeat("b", 64)),
		SessionProof: strings.Repeat("d", 64),
	}
	digest, err := recomputeGuardEvidenceSHA2560134(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.EvidenceSHA256 = digest
	a := guardRemoteAttestation0134{
		Schema: guardMacOSAttestationSchema0138, AttestationVersion: 1, ChallengeID: challengeID,
		ChallengeSHA256: deviceChallengeHash0121(challenge), CollectedAtUnix: now, Evidence: evidence,
		ProcessPolicy: guardProcessPolicyReport0134{
			Schema: guardMacOSProcessPolicySchema0138, PolicyVersion: 1, PID: 301, Enforced: true,
			MacOS: &guardMacOSProcessPolicyDetails0138{
				CoreDumpsDisabled: true, DebuggerAttachDenied: true, CodeSignatureValid: true, HardenedRuntime: true,
				LibraryValidation: true, DyldEnvironmentSanitized: true, ParentExitWatch: true, PrivateUmask: true,
			},
		},
		SessionProof: strings.Repeat("e", 64),
	}
	a.AttestationSHA256 = recomputeGuardAttestationSHA2560134(a)
	return a
}

func TestMacOSGuardAttestationValidation0138(t *testing.T) {
	policy := guardReleasePolicy0134{GuardSHA256: []string{testGuardHash0134}, LauncherSHA256: []string{testLauncherHash0134}, RequireAuthenticode: false}
	a := makeMacOSGuardAttestation0138(t, "macos-challenge", "macos-secret")
	if err := validateGuardAttestation0134(a, "macos-challenge", "macos-secret", policy, "macOS-arm64", time.Now().UTC(), time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatalf("valid macOS Guard Attestation rejected: %v", err)
	}
	a.ProcessPolicy.MacOS.LibraryValidation = false
	a.AttestationSHA256 = recomputeGuardAttestationSHA2560134(a)
	if err := validateGuardAttestation0134(a, "macos-challenge", "macos-secret", policy, "darwin", time.Now().UTC(), time.Now().UTC().Add(-time.Second)); err == nil {
		t.Fatal("macOS Guard Attestation without library validation was accepted")
	}
}

func TestGuardReleasePolicyV2ExactPlatformPair0140(t *testing.T) {
	guardA := strings.Repeat("a", 64)
	launcherA := strings.Repeat("b", 64)
	guardB := strings.Repeat("c", 64)
	launcherB := strings.Repeat("d", 64)
	cfg := config.Config{Environment: "test", GuardReleaseAllowlistJSON: `{
		"schemaVersion":"2.0",
		"releases":{"0.14.0":{"protocolVersion":4,"platforms":{
			"windows":{"signingMode":"unsigned-development","artifacts":[
				{"guardSha256":"` + guardA + `","launcherSha256":"` + launcherA + `","requireAuthenticode":false},
				{"guardSha256":"` + guardB + `","launcherSha256":"` + launcherB + `","requireAuthenticode":false}
			]},
			"linux":{"signingMode":"integrity-only","artifacts":[{"guardSha256":"` + guardA + `","launcherSha256":"` + launcherA + `"}]},
			"macos":{"signingMode":"adhoc-development","artifacts":[{"guardSha256":"` + guardB + `","launcherSha256":"` + launcherB + `"}]}
		}}}
	}`}
	s := Server{Version: "0.14.0", Config: cfg}
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		t.Fatal(err)
	}
	policy := policies["0.14.0"]
	allowed, _, err := policy.allowsArtifactPair0140("windows-amd64", guardA, launcherA)
	if err != nil || !allowed {
		t.Fatalf("exact Windows artifact pair was rejected: allowed=%v err=%v", allowed, err)
	}
	allowed, _, err = policy.allowsArtifactPair0140("windows-amd64", guardA, launcherB)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("cross-product artifact pair must not be accepted")
	}
	allowed, _, err = policy.allowsArtifactPair0140("macos-arm64", guardA, launcherA)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("Windows/Linux artifact pair must not cross the macOS platform namespace")
	}
}

func TestGuardReleasePolicyLegacyRejectedFrom0140(t *testing.T) {
	s := Server{Version: "0.14.0", Config: config.Config{Environment: "test", GuardReleaseAllowlistJSON: `{"0.14.0":{"guardSha256":["` + strings.Repeat("a", 64) + `"],"launcherSha256":["` + strings.Repeat("b", 64) + `"]}}`}}
	if _, err := s.guardReleasePolicies0134(); err == nil {
		t.Fatal("0.14.0 Backend accepted legacy Guard release policy")
	}
}

func TestGuardReleasePolicyProductionSigningRequirements0140(t *testing.T) {
	guardHash := strings.Repeat("a", 64)
	launcherHash := strings.Repeat("b", 64)
	policy := `{"schemaVersion":"2.0","releases":{"0.14.0":{"protocolVersion":4,"platforms":{"windows":{"signingMode":"unsigned-development","artifacts":[{"guardSha256":"` + guardHash + `","launcherSha256":"` + launcherHash + `","requireAuthenticode":false}]}}}}}`
	s := Server{Version: "0.14.0", Config: config.Config{Environment: "production", GuardReleaseAllowlistJSON: policy}}
	if _, err := s.guardReleasePolicies0134(); err == nil {
		t.Fatal("production Backend accepted unsigned Windows NeverGuard policy")
	}
}
