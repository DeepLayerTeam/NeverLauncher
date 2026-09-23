package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const (
	guardAttestationChallengeTTL0134 = 90 * time.Second
	guardLaunchTicketTTL0134         = 90 * time.Second
	guardAttestationClockSkew0134    = 15 * time.Second
	guardAttestationPurpose0134      = "guard-attest-v1"
	guardLaunchTicketPurpose0134     = "guard-launch-v1"
	guardAttestationSchema0134       = "neverguard/windows-guard-attestation/v1"
	guardIntegritySchema0134         = "neverguard/windows-integrity-evidence/v1"
	guardProcessPolicySchema0134     = "neverguard/windows-runtime-process-policy/v1"
)

type guardReleasePolicy0134 struct {
	GuardSHA256         []string `json:"guardSha256"`
	LauncherSHA256      []string `json:"launcherSha256"`
	RequireAuthenticode bool     `json:"requireAuthenticode"`
}

type guardAttestationBeginRequest0134 struct {
	LauncherVersion string `json:"launcherVersion"`
}

type guardAuthenticodeEvidence0134 struct {
	Trusted bool   `json:"trusted"`
	Status  string `json:"status"`
}

type guardProcessMitigationEvidence0134 struct {
	DEP                   *uint32  `json:"dep"`
	ASLR                  *uint32  `json:"aslr"`
	DynamicCode           *uint32  `json:"dynamicCode"`
	ExtensionPointDisable *uint32  `json:"extensionPointDisable"`
	ControlFlowGuard      *uint32  `json:"controlFlowGuard"`
	BinarySignature       *uint32  `json:"binarySignature"`
	ImageLoad             *uint32  `json:"imageLoad"`
	ChildProcess          *uint32  `json:"childProcess"`
	UserShadowStack       *uint32  `json:"userShadowStack"`
	SEHOP                 *uint32  `json:"sehop"`
	QueryFailures         []string `json:"queryFailures"`
}

type guardModuleSetEvidence0134 struct {
	ModuleCount          uint32   `json:"moduleCount"`
	ModuleSetSHA256      string   `json:"moduleSetSha256"`
	NonSystemModuleNames []string `json:"nonSystemModuleNames"`
}

type guardProcessIntegrityEvidence0134 struct {
	PID                    uint32                             `json:"pid"`
	ImagePath              string                             `json:"imagePath"`
	ImageSHA256            string                             `json:"imageSha256"`
	ImageSize              uint64                             `json:"imageSize"`
	ImageModifiedUnixMS    uint64                             `json:"imageModifiedUnixMs"`
	ProcessCreatedFiletime uint64                             `json:"processCreatedFiletime"`
	Authenticode           guardAuthenticodeEvidence0134      `json:"authenticode"`
	Mitigations            guardProcessMitigationEvidence0134 `json:"mitigations"`
	Modules                guardModuleSetEvidence0134         `json:"modules"`
}

type guardBoundaryEvidence0134 struct {
	ExpectedParentPID uint32 `json:"expectedParentPid"`
	ObservedParentPID uint32 `json:"observedParentPid"`
	ParentMatches     bool   `json:"parentMatches"`
}

type guardIntegrityEvidence0134 struct {
	Schema          string                            `json:"schema"`
	EvidenceVersion uint32                            `json:"evidenceVersion"`
	EvidenceID      string                            `json:"evidenceId"`
	CollectedAtUnix uint64                            `json:"collectedAtUnix"`
	Boundary        guardBoundaryEvidence0134         `json:"boundary"`
	Guard           guardProcessIntegrityEvidence0134 `json:"guard"`
	Launcher        guardProcessIntegrityEvidence0134 `json:"launcher"`
	EvidenceSHA256  string                            `json:"evidenceSha256"`
	SessionProof    string                            `json:"sessionProof"`
}

type guardProcessPolicyReport0134 struct {
	Schema                         string `json:"schema"`
	PolicyVersion                  uint32 `json:"policyVersion"`
	PID                            uint32 `json:"pid"`
	Enforced                       bool   `json:"enforced"`
	DynamicCodeProhibited          bool   `json:"dynamicCodeProhibited"`
	ExtensionPointsDisabled        bool   `json:"extensionPointsDisabled"`
	StrictHandleChecks             bool   `json:"strictHandleChecks"`
	RemoteImagesBlocked            bool   `json:"remoteImagesBlocked"`
	LowMandatoryLabelImagesBlocked bool   `json:"lowMandatoryLabelImagesBlocked"`
	PreferSystem32Images           bool   `json:"preferSystem32Images"`
	ChildProcessCreationBlocked    bool   `json:"childProcessCreationBlocked"`
}

type guardRemoteAttestation0134 struct {
	Schema             string                       `json:"schema"`
	AttestationVersion uint32                       `json:"attestationVersion"`
	ChallengeID        string                       `json:"challengeId"`
	ChallengeSHA256    string                       `json:"challengeSha256"`
	CollectedAtUnix    uint64                       `json:"collectedAtUnix"`
	Evidence           guardIntegrityEvidence0134   `json:"evidence"`
	ProcessPolicy      guardProcessPolicyReport0134 `json:"processPolicy"`
	AttestationSHA256  string                       `json:"attestationSha256"`
	SessionProof       string                       `json:"sessionProof"`
}

type guardAttestationCompleteRequest0134 struct {
	ChallengeID        string                     `json:"challengeId"`
	Challenge          string                     `json:"challenge"`
	ChallengeExpiresAt string                     `json:"challengeExpiresAt"`
	LauncherVersion    string                     `json:"launcherVersion"`
	Attestation        guardRemoteAttestation0134 `json:"attestation"`
	Signature          string                     `json:"signature"`
}

type guardIntegrityCore0134 struct {
	Schema          string                            `json:"schema"`
	EvidenceVersion uint32                            `json:"evidenceVersion"`
	EvidenceID      string                            `json:"evidenceId"`
	CollectedAtUnix uint64                            `json:"collectedAtUnix"`
	Boundary        guardBoundaryEvidence0134         `json:"boundary"`
	Guard           guardProcessIntegrityEvidence0134 `json:"guard"`
	Launcher        guardProcessIntegrityEvidence0134 `json:"launcher"`
}

func isSHA256Hex0134(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func normalizeHashList0134(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !isSHA256Hex0134(value) {
			return nil, fmt.Errorf("invalid SHA-256 %q", raw)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, errors.New("hash allowlist is empty")
	}
	return out, nil
}

func (s Server) guardAttestationRequired0134() bool {
	return config.IsProductionEnvironment(s.Config.Environment) || strings.TrimSpace(s.Config.GuardReleaseAllowlistJSON) != ""
}

func isWindowsDevicePlatform0134(platform string) bool {
	platform = strings.ToLower(strings.TrimSpace(platform))
	return platform == "windows" || platform == "win32" || platform == "win64" ||
		strings.HasPrefix(platform, "windows-") || strings.HasPrefix(platform, "win32-") || strings.HasPrefix(platform, "win64-")
}

func (s Server) guardAttestationRequiredForSession0134(claims authClaims) (bool, error) {
	if !s.guardAttestationRequired0134() {
		return false, nil
	}
	deviceID := strings.TrimSpace(claims.TrustedDeviceID)
	if deviceID == "" {
		return false, nil
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil {
		return false, err
	}
	return isWindowsDevicePlatform0134(device.Platform), nil
}

func (s Server) guardReleasePolicies0134() (map[string]guardReleasePolicy0134, error) {
	raw := strings.TrimSpace(s.Config.GuardReleaseAllowlistJSON)
	if raw == "" {
		return nil, errors.New("NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON is not configured")
	}
	policies := map[string]guardReleasePolicy0134{}
	if err := json.Unmarshal([]byte(raw), &policies); err != nil {
		return nil, fmt.Errorf("invalid guard release allowlist: %w", err)
	}
	if len(policies) == 0 {
		return nil, errors.New("guard release allowlist is empty")
	}
	normalized := make(map[string]guardReleasePolicy0134, len(policies))
	for version, policy := range policies {
		version = strings.TrimSpace(version)
		if version == "" || len(version) > 64 {
			return nil, errors.New("guard release allowlist contains invalid version")
		}
		guard, err := normalizeHashList0134(policy.GuardSHA256)
		if err != nil {
			return nil, fmt.Errorf("guard release %s: %w", version, err)
		}
		launcher, err := normalizeHashList0134(policy.LauncherSHA256)
		if err != nil {
			return nil, fmt.Errorf("launcher release %s: %w", version, err)
		}
		policy.GuardSHA256 = guard
		policy.LauncherSHA256 = launcher
		normalized[version] = policy
	}
	return normalized, nil
}

func containsHash0134(items []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, item := range items {
		if hmac.Equal([]byte(item), []byte(value)) {
			return true
		}
	}
	return false
}

func recomputeGuardEvidenceSHA2560134(e guardIntegrityEvidence0134) (string, error) {
	if e.Guard.Mitigations.QueryFailures == nil || e.Launcher.Mitigations.QueryFailures == nil ||
		e.Guard.Modules.NonSystemModuleNames == nil || e.Launcher.Modules.NonSystemModuleNames == nil {
		return "", errors.New("integrity evidence contains null vector fields")
	}
	raw, err := json.Marshal(guardIntegrityCore0134{
		Schema: e.Schema, EvidenceVersion: e.EvidenceVersion, EvidenceID: e.EvidenceID,
		CollectedAtUnix: e.CollectedAtUnix, Boundary: e.Boundary, Guard: e.Guard, Launcher: e.Launcher,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func guardAttestationCorePayload0134(a guardRemoteAttestation0134) string {
	return "NeverLauncher Guard Attestation Core v1\n" +
		"challenge-id=" + a.ChallengeID + "\n" +
		"challenge-sha256=" + a.ChallengeSHA256 + "\n" +
		"evidence-id=" + a.Evidence.EvidenceID + "\n" +
		"evidence-sha256=" + a.Evidence.EvidenceSHA256 + "\n" +
		"guard-sha256=" + a.Evidence.Guard.ImageSHA256 + "\n" +
		"launcher-sha256=" + a.Evidence.Launcher.ImageSHA256 + "\n" +
		"guard-module-set-sha256=" + a.Evidence.Guard.Modules.ModuleSetSHA256 + "\n" +
		"launcher-module-set-sha256=" + a.Evidence.Launcher.Modules.ModuleSetSHA256 + "\n" +
		"guard-authenticode-trusted=" + strconv.FormatBool(a.Evidence.Guard.Authenticode.Trusted) + "\n" +
		"launcher-authenticode-trusted=" + strconv.FormatBool(a.Evidence.Launcher.Authenticode.Trusted) + "\n" +
		"process-policy-version=" + strconv.FormatUint(uint64(a.ProcessPolicy.PolicyVersion), 10) + "\n" +
		"process-policy-enforced=" + strconv.FormatBool(a.ProcessPolicy.Enforced) + "\n" +
		"dynamic-code-prohibited=" + strconv.FormatBool(a.ProcessPolicy.DynamicCodeProhibited) + "\n" +
		"extension-points-disabled=" + strconv.FormatBool(a.ProcessPolicy.ExtensionPointsDisabled) + "\n" +
		"strict-handle-checks=" + strconv.FormatBool(a.ProcessPolicy.StrictHandleChecks) + "\n" +
		"remote-images-blocked=" + strconv.FormatBool(a.ProcessPolicy.RemoteImagesBlocked) + "\n" +
		"low-mandatory-label-images-blocked=" + strconv.FormatBool(a.ProcessPolicy.LowMandatoryLabelImagesBlocked) + "\n" +
		"prefer-system32-images=" + strconv.FormatBool(a.ProcessPolicy.PreferSystem32Images) + "\n" +
		"child-process-creation-blocked=" + strconv.FormatBool(a.ProcessPolicy.ChildProcessCreationBlocked) + "\n" +
		"collected-at=" + strconv.FormatUint(a.CollectedAtUnix, 10) + "\n"
}

func recomputeGuardAttestationSHA2560134(a guardRemoteAttestation0134) string {
	sum := sha256.Sum256([]byte(guardAttestationCorePayload0134(a)))
	return hex.EncodeToString(sum[:])
}

func guardDeviceSigningPayload0134(challenge string, claims authClaims, device model.TrustedDevice, launcherVersion string, a guardRemoteAttestation0134, challengeExpiresAt string) string {
	return "NeverLauncher Guard Attestation Device Binding v1\n" +
		"purpose=guard-attest\n" +
		"challenge=" + strings.TrimSpace(challenge) + "\n" +
		"challenge-id=" + strings.TrimSpace(a.ChallengeID) + "\n" +
		"user=" + strings.TrimSpace(claims.Sub) + "\n" +
		"device=" + strings.TrimSpace(device.ID) + "\n" +
		"session=" + strings.TrimSpace(claims.SessionID) + "\n" +
		"binding-epoch=" + strconv.FormatInt(claims.BindingEpoch, 10) + "\n" +
		"launcher-version=" + strings.TrimSpace(launcherVersion) + "\n" +
		"fingerprint=" + strings.TrimSpace(device.KeyFingerprint) + "\n" +
		"attestation-sha256=" + strings.TrimSpace(a.AttestationSHA256) + "\n" +
		"evidence-sha256=" + strings.TrimSpace(a.Evidence.EvidenceSHA256) + "\n" +
		"guard-sha256=" + strings.TrimSpace(a.Evidence.Guard.ImageSHA256) + "\n" +
		"launcher-sha256=" + strings.TrimSpace(a.Evidence.Launcher.ImageSHA256) + "\n" +
		"challenge-expires-at=" + strings.TrimSpace(challengeExpiresAt) + "\n"
}

func validateGuardAttestation0134(a guardRemoteAttestation0134, challengeID, challenge string, policy guardReleasePolicy0134, now time.Time, challengeCreatedAt time.Time) error {
	if a.Schema != guardAttestationSchema0134 || a.AttestationVersion != 1 || a.ChallengeID != strings.TrimSpace(challengeID) {
		return errors.New("Guard Attestation schema/version/challengeId mismatch")
	}
	expectedChallenge := deviceChallengeHash0121(challenge)
	if !hmac.Equal([]byte(expectedChallenge), []byte(strings.ToLower(strings.TrimSpace(a.ChallengeSHA256)))) {
		return errors.New("Guard Attestation challenge hash mismatch")
	}
	if !isSHA256Hex0134(a.AttestationSHA256) || !isSHA256Hex0134(a.SessionProof) ||
		!isSHA256Hex0134(a.Evidence.EvidenceSHA256) || !isSHA256Hex0134(a.Evidence.SessionProof) {
		return errors.New("Guard Attestation digest/proof malformed")
	}
	if a.Evidence.Schema != guardIntegritySchema0134 || a.Evidence.EvidenceVersion != 1 ||
		len(a.Evidence.EvidenceID) != 32 || a.Evidence.EvidenceID != strings.ToLower(a.Evidence.EvidenceID) {
		return errors.New("Integrity Evidence schema/version/id mismatch")
	}
	if _, err := hex.DecodeString(a.Evidence.EvidenceID); err != nil {
		return errors.New("Integrity Evidence id malformed")
	}
	if a.CollectedAtUnix != a.Evidence.CollectedAtUnix {
		return errors.New("Guard Attestation collection timestamp mismatch")
	}
	collected := time.Unix(int64(a.CollectedAtUnix), 0).UTC()
	if collected.Before(challengeCreatedAt.Add(-guardAttestationClockSkew0134)) || collected.After(now.Add(guardAttestationClockSkew0134)) {
		return errors.New("Guard Attestation collection timestamp outside challenge freshness window")
	}
	if !a.Evidence.Boundary.ParentMatches || a.Evidence.Boundary.ExpectedParentPID == 0 ||
		a.Evidence.Boundary.ExpectedParentPID != a.Evidence.Boundary.ObservedParentPID ||
		a.Evidence.Launcher.PID != a.Evidence.Boundary.ExpectedParentPID || a.Evidence.Guard.PID == 0 ||
		a.Evidence.Guard.PID == a.Evidence.Launcher.PID {
		return errors.New("Guard Attestation process boundary mismatch")
	}
	for label, value := range map[string]string{
		"guard image":      a.Evidence.Guard.ImageSHA256,
		"launcher image":   a.Evidence.Launcher.ImageSHA256,
		"guard modules":    a.Evidence.Guard.Modules.ModuleSetSHA256,
		"launcher modules": a.Evidence.Launcher.Modules.ModuleSetSHA256,
	} {
		if !isSHA256Hex0134(value) {
			return fmt.Errorf("%s SHA-256 malformed", label)
		}
	}
	if a.Evidence.Guard.Modules.ModuleCount == 0 || a.Evidence.Launcher.Modules.ModuleCount == 0 {
		return errors.New("Guard Attestation module evidence is empty")
	}
	evidenceDigest, err := recomputeGuardEvidenceSHA2560134(a.Evidence)
	if err != nil || !hmac.Equal([]byte(evidenceDigest), []byte(a.Evidence.EvidenceSHA256)) {
		return errors.New("Integrity Evidence digest verification failed")
	}
	if !hmac.Equal([]byte(recomputeGuardAttestationSHA2560134(a)), []byte(a.AttestationSHA256)) {
		return errors.New("Guard Attestation digest verification failed")
	}
	p := a.ProcessPolicy
	if p.Schema != guardProcessPolicySchema0134 || p.PolicyVersion != 1 || p.PID != a.Evidence.Guard.PID ||
		!p.Enforced || !p.DynamicCodeProhibited || !p.ExtensionPointsDisabled || !p.StrictHandleChecks ||
		!p.RemoteImagesBlocked || !p.LowMandatoryLabelImagesBlocked || !p.PreferSystem32Images || !p.ChildProcessCreationBlocked {
		return errors.New("NeverGuard process policy verification failed")
	}
	if !containsHash0134(policy.GuardSHA256, a.Evidence.Guard.ImageSHA256) ||
		!containsHash0134(policy.LauncherSHA256, a.Evidence.Launcher.ImageSHA256) {
		return errors.New("NeverGuard/Desktop release hash is not allowlisted")
	}
	if policy.RequireAuthenticode && (!a.Evidence.Guard.Authenticode.Trusted || !a.Evidence.Launcher.Authenticode.Trusted) {
		return errors.New("release policy requires trusted Authenticode for NeverGuard and Desktop")
	}
	return nil
}

func (s Server) authGuardAttestationBegin0134(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	if _, err := sessionBoundToDevice0124(s, claims, deviceID); err != nil {
		writeError(w, http.StatusConflict, "текущая сессия не привязана к trusted device")
		return
	}
	var req guardAttestationBeginRequest0134
	if err := decodeDeviceJSON0121(w, r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.LauncherVersion = strings.TrimSpace(req.LauncherVersion)
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Guard Attestation release policy не настроена")
		return
	}
	policy, ok := policies[req.LauncherVersion]
	if !ok {
		writeError(w, http.StatusPreconditionFailed, "эта версия Desktop отсутствует в Guard release allowlist")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	if !isWindowsDevicePlatform0134(device.Platform) {
		writeError(w, http.StatusPreconditionFailed, "Guard Attestation 0.13.4 применяется только к Windows trusted device")
		return
	}
	if err := attestationEligibleDevice0124(device); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	state, _ := effectiveDeviceAttestation0124(device, time.Now().UTC())
	if state != "verified" {
		writeError(w, http.StatusPreconditionFailed, "Guard Attestation требует свежую challenge-response device attestation")
		return
	}

	challengeID, err := randomToken("nga")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать Guard Attestation challenge")
		return
	}
	challenge, err := randomToken("ngc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать Guard Attestation challenge")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(guardAttestationChallengeTTL0134)
	entry := model.DeviceChallenge{
		ID: challengeID, UserID: claims.Sub, DeviceID: device.ID, Purpose: guardAttestationPurpose0134,
		ChallengeHash: deviceChallengeHash0121(challenge),
		Metadata: map[string]any{
			"sessionId":       claims.SessionID,
			"bindingEpoch":    strconv.FormatInt(claims.BindingEpoch, 10),
			"launcherVersion": req.LauncherVersion,
			"keyFingerprint":  device.KeyFingerprint,
		},
		CreatedAt: now, ExpiresAt: expires,
	}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить Guard Attestation challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"challengeId":         challengeID,
		"challenge":           challenge,
		"expiresAt":           expires,
		"launcherVersion":     req.LauncherVersion,
		"attestationSchema":   guardAttestationSchema0134,
		"evidenceSchema":      guardIntegritySchema0134,
		"processPolicySchema": guardProcessPolicySchema0134,
		"requireAuthenticode": policy.RequireAuthenticode,
		"oneTime":             true,
	}})
}

func (s Server) authGuardAttestationComplete0134(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	if _, err := sessionBoundToDevice0124(s, claims, deviceID); err != nil {
		writeError(w, http.StatusConflict, "текущая сессия не привязана к trusted device")
		return
	}
	var req guardAttestationCompleteRequest0134
	if err := decodeDeviceJSON0121(w, r, &req, 256<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный Guard Attestation JSON")
		return
	}
	req.LauncherVersion = strings.TrimSpace(req.LauncherVersion)
	req.ChallengeExpiresAt = strings.TrimSpace(req.ChallengeExpiresAt)
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Guard Attestation release policy не настроена")
		return
	}
	policy, ok := policies[req.LauncherVersion]
	if !ok {
		writeError(w, http.StatusPreconditionFailed, "эта версия Desktop отсутствует в Guard release allowlist")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	if !isWindowsDevicePlatform0134(device.Platform) {
		writeError(w, http.StatusPreconditionFailed, "Guard Attestation 0.13.4 применяется только к Windows trusted device")
		return
	}
	if err := attestationEligibleDevice0124(device); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	state, _ := effectiveDeviceAttestation0124(device, time.Now().UTC())
	if state != "verified" {
		writeError(w, http.StatusPreconditionFailed, "device attestation freshness истекла")
		return
	}
	if req.Attestation.ChallengeID != strings.TrimSpace(req.ChallengeID) {
		writeError(w, http.StatusBadRequest, "challengeId не совпадает с Guard Attestation")
		return
	}
	pub, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || pub.fingerprint != device.KeyFingerprint {
		writeError(w, http.StatusInternalServerError, "device public key повреждён")
		return
	}
	if err := validateGuardAttestation0134(req.Attestation, req.ChallengeID, req.Challenge, policy, time.Now().UTC(), time.Now().UTC().Add(-guardAttestationChallengeTTL0134)); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	payload := guardDeviceSigningPayload0134(req.Challenge, claims, device, req.LauncherVersion, req.Attestation, req.ChallengeExpiresAt)
	if err := verifyDeviceSignature0123(pub, payload, req.Signature); err != nil {
		writeError(w, http.StatusUnauthorized, "Guard Attestation device signature недействительна")
		return
	}

	now := time.Now().UTC()
	challenge, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, deviceID, guardAttestationPurpose0134, deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Guard Attestation challenge недействителен, истёк или уже использован")
		return
	}
	if metadataString0121(challenge.Metadata, "sessionId") != claims.SessionID ||
		metadataString0121(challenge.Metadata, "bindingEpoch") != strconv.FormatInt(claims.BindingEpoch, 10) ||
		metadataString0121(challenge.Metadata, "launcherVersion") != req.LauncherVersion ||
		metadataString0121(challenge.Metadata, "keyFingerprint") != device.KeyFingerprint ||
		req.ChallengeExpiresAt != challenge.ExpiresAt.UTC().Format(time.RFC3339Nano) {
		writeError(w, http.StatusUnauthorized, "Guard Attestation challenge больше не соответствует session/device/release binding")
		return
	}
	if err := validateGuardAttestation0134(req.Attestation, req.ChallengeID, req.Challenge, policy, now, challenge.CreatedAt.UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	ticketID, err := randomToken("gatid")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить Guard launch ticket")
		return
	}
	ticketSecret, err := randomToken("gat")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить Guard launch ticket")
		return
	}
	ticketExpires := now.Add(guardLaunchTicketTTL0134)
	ticket := model.DeviceChallenge{
		ID: ticketID, UserID: claims.Sub, DeviceID: deviceID, Purpose: guardLaunchTicketPurpose0134,
		ChallengeHash: deviceChallengeHash0121(ticketSecret),
		Metadata: map[string]any{
			"sessionId":         claims.SessionID,
			"bindingEpoch":      strconv.FormatInt(claims.BindingEpoch, 10),
			"launcherVersion":   req.LauncherVersion,
			"attestationSha256": req.Attestation.AttestationSHA256,
			"evidenceSha256":    req.Attestation.Evidence.EvidenceSHA256,
			"guardSha256":       req.Attestation.Evidence.Guard.ImageSHA256,
			"launcherSha256":    req.Attestation.Evidence.Launcher.ImageSHA256,
		},
		CreatedAt: now, ExpiresAt: ticketExpires,
	}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), ticket); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить Guard launch ticket")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("guard-attestation"), Actor: claims.Sub, Action: "neverguard:attestation:verified", Target: deviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"verified":          true,
		"attestationSha256": req.Attestation.AttestationSHA256,
		"evidenceSha256":    req.Attestation.Evidence.EvidenceSHA256,
		"guardSha256":       req.Attestation.Evidence.Guard.ImageSHA256,
		"launcherSha256":    req.Attestation.Evidence.Launcher.ImageSHA256,
		"launchTicket":      ticketID + "." + ticketSecret,
		"expiresAt":         ticketExpires,
		"oneTime":           true,
	}})
}

func (s Server) consumeGuardLaunchTicket0134(r *http.Request, claims authClaims, raw string) (model.DeviceChallenge, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || len(raw) > 512 {
		return model.DeviceChallenge{}, errors.New("Guard launch ticket malformed")
	}
	if strings.TrimSpace(claims.TrustedDeviceID) == "" {
		return model.DeviceChallenge{}, errors.New("current session is not bound to trusted device")
	}
	now := time.Now().UTC()
	ticket, err := s.Repo.ConsumeDeviceChallenge(r.Context(), parts[0], claims.Sub, claims.TrustedDeviceID, guardLaunchTicketPurpose0134, deviceChallengeHash0121(parts[1]), now)
	if err != nil {
		return model.DeviceChallenge{}, errors.New("Guard launch ticket invalid, expired or already used")
	}
	if metadataString0121(ticket.Metadata, "sessionId") != claims.SessionID ||
		metadataString0121(ticket.Metadata, "bindingEpoch") != strconv.FormatInt(claims.BindingEpoch, 10) {
		return model.DeviceChallenge{}, errors.New("Guard launch ticket session/device binding mismatch")
	}
	version := metadataString0121(ticket.Metadata, "launcherVersion")
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		return model.DeviceChallenge{}, errors.New("Guard release policy unavailable")
	}
	policy, ok := policies[version]
	if !ok || !containsHash0134(policy.GuardSHA256, metadataString0121(ticket.Metadata, "guardSha256")) ||
		!containsHash0134(policy.LauncherSHA256, metadataString0121(ticket.Metadata, "launcherSha256")) {
		return model.DeviceChallenge{}, errors.New("Guard launch ticket release policy no longer allows this build")
	}
	return ticket, nil
}
