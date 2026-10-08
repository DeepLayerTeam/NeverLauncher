package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const (
	guardAttestationV2ChallengeTTL01810 = 90 * time.Second
	guardContinuousJoinTTL01810         = 45 * time.Second
	guardAttestationV2Purpose01810      = "guard-attest-v2"
	guardContinuousJoinPurpose01810     = "guard-continuous-join-v2"
	guardAttestationV2Schema01810       = "neverguard/windows-guard-attestation/v2"
	guardContinuousEvidenceSchema01810  = "neverguard/windows-continuous-evidence/v2"
	guardAttestationV2Version01810      = uint32(2)
	guardContinuousEvidenceVersion01810 = uint32(2)
	guardContinuousMaxStaleness01810    = 5 * time.Second
)

type guardContinuousEvidence01810 struct {
	Schema                        string `json:"schema"`
	EvidenceVersion               uint32 `json:"evidenceVersion"`
	ProcessID                     string `json:"processId"`
	RuntimePID                    uint32 `json:"runtimePid"`
	CollectedAtUnixMS             uint64 `json:"collectedAtUnixMs"`
	SensorProtocolVersion         uint32 `json:"sensorProtocolVersion"`
	SensorAuthenticated           bool   `json:"sensorAuthenticated"`
	SensorLoadedBeforeMain        bool   `json:"sensorLoadedBeforeMain"`
	ModuleGuardVersion            uint32 `json:"moduleGuardVersion"`
	ModuleGuardHealthy            bool   `json:"moduleGuardHealthy"`
	ModuleEventCount              uint64 `json:"moduleEventCount"`
	ModuleLastSequence            uint64 `json:"moduleLastSequence"`
	ModuleEventChainSHA256        string `json:"moduleEventChainSha256"`
	ModuleSetSHA256               string `json:"moduleSetSha256"`
	HookEngineHealthy             bool   `json:"hookEngineHealthy"`
	HookSetSHA256                 string `json:"hookSetSha256"`
	MemoryIntegrityHealthy        bool   `json:"memoryIntegrityHealthy"`
	CodeSetSHA256                 string `json:"codeSetSha256"`
	ExecutableMapSHA256           string `json:"executableMapSha256"`
	ThreadProcessIntegrityHealthy bool   `json:"threadProcessIntegrityHealthy"`
	JobBound                      bool   `json:"jobBound"`
	ThreadSetSHA256               string `json:"threadSetSha256"`
	ThreadOriginSetSHA256         string `json:"threadOriginSetSha256"`
	ProcessTreeSHA256             string `json:"processTreeSha256"`
	DebugInstrumentationHealthy   bool   `json:"debugInstrumentationHealthy"`
	DebugStateSHA256              string `json:"debugStateSha256"`
	JVMAwareHealthy               bool   `json:"jvmAwareHealthy"`
	JavaMajor                     uint32 `json:"javaMajor"`
	JVMStateSHA256                string `json:"jvmStateSha256"`
	ContinuousGuardVersion        uint32 `json:"continuousGuardVersion"`
	ContinuousGuardHealthy        bool   `json:"continuousGuardHealthy"`
	SensorHeartbeatCount          uint64 `json:"sensorHeartbeatCount"`
	GuardHeartbeatCount           uint64 `json:"guardHeartbeatCount"`
	CrossCheckCount               uint64 `json:"crossCheckCount"`
	LastSensorSequence            uint64 `json:"lastSensorSequence"`
	LastGuardSequence             uint64 `json:"lastGuardSequence"`
	SensorEventChainSHA256        string `json:"sensorEventChainSha256"`
	LastCrossCheckSHA256          string `json:"lastCrossCheckSha256"`
	LastSensorHeartbeatUnixMS     uint64 `json:"lastSensorHeartbeatUnixMs"`
	LastGuardHeartbeatUnixMS      uint64 `json:"lastGuardHeartbeatUnixMs"`
	EvidenceSHA256                string `json:"evidenceSha256"`
}

type guardRemoteAttestationV201810 struct {
	Schema             string                       `json:"schema"`
	AttestationVersion uint32                       `json:"attestationVersion"`
	ChallengeID        string                       `json:"challengeId"`
	ChallengeSHA256    string                       `json:"challengeSha256"`
	CollectedAtUnixMS  uint64                       `json:"collectedAtUnixMs"`
	BaseAttestation    guardRemoteAttestation0134   `json:"baseAttestation"`
	ContinuousEvidence guardContinuousEvidence01810 `json:"continuousEvidence"`
	AttestationSHA256  string                       `json:"attestationSha256"`
}

type guardAttestationV2CompleteRequest01810 struct {
	ChallengeID        string                        `json:"challengeId"`
	Challenge          string                        `json:"challenge"`
	ChallengeExpiresAt string                        `json:"challengeExpiresAt"`
	LauncherVersion    string                        `json:"launcherVersion"`
	Attestation        guardRemoteAttestationV201810 `json:"attestation"`
	Signature          string                        `json:"signature"`
}

func guardContinuousEvidenceCore01810(e guardContinuousEvidence01810) string {
	return "NeverLauncher Windows Continuous Evidence v2\n" +
		"process-id=" + e.ProcessID + "\n" +
		"runtime-pid=" + strconv.FormatUint(uint64(e.RuntimePID), 10) + "\n" +
		"collected-at-ms=" + strconv.FormatUint(e.CollectedAtUnixMS, 10) + "\n" +
		"sensor-protocol-version=" + strconv.FormatUint(uint64(e.SensorProtocolVersion), 10) + "\n" +
		"sensor-authenticated=" + strconv.FormatBool(e.SensorAuthenticated) + "\n" +
		"sensor-loaded-before-main=" + strconv.FormatBool(e.SensorLoadedBeforeMain) + "\n" +
		"module-guard-version=" + strconv.FormatUint(uint64(e.ModuleGuardVersion), 10) + "\n" +
		"module-guard-healthy=" + strconv.FormatBool(e.ModuleGuardHealthy) + "\n" +
		"module-event-count=" + strconv.FormatUint(e.ModuleEventCount, 10) + "\n" +
		"module-last-sequence=" + strconv.FormatUint(e.ModuleLastSequence, 10) + "\n" +
		"module-event-chain-sha256=" + e.ModuleEventChainSHA256 + "\n" +
		"module-set-sha256=" + e.ModuleSetSHA256 + "\n" +
		"hook-engine-healthy=" + strconv.FormatBool(e.HookEngineHealthy) + "\n" +
		"hook-set-sha256=" + e.HookSetSHA256 + "\n" +
		"memory-integrity-healthy=" + strconv.FormatBool(e.MemoryIntegrityHealthy) + "\n" +
		"code-set-sha256=" + e.CodeSetSHA256 + "\n" +
		"executable-map-sha256=" + e.ExecutableMapSHA256 + "\n" +
		"thread-process-integrity-healthy=" + strconv.FormatBool(e.ThreadProcessIntegrityHealthy) + "\n" +
		"job-bound=" + strconv.FormatBool(e.JobBound) + "\n" +
		"thread-set-sha256=" + e.ThreadSetSHA256 + "\n" +
		"thread-origin-set-sha256=" + e.ThreadOriginSetSHA256 + "\n" +
		"process-tree-sha256=" + e.ProcessTreeSHA256 + "\n" +
		"debug-instrumentation-healthy=" + strconv.FormatBool(e.DebugInstrumentationHealthy) + "\n" +
		"debug-state-sha256=" + e.DebugStateSHA256 + "\n" +
		"jvm-aware-healthy=" + strconv.FormatBool(e.JVMAwareHealthy) + "\n" +
		"java-major=" + strconv.FormatUint(uint64(e.JavaMajor), 10) + "\n" +
		"jvm-state-sha256=" + e.JVMStateSHA256 + "\n" +
		"continuous-guard-version=" + strconv.FormatUint(uint64(e.ContinuousGuardVersion), 10) + "\n" +
		"continuous-guard-healthy=" + strconv.FormatBool(e.ContinuousGuardHealthy) + "\n" +
		"sensor-heartbeat-count=" + strconv.FormatUint(e.SensorHeartbeatCount, 10) + "\n" +
		"guard-heartbeat-count=" + strconv.FormatUint(e.GuardHeartbeatCount, 10) + "\n" +
		"cross-check-count=" + strconv.FormatUint(e.CrossCheckCount, 10) + "\n" +
		"last-sensor-sequence=" + strconv.FormatUint(e.LastSensorSequence, 10) + "\n" +
		"last-guard-sequence=" + strconv.FormatUint(e.LastGuardSequence, 10) + "\n" +
		"sensor-event-chain-sha256=" + e.SensorEventChainSHA256 + "\n" +
		"last-cross-check-sha256=" + e.LastCrossCheckSHA256 + "\n" +
		"last-sensor-heartbeat-ms=" + strconv.FormatUint(e.LastSensorHeartbeatUnixMS, 10) + "\n" +
		"last-guard-heartbeat-ms=" + strconv.FormatUint(e.LastGuardHeartbeatUnixMS, 10) + "\n"
}

func recomputeGuardContinuousEvidenceSHA25601810(e guardContinuousEvidence01810) string {
	sum := sha256.Sum256([]byte(guardContinuousEvidenceCore01810(e)))
	return hex.EncodeToString(sum[:])
}

func guardAttestationV2Core01810(a guardRemoteAttestationV201810) string {
	return "NeverLauncher Guard Attestation Core Windows v2\n" +
		"challenge-id=" + a.ChallengeID + "\n" +
		"challenge-sha256=" + a.ChallengeSHA256 + "\n" +
		"collected-at-ms=" + strconv.FormatUint(a.CollectedAtUnixMS, 10) + "\n" +
		"base-attestation-sha256=" + a.BaseAttestation.AttestationSHA256 + "\n" +
		"continuous-evidence-sha256=" + a.ContinuousEvidence.EvidenceSHA256 + "\n" +
		"runtime-pid=" + strconv.FormatUint(uint64(a.ContinuousEvidence.RuntimePID), 10) + "\n" +
		"last-sensor-sequence=" + strconv.FormatUint(a.ContinuousEvidence.LastSensorSequence, 10) + "\n" +
		"last-guard-sequence=" + strconv.FormatUint(a.ContinuousEvidence.LastGuardSequence, 10) + "\n" +
		"sensor-event-chain-sha256=" + a.ContinuousEvidence.SensorEventChainSHA256 + "\n" +
		"last-cross-check-sha256=" + a.ContinuousEvidence.LastCrossCheckSHA256 + "\n"
}

func recomputeGuardAttestationV2SHA25601810(a guardRemoteAttestationV201810) string {
	sum := sha256.Sum256([]byte(guardAttestationV2Core01810(a)))
	return hex.EncodeToString(sum[:])
}

func validateGuardContinuousEvidence01810(e guardContinuousEvidence01810, now time.Time) error {
	if e.Schema != guardContinuousEvidenceSchema01810 || e.EvidenceVersion != guardContinuousEvidenceVersion01810 || strings.TrimSpace(e.ProcessID) == "" || e.RuntimePID == 0 {
		return errors.New("Защита Аттестация v2 непрерывный свидетельство schema/identity несоответствие")
	}
	if e.SensorProtocolVersion != 3 || e.ModuleGuardVersion != 1 || e.ContinuousGuardVersion != 1 {
		return errors.New("Защита Аттестация v2 непрерывный компонент версия несоответствие")
	}
	if !e.SensorAuthenticated || !e.SensorLoadedBeforeMain || !e.ModuleGuardHealthy || !e.HookEngineHealthy || !e.MemoryIntegrityHealthy || !e.ThreadProcessIntegrityHealthy || !e.JobBound || !e.DebugInstrumentationHealthy || !e.JVMAwareHealthy || !e.ContinuousGuardHealthy {
		return errors.New("Защита Аттестация v2 непрерывный защита является не работоспособный")
	}
	if e.ModuleEventCount == 0 || e.ModuleLastSequence == 0 || e.SensorHeartbeatCount == 0 || e.GuardHeartbeatCount == 0 || e.CrossCheckCount == 0 || e.LastSensorSequence == 0 || e.LastGuardSequence == 0 {
		return errors.New("Защита Аттестация v2 непрерывный счётчики являются не armed")
	}
	if e.SensorHeartbeatCount != e.GuardHeartbeatCount || e.SensorHeartbeatCount != e.CrossCheckCount {
		return errors.New("Защита Аттестация v2 Sensor/Guard сигнал состояния счётчики diverged")
	}
	switch e.JavaMajor {
	case 8, 16, 17, 21, 25:
	default:
		return errors.New("Защита Аттестация v2 Java крупный является не сертифицированный")
	}
	for label, value := range map[string]string{
		"module event chain":  e.ModuleEventChainSHA256,
		"module set":          e.ModuleSetSHA256,
		"hook set":            e.HookSetSHA256,
		"code set":            e.CodeSetSHA256,
		"executable map":      e.ExecutableMapSHA256,
		"thread set":          e.ThreadSetSHA256,
		"thread origin set":   e.ThreadOriginSetSHA256,
		"process tree":        e.ProcessTreeSHA256,
		"debug state":         e.DebugStateSHA256,
		"JVM state":           e.JVMStateSHA256,
		"Sensor event chain":  e.SensorEventChainSHA256,
		"last cross-check":    e.LastCrossCheckSHA256,
		"continuous evidence": e.EvidenceSHA256,
	} {
		if !isSHA256Hex0134(value) {
			return fmt.Errorf("Защита Аттестация v2 %s SHA-256 повреждённый", label)
		}
	}
	nowMS := uint64(now.UTC().UnixMilli())
	maxFuture := nowMS + 2_000
	maxStale := uint64(guardContinuousMaxStaleness01810 / time.Millisecond)
	if e.CollectedAtUnixMS > maxFuture || nowMS > e.CollectedAtUnixMS+maxStale || nowMS > e.LastSensorHeartbeatUnixMS+maxStale || nowMS > e.LastGuardHeartbeatUnixMS+maxStale {
		return errors.New("Защита Аттестация v2 непрерывный свидетельство является устаревший")
	}
	expected := recomputeGuardContinuousEvidenceSHA25601810(e)
	if !hmac.Equal([]byte(expected), []byte(strings.ToLower(strings.TrimSpace(e.EvidenceSHA256)))) {
		return errors.New("Защита Аттестация v2 непрерывный свидетельство хеш несоответствие")
	}
	return nil
}

func validateGuardAttestationV201810(a guardRemoteAttestationV201810, challengeID, challenge string, policy guardReleasePolicy0134, platform string, now time.Time, challengeCreatedAt time.Time) error {
	if a.Schema != guardAttestationV2Schema01810 || a.AttestationVersion != guardAttestationV2Version01810 || a.ChallengeID != strings.TrimSpace(challengeID) {
		return errors.New("Защита Аттестация v2 schema/version/challengeId несоответствие")
	}
	expectedChallenge := deviceChallengeHash0121(challenge)
	if !hmac.Equal([]byte(expectedChallenge), []byte(strings.ToLower(strings.TrimSpace(a.ChallengeSHA256)))) {
		return errors.New("Защита Аттестация v2 запрос хеш несоответствие")
	}
	if !isSHA256Hex0134(a.AttestationSHA256) {
		return errors.New("Защита Аттестация v2 хеш повреждённый")
	}
	if a.BaseAttestation.ChallengeID != a.ChallengeID || !hmac.Equal([]byte(a.BaseAttestation.ChallengeSHA256), []byte(a.ChallengeSHA256)) {
		return errors.New("Защита Аттестация v2 основа запрос привязка несоответствие")
	}
	if err := validateGuardAttestation0134(a.BaseAttestation, challengeID, challenge, policy, platform, now, challengeCreatedAt); err != nil {
		return fmt.Errorf("Защита Аттестация v2 основа проверка ошибка: %w", err)
	}
	if err := validateGuardContinuousEvidence01810(a.ContinuousEvidence, now); err != nil {
		return err
	}
	if a.CollectedAtUnixMS != a.ContinuousEvidence.CollectedAtUnixMS {
		return errors.New("Защита Аттестация v2 коллекция метка времени несоответствие")
	}
	baseCollectedMS := a.BaseAttestation.CollectedAtUnix * 1000
	if a.CollectedAtUnixMS+5_000 < baseCollectedMS || baseCollectedMS+5_000 < a.CollectedAtUnixMS {
		return errors.New("Защита Аттестация v2 base/continuous коллекция Windows diverged")
	}
	if a.ContinuousEvidence.RuntimePID == a.BaseAttestation.Evidence.Guard.PID || a.ContinuousEvidence.RuntimePID == a.BaseAttestation.Evidence.Launcher.PID {
		return errors.New("Защита Аттестация v2 среда выполнения PID collides с Guard/Desktop граница")
	}
	expected := recomputeGuardAttestationV2SHA25601810(a)
	if !hmac.Equal([]byte(expected), []byte(strings.ToLower(strings.TrimSpace(a.AttestationSHA256)))) {
		return errors.New("Защита Аттестация v2 хеш проверка ошибка")
	}
	return nil
}

func guardDeviceSigningPayloadV201810(challenge string, claims authClaims, device model.TrustedDevice, launcherVersion string, a guardRemoteAttestationV201810, challengeExpiresAt string) string {
	return "NeverLauncher Guard Attestation Device Binding v2\n" +
		"purpose=guard-attest-v2\n" +
		"challenge=" + strings.TrimSpace(challenge) + "\n" +
		"challenge-id=" + strings.TrimSpace(a.ChallengeID) + "\n" +
		"user=" + strings.TrimSpace(claims.Sub) + "\n" +
		"device=" + strings.TrimSpace(device.ID) + "\n" +
		"session=" + strings.TrimSpace(claims.SessionID) + "\n" +
		"binding-epoch=" + strconv.FormatInt(claims.BindingEpoch, 10) + "\n" +
		"launcher-version=" + strings.TrimSpace(launcherVersion) + "\n" +
		"fingerprint=" + strings.TrimSpace(device.KeyFingerprint) + "\n" +
		"attestation-sha256=" + strings.TrimSpace(a.AttestationSHA256) + "\n" +
		"continuous-evidence-sha256=" + strings.TrimSpace(a.ContinuousEvidence.EvidenceSHA256) + "\n" +
		"base-attestation-sha256=" + strings.TrimSpace(a.BaseAttestation.AttestationSHA256) + "\n" +
		"runtime-pid=" + strconv.FormatUint(uint64(a.ContinuousEvidence.RuntimePID), 10) + "\n" +
		"challenge-expires-at=" + strings.TrimSpace(challengeExpiresAt) + "\n"
}

func (s Server) authGuardAttestationV2Begin01810(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusPreconditionFailed, "Guard Attestation v2 continuous evidence поддерживает только Windows trusted device")
		return
	}
	policySchema, protocolVersion, requireAuthenticode, err := policy.metadataForPlatform0140(device.Platform)
	if err != nil {
		writeError(w, http.StatusPreconditionFailed, "эта версия Desktop не сертифицирована для Windows устройства")
		return
	}
	if err := attestationEligibleDevice0124(device); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	state, _ := effectiveDeviceAttestation0124(device, time.Now().UTC())
	if state != "verified" {
		writeError(w, http.StatusPreconditionFailed, "Guard Attestation v2 требует свежую device attestation")
		return
	}
	challengeID, err := randomToken("ngav2")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать Guard Attestation v2 challenge")
		return
	}
	challenge, err := randomToken("ngcv2")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать Guard Attestation v2 challenge")
		return
	}
	now := canonicalGuardAttestationTime0134(time.Now())
	expires := canonicalGuardAttestationTime0134(now.Add(guardAttestationV2ChallengeTTL01810))
	entry := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: device.ID, Purpose: guardAttestationV2Purpose01810, ChallengeHash: deviceChallengeHash0121(challenge), Metadata: map[string]any{
		"sessionId": claims.SessionID, "bindingEpoch": strconv.FormatInt(claims.BindingEpoch, 10), "launcherVersion": req.LauncherVersion,
		"keyFingerprint": device.KeyFingerprint, "guardReleasePolicySchema": policySchema, "guardProtocolVersion": strconv.FormatUint(uint64(protocolVersion), 10), "guardPlatform": "windows",
	}, CreatedAt: now, ExpiresAt: expires}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить Guard Attestation v2 challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"challengeId": challengeID, "challenge": challenge, "expiresAt": expires, "launcherVersion": req.LauncherVersion,
		"attestationSchema": guardAttestationV2Schema01810, "continuousEvidenceSchema": guardContinuousEvidenceSchema01810,
		"platform": "windows", "releasePolicySchema": policySchema, "guardProtocolVersion": protocolVersion,
		"requireAuthenticode": requireAuthenticode, "oneTime": true,
	}})
}

func (s Server) authGuardAttestationV2Complete01810(w http.ResponseWriter, r *http.Request) {
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
	var req guardAttestationV2CompleteRequest01810
	if err := decodeDeviceJSON0121(w, r, &req, 512<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный Guard Attestation v2 JSON")
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
		writeError(w, http.StatusPreconditionFailed, "Guard Attestation v2 разрешена только для Windows trusted device")
		return
	}
	policySchema, protocolVersion, _, err := policy.metadataForPlatform0140(device.Platform)
	if err != nil {
		writeError(w, http.StatusPreconditionFailed, "эта версия Desktop не сертифицирована для Windows устройства")
		return
	}
	state, _ := effectiveDeviceAttestation0124(device, time.Now().UTC())
	if state != "verified" {
		writeError(w, http.StatusPreconditionFailed, "device attestation freshness истекла")
		return
	}
	if req.Attestation.ChallengeID != strings.TrimSpace(req.ChallengeID) {
		writeError(w, http.StatusBadRequest, "challengeId не совпадает с Guard Attestation v2")
		return
	}
	pub, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || pub.fingerprint != device.KeyFingerprint {
		writeError(w, http.StatusInternalServerError, "device public key повреждён")
		return
	}
	now := canonicalGuardAttestationTime0134(time.Now())
	if err := validateGuardAttestationV201810(req.Attestation, req.ChallengeID, req.Challenge, policy, device.Platform, now, now.Add(-guardAttestationV2ChallengeTTL01810)); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	payload := guardDeviceSigningPayloadV201810(req.Challenge, claims, device, req.LauncherVersion, req.Attestation, req.ChallengeExpiresAt)
	if err := verifyDeviceSignature0123(pub, payload, req.Signature); err != nil {
		writeError(w, http.StatusUnauthorized, "Guard Attestation v2 device signature недействительна")
		return
	}
	stored, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, deviceID, guardAttestationV2Purpose01810, deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Guard Attestation v2 challenge недействителен, истёк или уже использован")
		return
	}
	releaseBindingMatches := metadataString0121(stored.Metadata, "guardReleasePolicySchema") == policySchema && metadataString0121(stored.Metadata, "guardProtocolVersion") == strconv.FormatUint(uint64(protocolVersion), 10) && metadataString0121(stored.Metadata, "guardPlatform") == "windows"
	if metadataString0121(stored.Metadata, "sessionId") != claims.SessionID || metadataString0121(stored.Metadata, "bindingEpoch") != strconv.FormatInt(claims.BindingEpoch, 10) || metadataString0121(stored.Metadata, "launcherVersion") != req.LauncherVersion || metadataString0121(stored.Metadata, "keyFingerprint") != device.KeyFingerprint || !releaseBindingMatches || req.ChallengeExpiresAt != stored.ExpiresAt.UTC().Format(time.RFC3339Nano) {
		writeError(w, http.StatusUnauthorized, "Guard Attestation v2 challenge больше не соответствует session/device/release binding")
		return
	}
	if err := validateGuardAttestationV201810(req.Attestation, req.ChallengeID, req.Challenge, policy, device.Platform, now, stored.CreatedAt.UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	ticketID, err := randomToken("ngctid")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить Continuous Guard ticket")
		return
	}
	ticketSecret, err := randomToken("ngct")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить Continuous Guard ticket")
		return
	}
	ticketExpires := canonicalGuardAttestationTime0134(now.Add(guardContinuousJoinTTL01810))
	ticket := model.DeviceChallenge{ID: ticketID, UserID: claims.Sub, DeviceID: deviceID, Purpose: guardContinuousJoinPurpose01810, ChallengeHash: deviceChallengeHash0121(ticketSecret), Metadata: map[string]any{
		"sessionId": claims.SessionID, "bindingEpoch": strconv.FormatInt(claims.BindingEpoch, 10), "launcherVersion": req.LauncherVersion,
		"attestationSha256": req.Attestation.AttestationSHA256, "continuousEvidenceSha256": req.Attestation.ContinuousEvidence.EvidenceSHA256,
		"baseAttestationSha256": req.Attestation.BaseAttestation.AttestationSHA256, "runtimePid": strconv.FormatUint(uint64(req.Attestation.ContinuousEvidence.RuntimePID), 10),
		"guardSha256": req.Attestation.BaseAttestation.Evidence.Guard.ImageSHA256, "launcherSha256": req.Attestation.BaseAttestation.Evidence.Launcher.ImageSHA256,
		"sensorEventChainSha256": req.Attestation.ContinuousEvidence.SensorEventChainSHA256, "lastCrossCheckSha256": req.Attestation.ContinuousEvidence.LastCrossCheckSHA256,
	}, CreatedAt: now, ExpiresAt: ticketExpires}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), ticket); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить Continuous Guard ticket")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("guard-attestation-v2"), Actor: claims.Sub, Action: "neverguard:attestation-v2:verified", Target: deviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"verified": true, "attestationVersion": 2, "attestationSha256": req.Attestation.AttestationSHA256,
		"continuousEvidenceSha256": req.Attestation.ContinuousEvidence.EvidenceSHA256, "runtimePid": req.Attestation.ContinuousEvidence.RuntimePID,
		"sensorHeartbeatCount": req.Attestation.ContinuousEvidence.SensorHeartbeatCount, "guardHeartbeatCount": req.Attestation.ContinuousEvidence.GuardHeartbeatCount,
		"crossCheckCount": req.Attestation.ContinuousEvidence.CrossCheckCount, "continuousGuardTicket": ticketID + "." + ticketSecret,
		"expiresAt": ticketExpires, "oneTime": true,
	}})
}

func (s Server) consumeGuardContinuousJoinTicket01810(r *http.Request, claims authClaims, raw string) (model.DeviceChallenge, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || len(raw) > 512 {
		return model.DeviceChallenge{}, errors.New("Непрерывный Защита билет повреждённый")
	}
	if strings.TrimSpace(claims.TrustedDeviceID) == "" {
		return model.DeviceChallenge{}, errors.New("текущий сессия является не привязанный к доверенный устройство")
	}
	now := time.Now().UTC()
	ticket, err := s.Repo.ConsumeDeviceChallenge(r.Context(), parts[0], claims.Sub, claims.TrustedDeviceID, guardContinuousJoinPurpose01810, deviceChallengeHash0121(parts[1]), now)
	if err != nil {
		return model.DeviceChallenge{}, errors.New("Непрерывный Защита билет недопустимый, истёкший или уже используется")
	}
	if metadataString0121(ticket.Metadata, "sessionId") != claims.SessionID || metadataString0121(ticket.Metadata, "bindingEpoch") != strconv.FormatInt(claims.BindingEpoch, 10) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "attestationSha256")) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "continuousEvidenceSha256")) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "baseAttestationSha256")) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "guardSha256")) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "launcherSha256")) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "sensorEventChainSha256")) || !isSHA256Hex0134(metadataString0121(ticket.Metadata, "lastCrossCheckSha256")) {
		return model.DeviceChallenge{}, errors.New("Непрерывный Защита билет session/evidence привязка несоответствие")
	}
	if runtimePID, err := strconv.ParseUint(metadataString0121(ticket.Metadata, "runtimePid"), 10, 32); err != nil || runtimePID == 0 {
		return model.DeviceChallenge{}, errors.New("Непрерывный Защита билет среда выполнения привязка повреждённый")
	}
	return ticket, nil
}

func validateContinuousGuardTicketForMinecraftSession01810(ticket model.DeviceChallenge, session model.MinecraftSession) error {
	if strings.TrimSpace(session.ID) == "" || !session.IntegrityVerified {
		return errors.New("Minecraft целостность сессия является не проверен")
	}
	if metadataString0121(ticket.Metadata, "launcherVersion") != strings.TrimSpace(session.LauncherVersion) {
		return errors.New("Непрерывный Защита билет лаунчер версия делает не соответствовать Minecraft целостность сессия")
	}
	for label, pair := range map[string][2]string{
		"Guard":   {metadataString0121(ticket.Metadata, "guardSha256"), strings.ToLower(strings.TrimSpace(session.GuardSHA256))},
		"Desktop": {metadataString0121(ticket.Metadata, "launcherSha256"), strings.ToLower(strings.TrimSpace(session.LauncherSHA256))},
	} {
		left := strings.ToLower(strings.TrimSpace(pair[0]))
		right := strings.ToLower(strings.TrimSpace(pair[1]))
		if !isSHA256Hex0134(left) || !isSHA256Hex0134(right) || !hmac.Equal([]byte(left), []byte(right)) {
			return fmt.Errorf("Непрерывный Защита билет %s артефакт привязка несоответствие", label)
		}
	}
	return nil
}

func (s Server) continuousGuardRequiredForJoin01810(userID, trustedDeviceID string) (bool, error) {
	required, err := guardAttestationRequiredForDevice0135(s, userID, trustedDeviceID)
	if err != nil {
		return true, err
	}
	if !required {
		return false, nil
	}
	device, err := s.Repo.GetTrustedDevice(userID, trustedDeviceID)
	if err != nil {
		return true, err
	}
	return isWindowsDevicePlatform0134(device.Platform), nil
}
