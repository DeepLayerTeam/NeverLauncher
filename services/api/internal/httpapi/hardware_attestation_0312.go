package httpapi

import (
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/attestverify"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const hardwareChallengeTTL0312 = 2 * time.Minute

func hardwareRootStore0312(now time.Time) (*attestverify.Store, error) {
	return attestverify.Load(os.Getenv("LAUNCHER_TPM_AK_ROOTS_FILE"), now)
}

func activeHardwareEvidence0312(s Server, device model.TrustedDevice, session authSessionRecord, now time.Time) (model.DeviceHardwareEvidence, bool) {
	var none model.DeviceHardwareEvidence
	evidence, err := s.Repo.LatestHardwareEvidence(nil, device.UserID, device.ID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" || device.KeyBinding != "hardware" || device.KeyAlgorithm != "p256" || evidence.KeyFingerprint != device.KeyFingerprint || evidence.SessionID != session.ID || evidence.BindingEpoch != session.BindingEpoch || !now.Before(evidence.ExpiresAt) || evidence.VerifiedAt.After(now) {
		return none, false
	}
	store, err := hardwareRootStore0312(now)
	if err != nil || !store.ActivePinned(evidence.RootID, evidence.RootFingerprint, evidence.AKFingerprint, normalizedTPMPlatform0312(device.Platform), now) {
		return none, false
	}
	return evidence, true
}

func normalizedTPMPlatform0312(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if strings.HasPrefix(p, "win") {
		return "windows"
	}
	if strings.HasPrefix(p, "linux") {
		return "linux"
	}
	return ""
}

func (s Server) authTPMCertifyBegin0312(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}
	id := strings.TrimSpace(r.PathValue("deviceId"))
	session, err := sessionBoundToDevice0124(s, claims, id)
	if err != nil || session.BindingEpoch < 1 || claims.BindingEpoch != session.BindingEpoch {
		writeError(w, http.StatusConflict, "active device/session/binding epoch required")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if err = attestationEligibleDevice0124(device); err != nil || normalizedTPMPlatform0312(device.Platform) == "" {
		writeError(w, http.StatusPreconditionFailed, "TPM P-256 device on Windows/Linux required")
		return
	}
	now := canonicalDeviceAttestationTime0124(time.Now())
	if _, err = hardwareRootStore0312(now); err != nil {
		writeError(w, http.StatusPreconditionFailed, "TPM AK trust roots unavailable or invalid")
		return
	}
	challengeID, err := randomToken("htc")
	if err != nil {
		writeError(w, 500, "random challenge unavailable")
		return
	}
	challenge, err := randomToken("htn")
	if err != nil {
		writeError(w, 500, "random challenge unavailable")
		return
	}
	expires := canonicalDeviceAttestationTime0124(now.Add(hardwareChallengeTTL0312))
	ch := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: id, Purpose: "hardware-certify", ChallengeHash: deviceChallengeHash0121(challenge), CreatedAt: now, ExpiresAt: expires, Metadata: map[string]any{
		"sessionId": session.ID, "bindingEpoch": strconv.FormatInt(session.BindingEpoch, 10), "keyFingerprint": device.KeyFingerprint, "platform": normalizedTPMPlatform0312(device.Platform),
	}}
	if err = s.Repo.SaveDeviceChallenge(r.Context(), ch); err != nil {
		writeError(w, 500, "cannot persist challenge")
		return
	}
	pub, err := base64.RawURLEncoding.DecodeString(device.PublicKey)
	if err != nil {
		writeError(w, 500, "device key corrupt")
		return
	}
	b := attestverify.Binding{UserID: claims.Sub, DeviceID: id, SessionID: session.ID, BindingEpoch: session.BindingEpoch, ChallengeID: challengeID, Challenge: challenge, IssuedAt: now, ExpiresAt: expires, DevicePublicKey: pub, Platform: normalizedTPMPlatform0312(device.Platform)}
	hash := attestverify.ExpectedExtraData(b)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"challengeId": challengeID, "challenge": challenge, "deviceId": id, "sessionId": session.ID, "bindingEpoch": session.BindingEpoch, "issuedAt": now, "expiresAt": expires,
		"format": "tpm2-certify-sha256-v1", "tpmExtraDataSha256": base64.RawURLEncoding.EncodeToString(hash[:]),
		"hardwareAssurance": "not-verified", "measuredBoot": "not-verified",
	}})
}

type hardwareCompleteRequest0312 struct {
	ChallengeID string                `json:"challengeId"`
	Challenge   string                `json:"challenge"`
	Evidence    attestverify.Evidence `json:"evidence"`
}

func (s Server) authTPMCertifyComplete0312(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, 401, "invalid bearer token")
		return
	}
	id := strings.TrimSpace(r.PathValue("deviceId"))
	session, err := sessionBoundToDevice0124(s, claims, id)
	if err != nil || session.BindingEpoch < 1 || claims.BindingEpoch != session.BindingEpoch {
		writeError(w, 409, "device/session epoch changed")
		return
	}
	var req hardwareCompleteRequest0312
	if err = decodeDeviceJSON0121(w, r, &req, 96<<10); err != nil {
		writeError(w, 400, "invalid TPM evidence JSON")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, id)
	if err != nil {
		writeError(w, 404, "device not found")
		return
	}
	if err = attestationEligibleDevice0124(device); err != nil {
		writeError(w, 412, "inactive or ineligible device")
		return
	}
	now := time.Now().UTC()
	store, err := hardwareRootStore0312(now)
	if err != nil {
		writeError(w, 412, "TPM AK roots unavailable")
		return
	}
	ch, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, id, "hardware-certify", deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, 401, "expired, invalid or replayed TPM challenge")
		return
	}
	platform := normalizedTPMPlatform0312(device.Platform)
	if metadataString0121(ch.Metadata, "sessionId") != session.ID || metadataString0121(ch.Metadata, "bindingEpoch") != strconv.FormatInt(session.BindingEpoch, 10) || metadataString0121(ch.Metadata, "keyFingerprint") != device.KeyFingerprint || metadataString0121(ch.Metadata, "platform") != platform {
		writeError(w, 401, "device identity/session/epoch has changed")
		return
	}
	pub, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || pub.fingerprint != device.KeyFingerprint {
		writeError(w, 500, "registered key integrity failure")
		return
	}
	b := attestverify.Binding{UserID: claims.Sub, DeviceID: id, SessionID: session.ID, BindingEpoch: session.BindingEpoch, ChallengeID: req.ChallengeID, Challenge: req.Challenge, IssuedAt: ch.CreatedAt, ExpiresAt: ch.ExpiresAt, DevicePublicKey: pub.raw, Platform: platform}
	result, err := attestverify.Verify(req.Evidence, b, store, now)
	if err != nil {
		writeError(w, 401, "TPM Certify rejected: "+err.Error())
		return
	}
	evidence := model.DeviceHardwareEvidence{UserID: claims.Sub, DeviceID: id, SessionID: session.ID, BindingEpoch: session.BindingEpoch, KeyFingerprint: device.KeyFingerprint, RootID: result.RootID, RootFingerprint: result.RootFingerprint, AKFingerprint: result.AKFingerprint, ChallengeID: req.ChallengeID, VerifiedAt: now, ExpiresAt: result.ExpiresAt}
	if err = s.Repo.SaveHardwareEvidence(r.Context(), evidence); err != nil {
		writeError(w, 409, "cannot commit hardware evidence")
		return
	}
	// Do not modify legacy "challenge-response-v1" or turn key provenance into Guard trust.
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "tpm-certify-" + req.ChallengeID, Actor: claims.Sub, Action: "auth:device:tpm-certify:verified", Target: id, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"verification": "tpm-ak-certified", "rootId": result.RootID, "akFingerprint": result.AKFingerprint, "expiresAt": result.ExpiresAt, "bindingEpoch": session.BindingEpoch, "runtimeEvidence": "none", "measuredBoot": "not-verified",
	}})
}
