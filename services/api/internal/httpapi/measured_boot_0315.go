package httpapi

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/attestverify"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const measuredBootTTL0315 = 2 * time.Minute

func measuredBootPolicy0315(now time.Time) (attestverify.PCRPolicyFile0315, string, error) {
	return attestverify.LoadPCRPolicy0315(os.Getenv("NEVERLAUNCHER_TPM_PCR_POLICY_FILE"), now)
}
func (s Server) measuredBootPrerequisites0315(r *http.Request, deviceID string) (authClaims, authSessionRecord, model.TrustedDevice, model.DeviceHardwareEvidence, bool) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		return authClaims{}, authSessionRecord{}, model.TrustedDevice{}, model.DeviceHardwareEvidence{}, false
	}
	session, err := sessionBoundToDevice0124(s, claims, deviceID)
	if err != nil || session.BindingEpoch < 1 || claims.BindingEpoch != session.BindingEpoch {
		return claims, authSessionRecord{}, model.TrustedDevice{}, model.DeviceHardwareEvidence{}, false
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil || attestationEligibleDevice0124(device) != nil || normalizedTPMPlatform0312(device.Platform) == "" {
		return claims, session, model.TrustedDevice{}, model.DeviceHardwareEvidence{}, false
	}
	hw, ok := activeHardwareEvidence0312(s, device, session, time.Now().UTC())
	return claims, session, device, hw, ok
}
func (s Server) authMeasuredBootBegin0315(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("deviceId"))
	claims, session, device, _, ok := s.measuredBootPrerequisites0315(r, id)
	if !ok {
		writeError(w, http.StatusPreconditionFailed, "active registered session and remotely verified TPM Certify required")
		return
	}
	now := canonicalDeviceAttestationTime0124(time.Now())
	policies, hash, err := measuredBootPolicy0315(now)
	if err != nil {
		writeError(w, 412, "operator measured-boot policy unavailable: "+err.Error())
		return
	}
	policyID := strings.TrimSpace(r.URL.Query().Get("policyId"))
	policy, err := policies.Find(policyID, normalizedTPMPlatform0312(device.Platform), now)
	if err != nil {
		writeError(w, 412, "no active measured-boot policy for requested ID/platform")
		return
	}
	idChallenge, err := randomToken("mpc")
	if err != nil {
		writeError(w, 500, "random challenge unavailable")
		return
	}
	secret, err := randomToken("mpn")
	if err != nil {
		writeError(w, 500, "random challenge unavailable")
		return
	}
	expires := canonicalDeviceAttestationTime0124(now.Add(measuredBootTTL0315))
	challenge := model.DeviceChallenge{ID: idChallenge, UserID: claims.Sub, DeviceID: id, Purpose: "measured-boot-quote", ChallengeHash: deviceChallengeHash0121(secret), CreatedAt: now, ExpiresAt: expires, Metadata: map[string]any{
		"sessionId": session.ID, "bindingEpoch": strconv.FormatInt(session.BindingEpoch, 10), "keyFingerprint": device.KeyFingerprint, "platform": normalizedTPMPlatform0312(device.Platform), "policyId": policy.ID, "policyHash": hash,
	}}
	if err = s.Repo.SaveDeviceChallenge(r.Context(), challenge); err != nil {
		writeError(w, 500, "cannot persist PCR challenge")
		return
	}
	b := attestverify.Binding{UserID: claims.Sub, DeviceID: id, SessionID: session.ID, BindingEpoch: session.BindingEpoch, ChallengeID: idChallenge, Challenge: secret, IssuedAt: now, ExpiresAt: expires, Platform: normalizedTPMPlatform0312(device.Platform)}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"challengeId": idChallenge, "challenge": secret, "deviceId": id, "sessionId": session.ID, "bindingEpoch": session.BindingEpoch, "issuedAt": now, "expiresAt": expires, "format": "tpm2-quote-sha256-v1", "tpmExtraDataSha256": attestverify.EncodeQuoteNonce0315(b, policy, hash), "policyId": policy.ID, "policyHash": hash, "pcrSelection": attestverify.PCRPolicySelection0315(policy), "measuredBoot": "not-verified",
	}})
}

type measuredBootComplete0315 struct {
	ChallengeID string                         `json:"challengeId"`
	Challenge   string                         `json:"challenge"`
	Evidence    attestverify.QuoteEvidence0315 `json:"evidence"`
}

func (s Server) authMeasuredBootComplete0315(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("deviceId"))
	claims, session, device, hw, ok := s.measuredBootPrerequisites0315(r, id)
	if !ok {
		writeError(w, 412, "active device/session with certified TPM identity required")
		return
	}
	var req measuredBootComplete0315
	if err := decodeDeviceJSON0121(w, r, &req, 96<<10); err != nil {
		writeError(w, 400, "invalid TPM Quote evidence JSON")
		return
	}
	now := time.Now().UTC()
	ch, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, id, "measured-boot-quote", deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, 401, "expired, invalid or replayed Quote challenge")
		return
	}
	platform := normalizedTPMPlatform0312(device.Platform)
	policyID := metadataString0121(ch.Metadata, "policyId")
	oldHash := metadataString0121(ch.Metadata, "policyHash")
	if metadataString0121(ch.Metadata, "sessionId") != session.ID || metadataString0121(ch.Metadata, "bindingEpoch") != strconv.FormatInt(session.BindingEpoch, 10) || metadataString0121(ch.Metadata, "keyFingerprint") != device.KeyFingerprint || metadataString0121(ch.Metadata, "platform") != platform {
		writeError(w, 401, "Quote session/device/epoch changed")
		return
	}
	policies, hash, err := measuredBootPolicy0315(now)
	if err != nil || hash != oldHash {
		writeError(w, 412, "PCR policy unavailable or changed during challenge")
		return
	}
	policy, err := policies.Find(policyID, platform, now)
	if err != nil {
		writeError(w, 412, "PCR policy no longer active")
		return
	}
	roots, err := hardwareRootStore0312(now)
	if err != nil {
		writeError(w, 412, "trusted AK roots unavailable")
		return
	}
	b := attestverify.Binding{UserID: claims.Sub, DeviceID: id, SessionID: session.ID, BindingEpoch: session.BindingEpoch, ChallengeID: ch.ID, Challenge: req.Challenge, IssuedAt: ch.CreatedAt, ExpiresAt: ch.ExpiresAt, Platform: platform}
	result, err := attestverify.VerifyQuote0315(req.Evidence, b, policy, hash, attestverify.Result{RootID: hw.RootID, RootFingerprint: hw.RootFingerprint, AKFingerprint: hw.AKFingerprint, ExpiresAt: hw.ExpiresAt}, roots, now)
	if err != nil {
		writeError(w, 401, "TPM Quote rejected: "+err.Error())
		return
	}
	saved := model.MeasuredBootEvidence0315{UserID: claims.Sub, DeviceID: id, SessionID: session.ID, BindingEpoch: session.BindingEpoch, KeyFingerprint: device.KeyFingerprint, RootID: result.RootID, RootFingerprint: result.RootFingerprint, AKFingerprint: result.AKFingerprint, PolicyID: result.PolicyID, PolicyHash: result.PolicyHash, PCRDigest: result.PCRDigest, ChallengeID: ch.ID, VerifiedAt: now, ExpiresAt: result.ExpiresAt}
	if err = s.Repo.SaveMeasuredBoot0315(r.Context(), saved); err != nil {
		writeError(w, 409, "cannot persist TPM Quote verification")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "tpm-quote-" + ch.ID, Actor: claims.Sub, Action: "auth:device:measured-boot:verified", Target: id, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"verification": "tpm-quote-pcr-policy-verified", "policyId": result.PolicyID, "policyHash": result.PolicyHash, "pcrDigest": result.PCRDigest, "expiresAt": result.ExpiresAt, "bindingEpoch": session.BindingEpoch, "guardRuntime": "not-verified"}})
}
func (s Server) authMeasuredBootStatus0315(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("deviceId"))
	_, session, device, hw, ok := s.measuredBootPrerequisites0315(r, id)
	answer := map[string]any{"verification": "not-verified", "reason": "missing-active-tpm-certified-device-session", "guardRuntime": "not-verified"}
	if ok {
		answer["reason"] = "no-verified-quote"
		saved, err := s.Repo.LatestMeasuredBoot0315(r.Context(), device.UserID, id)
		if err == nil {
			now := time.Now().UTC()
			policies, hash, e := measuredBootPolicy0315(now)
			if e == nil && hash == saved.PolicyHash && saved.SessionID == session.ID && saved.BindingEpoch == session.BindingEpoch && saved.KeyFingerprint == device.KeyFingerprint && saved.AKFingerprint == hw.AKFingerprint && saved.RootID == hw.RootID && saved.RootFingerprint == hw.RootFingerprint && saved.VerifiedAt.Before(now.Add(10*time.Second)) && now.Before(saved.ExpiresAt) {
				if _, e = policies.Find(saved.PolicyID, normalizedTPMPlatform0312(device.Platform), now); e == nil {
					answer = map[string]any{"verification": "tpm-quote-pcr-policy-verified", "policyId": saved.PolicyID, "pcrDigest": saved.PCRDigest, "verifiedAt": saved.VerifiedAt, "expiresAt": saved.ExpiresAt, "guardRuntime": "not-verified"}
				}
			}
			if answer["verification"] == "not-verified" {
				answer["reason"] = "quote-expired-policy-changed-or-device-binding-revoked"
			}
		}
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": answer})
}
