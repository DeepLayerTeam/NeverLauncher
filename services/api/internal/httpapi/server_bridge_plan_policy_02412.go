package httpapi

import (
	"encoding/hex"
	"errors"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/planpolicy02412"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const planProofDomain02412 = "NeverLauncher-Verified-Component-Plan-v1"
const planChallengePurpose02412 = "serverbridge-verified-plan-v1"

type planPolicy02412 = planpolicy02412.Policy

func planPolicyRequired02412() bool                              { return planpolicy02412.Required() }
func loadPlanPolicy02412(now time.Time) (planPolicy02412, error) { return planpolicy02412.Load(now) }
func planMatches02412(p planPolicy02412, server, project, profile, channel, release, catalog, plan string) bool {
	return planpolicy02412.Matches(p, server, project, profile, channel, release, catalog, plan)
}

type planChallengeRequest02412 struct {
	ServerID  string `json:"serverId"`
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
}
type verifiedPlanEvidence02412 struct {
	ChallengeID            string `json:"challengeId"`
	Challenge              string `json:"challenge"`
	UserID                 string `json:"userId"`
	DeviceID               string `json:"deviceId"`
	SessionID              string `json:"sessionId"`
	BindingEpoch           int64  `json:"bindingEpoch"`
	ServerID               string `json:"serverId"`
	ProjectID              string `json:"projectId"`
	ProfileID              string `json:"profileId"`
	Channel                string `json:"channel"`
	ReleaseSignature       string `json:"releaseSignature"`
	CatalogDigest          string `json:"catalogDigest"`
	PlanSHA256             string `json:"planSha256"`
	GuardAttestationSHA256 string `json:"guardAttestationSha256"`
	Signature              string `json:"signature"`
}

func isHexLength02412(v string, n int) bool {
	if len(v) != n {
		return false
	}
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == n/2 && v == strings.ToLower(v)
}

func planEvidencePayload02412(e verifiedPlanEvidence02412) string {
	return strings.Join([]string{planProofDomain02412, e.ChallengeID, e.Challenge, e.UserID, e.DeviceID, e.SessionID,
		strconv.FormatInt(e.BindingEpoch, 10), e.ServerID, e.ProjectID, e.ProfileID, e.Channel,
		e.ReleaseSignature, e.CatalogDigest, e.PlanSHA256, e.GuardAttestationSHA256, ""}, "\n")
}
func (s Server) serverBridgePlanChallenge02412(w http.ResponseWriter, r *http.Request) {
	claims, _, err := s.bridgeClaimsFromRequest910(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "player session required")
		return
	}
	if !planPolicyRequired02412() {
		writeError(w, http.StatusPreconditionFailed, "verified plan policy is disabled")
		return
	}
	policy, err := loadPlanPolicy02412(time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "signed plan policy unavailable")
		return
	}
	var req planChallengeRequest02412
	if err = decodeDeviceJSON0121(w, r, &req, 4096); err != nil {
		writeError(w, http.StatusBadRequest, "invalid plan challenge request")
		return
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if !s.canAccessProject(claims, req.ProjectID) || req.ServerID == "" || req.ProfileID == "" {
		writeError(w, http.StatusForbidden, "project/profile/server access denied")
		return
	}
	scoped := false
	for _, a := range policy.AllowedPlans {
		if a.ServerID == req.ServerID && a.ProjectID == req.ProjectID && a.ProfileID == req.ProfileID && a.Channel == req.Channel {
			scoped = true
			break
		}
	}
	if !scoped {
		writeError(w, http.StatusForbidden, "no signed plan policy for server/profile/channel")
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, claims.Sub, claims.SessionID, claims.TrustedDeviceID, claims.BindingEpoch, true)
	if !trust.Allowed {
		writeError(w, http.StatusForbidden, "device trust required for verified plan")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, claims.TrustedDeviceID)
	if err != nil || device.KeyAlgorithm != "p256" || device.KeyBinding != "hardware" {
		writeError(w, http.StatusForbidden, "hardware-bound device key required")
		return
	}
	challengeID, err := randomToken("plcid")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge entropy unavailable")
		return
	}
	secret, err := randomToken("plc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge entropy unavailable")
		return
	}
	now := canonicalGuardAttestationTime0134(time.Now().UTC())
	record := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: claims.TrustedDeviceID, Purpose: planChallengePurpose02412, ChallengeHash: deviceChallengeHash0121(secret),
		Metadata: map[string]any{"sessionId": claims.SessionID, "bindingEpoch": strconv.FormatInt(claims.BindingEpoch, 10), "serverId": req.ServerID, "projectId": req.ProjectID, "profileId": req.ProfileID, "channel": req.Channel, "policyEpoch": strconv.FormatUint(policy.Epoch, 10)}, CreatedAt: now, ExpiresAt: now.Add(60 * time.Second)}
	if err = s.Repo.SaveDeviceChallenge(r.Context(), record); err != nil {
		writeError(w, http.StatusServiceUnavailable, "plan challenge persistence unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"challengeId": challengeID, "challenge": secret, "expiresAt": record.ExpiresAt, "policyEpoch": policy.Epoch}})
}

// Evaluate before creating a one-time join ticket. Challenge consumption is an
// atomic repository operation (also across multi-node PostgreSQL deployments).
func (s Server) verifyPlanForJoin02412(r *http.Request, claims authClaims, req bridgeJoinRequest, guardTicket model.DeviceChallenge) error {
	policy, err := loadPlanPolicy02412(time.Now().UTC())
	if err != nil {
		return err
	}
	e := req.PlanEvidence
	if e == nil {
		return errors.New("verified component plan evidence required")
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if e.UserID != claims.Sub || e.SessionID != claims.SessionID || e.DeviceID != claims.TrustedDeviceID || e.BindingEpoch != claims.BindingEpoch || e.ServerID != req.ServerID || e.ProjectID != req.ProjectID || e.ProfileID != req.ProfileID || e.Channel != req.Channel {
		return errors.New("verified component plan session, trusted device or target mismatch")
	}
	if !isHexLength02412(e.ReleaseSignature, 128) || !isHexLength02412(e.CatalogDigest, 64) || !isHexLength02412(e.PlanSHA256, 64) || !isHexLength02412(e.GuardAttestationSHA256, 64) {
		return errors.New("malformed signed component plan measurements")
	}
	if !planMatches02412(policy, e.ServerID, e.ProjectID, e.ProfileID, e.Channel, e.ReleaseSignature, e.CatalogDigest, e.PlanSHA256) {
		return errors.New("signed policy denies resolved component plan")
	}
	// This release requires a freshly completed continuous Guard v2 attestation.
	// A user-supplied list of mods, plan digest or P-256 signature alone is NEVER sufficient.
	if guardTicket.ID == "" || metadataString0121(guardTicket.Metadata, "attestationSha256") != e.GuardAttestationSHA256 {
		return errors.New("verified plan is not bound to current continuous NeverGuard evidence")
	}
	if e.ChallengeID == "" || e.Challenge == "" || len(e.Challenge) > 160 || len(e.ChallengeID) > 160 || strings.ContainsAny(planEvidencePayload02412(*e), "\r") {
		return errors.New("invalid verified plan challenge")
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, claims.TrustedDeviceID)
	if err != nil || device.KeyAlgorithm != "p256" || device.KeyBinding != "hardware" {
		return errors.New("hardware device identity unavailable")
	}
	key, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || key.fingerprint != device.KeyFingerprint {
		return errors.New("device proof key binding invalid")
	}
	if err = verifyDeviceSignature0123(key, planEvidencePayload02412(*e), e.Signature); err != nil {
		return errors.New("verified plan device proof signature invalid")
	}
	consumed, err := s.Repo.ConsumeDeviceChallenge(r.Context(), e.ChallengeID, claims.Sub, claims.TrustedDeviceID, planChallengePurpose02412, deviceChallengeHash0121(e.Challenge), time.Now().UTC())
	if err != nil {
		return errors.New("verified plan challenge expired or replayed")
	}
	if metadataString0121(consumed.Metadata, "sessionId") != claims.SessionID || metadataString0121(consumed.Metadata, "bindingEpoch") != strconv.FormatInt(claims.BindingEpoch, 10) || metadataString0121(consumed.Metadata, "serverId") != req.ServerID || metadataString0121(consumed.Metadata, "projectId") != req.ProjectID || metadataString0121(consumed.Metadata, "profileId") != req.ProfileID || metadataString0121(consumed.Metadata, "channel") != req.Channel || metadataString0121(consumed.Metadata, "policyEpoch") != strconv.FormatUint(policy.Epoch, 10) {
		return errors.New("verified plan challenge binding/policy epoch changed")
	}
	return nil
}

// A signed policy activated after a ticket was issued invalidates that ticket.
// This also closes the rollout window where a pre-policy legacy join was
// minted before REQUIRE_PLAN_POLICY was enabled.
func planJoinEpochValid02412(created time.Time) error {
	if !planPolicyRequired02412() {
		return nil
	}
	p, err := loadPlanPolicy02412(time.Now().UTC())
	if err != nil {
		return err
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return err
	}
	if created.Before(issued) {
		return errors.New("join ticket predates active verified plan policy")
	}
	return nil
}

func planPolicyStatus02412() string {
	if !planPolicyRequired02412() {
		return "legacy-disabled"
	}
	if _, e := loadPlanPolicy02412(time.Now().UTC()); e != nil {
		return "fail-closed"
	}
	return "active"
}
