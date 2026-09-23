package httpapi

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const minecraftIntegrityPolicy0135 = "guard-launch-integrity-v1"

type minecraftIntegrityDecision0135 struct {
	Allowed                bool      `json:"allowed"`
	Required               bool      `json:"required"`
	Reason                 string    `json:"reason"`
	Policy                 string    `json:"policy"`
	LauncherVersion        string    `json:"launcherVersion,omitempty"`
	GuardAttestationSHA256 string    `json:"guardAttestationSha256,omitempty"`
	GuardEvidenceSHA256    string    `json:"guardEvidenceSha256,omitempty"`
	GuardSHA256            string    `json:"guardSha256,omitempty"`
	LauncherSHA256         string    `json:"launcherSha256,omitempty"`
	VerifiedAt             time.Time `json:"verifiedAt,omitempty"`
}

type minecraftIntegritySnapshot0135 struct {
	GuardAttestationSHA256 string
	GuardEvidenceSHA256    string
	GuardSHA256            string
	LauncherSHA256         string
	LauncherVersion        string
	VerifiedAt             time.Time
}

func guardAttestationRequiredForDevice0135(s Server, userID, deviceID string) (bool, error) {
	if !s.guardAttestationRequired0134() {
		return false, nil
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false, nil
	}
	device, err := s.Repo.GetTrustedDevice(strings.TrimSpace(userID), deviceID)
	if err != nil {
		return false, err
	}
	return isWindowsDevicePlatform0134(device.Platform), nil
}

func minecraftIntegrityDeny0135(required bool, reason string, session model.MinecraftSession) minecraftIntegrityDecision0135 {
	return minecraftIntegrityDecision0135{
		Allowed:                false,
		Required:               required,
		Reason:                 reason,
		Policy:                 minecraftIntegrityPolicy0135,
		LauncherVersion:        strings.TrimSpace(session.LauncherVersion),
		GuardAttestationSHA256: strings.TrimSpace(session.GuardAttestationSHA256),
		GuardEvidenceSHA256:    strings.TrimSpace(session.GuardEvidenceSHA256),
		GuardSHA256:            strings.TrimSpace(session.GuardSHA256),
		LauncherSHA256:         strings.TrimSpace(session.LauncherSHA256),
		VerifiedAt:             session.IntegrityVerifiedAt,
	}
}

func minecraftIntegrityAllow0135(required bool, reason string, session model.MinecraftSession) minecraftIntegrityDecision0135 {
	decision := minecraftIntegrityDeny0135(required, reason, session)
	decision.Allowed = true
	return decision
}

func snapshotFromGuardLaunchTicket0135(ticket model.DeviceChallenge) (minecraftIntegritySnapshot0135, error) {
	if strings.TrimSpace(ticket.ID) == "" {
		return minecraftIntegritySnapshot0135{}, errors.New("Guard launch ticket is missing")
	}
	snapshot := minecraftIntegritySnapshot0135{
		GuardAttestationSHA256: strings.ToLower(strings.TrimSpace(metadataString0121(ticket.Metadata, "attestationSha256"))),
		GuardEvidenceSHA256:    strings.ToLower(strings.TrimSpace(metadataString0121(ticket.Metadata, "evidenceSha256"))),
		GuardSHA256:            strings.ToLower(strings.TrimSpace(metadataString0121(ticket.Metadata, "guardSha256"))),
		LauncherSHA256:         strings.ToLower(strings.TrimSpace(metadataString0121(ticket.Metadata, "launcherSha256"))),
		LauncherVersion:        strings.TrimSpace(metadataString0121(ticket.Metadata, "launcherVersion")),
		VerifiedAt:             ticket.CreatedAt.UTC(),
	}
	for label, value := range map[string]string{
		"attestationSha256": snapshot.GuardAttestationSHA256,
		"evidenceSha256":    snapshot.GuardEvidenceSHA256,
		"guardSha256":       snapshot.GuardSHA256,
		"launcherSha256":    snapshot.LauncherSHA256,
	} {
		if !isSHA256Hex0134(value) {
			return minecraftIntegritySnapshot0135{}, fmt.Errorf("Guard launch ticket %s malformed", label)
		}
	}
	if snapshot.LauncherVersion == "" || len(snapshot.LauncherVersion) > 64 || snapshot.VerifiedAt.IsZero() {
		return minecraftIntegritySnapshot0135{}, errors.New("Guard launch ticket integrity metadata incomplete")
	}
	return snapshot, nil
}

func (s Server) evaluateMinecraftIntegrity0135(session model.MinecraftSession) minecraftIntegrityDecision0135 {
	required, err := guardAttestationRequiredForDevice0135(s, session.UserID, session.TrustedDeviceID)
	if err != nil {
		return minecraftIntegrityDeny0135(true, "integrity_device_unavailable", session)
	}
	if !required {
		return minecraftIntegrityAllow0135(false, "integrity_not_required", session)
	}
	if !session.IntegrityVerified {
		return minecraftIntegrityDeny0135(true, "integrity_snapshot_missing", session)
	}
	for label, value := range map[string]string{
		"attestation": session.GuardAttestationSHA256,
		"evidence":    session.GuardEvidenceSHA256,
		"guard":       session.GuardSHA256,
		"launcher":    session.LauncherSHA256,
	} {
		if !isSHA256Hex0134(strings.ToLower(strings.TrimSpace(value))) {
			return minecraftIntegrityDeny0135(true, "integrity_"+label+"_hash_invalid", session)
		}
	}
	version := strings.TrimSpace(session.LauncherVersion)
	if version == "" || len(version) > 64 {
		return minecraftIntegrityDeny0135(true, "integrity_release_missing", session)
	}
	if session.IntegrityVerifiedAt.IsZero() || session.CreatedAt.IsZero() {
		return minecraftIntegrityDeny0135(true, "integrity_timestamp_missing", session)
	}
	verifiedAt := session.IntegrityVerifiedAt.UTC()
	createdAt := session.CreatedAt.UTC()
	if verifiedAt.After(createdAt.Add(guardAttestationClockSkew0134)) || createdAt.Sub(verifiedAt) > guardLaunchTicketTTL0134+guardAttestationClockSkew0134 {
		return minecraftIntegrityDeny0135(true, "integrity_attestation_not_fresh_at_issue", session)
	}
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		return minecraftIntegrityDeny0135(true, "integrity_release_policy_unavailable", session)
	}
	policy, ok := policies[version]
	if !ok {
		return minecraftIntegrityDeny0135(true, "integrity_release_revoked", session)
	}
	if !containsHash0134(policy.GuardSHA256, session.GuardSHA256) || !containsHash0134(policy.LauncherSHA256, session.LauncherSHA256) {
		return minecraftIntegrityDeny0135(true, "integrity_release_revoked", session)
	}
	return minecraftIntegrityAllow0135(true, "integrity_verified", session)
}

func minecraftIntegrityPermanentFailure0135(reason string) bool {
	switch reason {
	case "integrity_snapshot_missing", "integrity_attestation_hash_invalid", "integrity_evidence_hash_invalid", "integrity_guard_hash_invalid", "integrity_launcher_hash_invalid", "integrity_release_missing", "integrity_timestamp_missing", "integrity_attestation_not_fresh_at_issue", "integrity_release_revoked":
		return true
	default:
		return false
	}
}

func (s Server) evaluateServerBridgeJoinIntegrity0135(join bridgeJoinRecord) (model.MinecraftSession, minecraftIntegrityDecision0135) {
	required, err := guardAttestationRequiredForDevice0135(s, join.UserID, join.TrustedDeviceID)
	if err != nil {
		return model.MinecraftSession{}, minecraftIntegrityDeny0135(true, "integrity_device_unavailable", model.MinecraftSession{})
	}
	if strings.TrimSpace(join.MinecraftSessionID) == "" {
		if required {
			return model.MinecraftSession{}, minecraftIntegrityDeny0135(true, "minecraft_integrity_session_required", model.MinecraftSession{})
		}
		return model.MinecraftSession{}, minecraftIntegrityAllow0135(false, "integrity_not_required", model.MinecraftSession{})
	}
	repo, err := s.minecraftRepo119()
	if err != nil {
		return model.MinecraftSession{}, minecraftIntegrityDeny0135(required, "minecraft_integrity_repository_unavailable", model.MinecraftSession{})
	}
	session, err := repo.GetMinecraftSession(join.MinecraftSessionID)
	if err != nil || session.Status != "active" || !session.ExpiresAt.After(time.Now().UTC()) {
		return model.MinecraftSession{}, minecraftIntegrityDeny0135(required, "minecraft_integrity_session_inactive", session)
	}
	if session.UserID != join.UserID || session.NeverSessionID != join.SessionID || strings.TrimSpace(session.TrustedDeviceID) != strings.TrimSpace(join.TrustedDeviceID) || session.BindingEpoch != join.BindingEpoch {
		return session, minecraftIntegrityDeny0135(required, "minecraft_integrity_binding_mismatch", session)
	}
	return session, s.evaluateMinecraftIntegrity0135(session)
}

func (s Server) requireMinecraftIntegrityForBridgeSession0135(userID, neverSessionID, trustedDeviceID string, bindingEpoch int64, minecraftAccessToken string) (model.MinecraftSession, error) {
	required, err := guardAttestationRequiredForDevice0135(s, userID, trustedDeviceID)
	if err != nil {
		return model.MinecraftSession{}, errors.New("не удалось определить Minecraft integrity policy")
	}
	minecraftAccessToken = strings.TrimSpace(minecraftAccessToken)
	if minecraftAccessToken == "" {
		if required {
			return model.MinecraftSession{}, errors.New("minecraftAccessToken обязателен для integrity-enforced ServerBridge join")
		}
		return model.MinecraftSession{}, nil
	}
	session, _, _, err := s.validateMinecraftToken119(minecraftAccessToken)
	if err != nil {
		return model.MinecraftSession{}, errors.New("Minecraft session недействительна")
	}
	if session.UserID != strings.TrimSpace(userID) || session.NeverSessionID != strings.TrimSpace(neverSessionID) || strings.TrimSpace(session.TrustedDeviceID) != strings.TrimSpace(trustedDeviceID) || session.BindingEpoch != bindingEpoch {
		return model.MinecraftSession{}, errors.New("Minecraft session не совпадает с Never session/device binding")
	}
	decision := s.evaluateMinecraftIntegrity0135(session)
	if !decision.Allowed {
		return model.MinecraftSession{}, fmt.Errorf("Minecraft integrity policy denied: %s", decision.Reason)
	}
	return session, nil
}

func integrityMetadataFromMinecraftSession0135(session model.MinecraftSession) map[string]any {
	return map[string]any{
		"policy":                 minecraftIntegrityPolicy0135,
		"verified":               session.IntegrityVerified,
		"launcherVersion":        session.LauncherVersion,
		"guardAttestationSha256": session.GuardAttestationSHA256,
		"guardEvidenceSha256":    session.GuardEvidenceSHA256,
		"guardSha256":            session.GuardSHA256,
		"launcherSha256":         session.LauncherSHA256,
		"verifiedAt":             session.IntegrityVerifiedAt,
		"bindingEpoch":           strconv.FormatInt(session.BindingEpoch, 10),
	}
}

func isRepositoryNotFound0135(err error) bool {
	return errors.Is(err, repository.ErrNotFound)
}
