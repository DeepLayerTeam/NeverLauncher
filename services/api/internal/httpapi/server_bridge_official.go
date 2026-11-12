package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Официальные билеты выдаются только после доказательства Minecraft Services, что
// bearer владеет выбранным Java-профилем и этот профиль связан с данным
// пользователем Launcher. Minecraft bearer не попадает в билет, строку БД или ответ.
var errOfficialBridgeProof0397 = errors.New("serverbridge_official_identity_not_verified")

func verifiedOfficialBridgeProfile0397(ctx context.Context, verifier minecraftProfileVerifier0268,
	store repository.OfficialLinkStore0268, owner, username, bearer string) (officialminecraft.Profile, error) {
	if store == nil || len(bearer) < 16 || len(bearer) > 8192 || strings.ContainsAny(bearer, "\r\n\x00\t ") {
		return officialminecraft.Profile{}, errOfficialBridgeProof0397
	}
	p, err := verifier.Profile(ctx, bearer)
	if err != nil {
		return officialminecraft.Profile{}, errOfficialBridgeProof0397
	}
	uuid, ok := canonicalMinecraftUUID0268(p.ID)
	if !ok || !validOfficialProfile0263(p) || !strings.EqualFold(username, p.Name) {
		return officialminecraft.Profile{}, errOfficialBridgeProof0397
	}
	links, err := store.ListOfficialLinks0268(ctx, owner)
	if err != nil {
		return officialminecraft.Profile{}, errors.New("serverbridge_official_identity_store_unavailable")
	}
	for _, link := range links {
		if strings.EqualFold(link.MinecraftUUID, uuid) && strings.EqualFold(link.MinecraftName, p.Name) {
			p.ID = uuid
			return p, nil
		}
	}
	return officialminecraft.Profile{}, errOfficialBridgeProof0397
}

// В одноразовой записи входа хранится НЕСЕКРЕТНЫЙ снимок целостности. Он никогда
// не создаётся из JSON renderer; его может заполнить только погашенный challenge
// доверенного устройства.
func officialJoinProof0397(owner, session, device string, bindingEpoch int64,
	p officialminecraft.Profile, snapshot *minecraftIntegritySnapshot0135, now time.Time) (string, error) {
	uuid, ok := canonicalMinecraftUUID0268(p.ID)
	if !ok || !validOfficialProfile0263(p) || owner == "" || session == "" {
		return "", errOfficialBridgeProof0397
	}
	proof := model.MinecraftSession{
		ID: "official-" + uuid, UserID: owner, LauncherSessionID: session, ProfileUUID: uuid,
		TrustedDeviceID: device, BindingEpoch: bindingEpoch, Status: "active",
		CreatedAt: now.UTC(), LastSeenAt: now.UTC(), ExpiresAt: now.UTC().Add(12 * time.Hour),
	}
	if snapshot != nil {
		proof.IntegrityVerified = true
		proof.GuardAttestationSHA256 = snapshot.GuardAttestationSHA256
		proof.GuardEvidenceSHA256 = snapshot.GuardEvidenceSHA256
		proof.GuardSHA256 = snapshot.GuardSHA256
		proof.LauncherSHA256 = snapshot.LauncherSHA256
		proof.LauncherVersion = snapshot.LauncherVersion
		proof.IntegrityVerifiedAt = snapshot.VerifiedAt
	}
	data, err := json.Marshal(proof)
	if err != nil || len(data) > 16384 {
		return "", errOfficialBridgeProof0397
	}
	return string(data), nil
}

func (s Server) evaluateOfficialBridgeIntegrity0397(join bridgeJoinRecord) minecraftIntegrityDecision0135 {
	deny := func(reason string) minecraftIntegrityDecision0135 {
		return minecraftIntegrityDeny0135(true, reason, model.MinecraftSession{})
	}
	var proof model.MinecraftSession
	if join.IdentityRealm != "official" || join.MinecraftSessionID != "" ||
		len(join.OfficialProof) < 16 || len(join.OfficialProof) > 16384 || json.Unmarshal([]byte(join.OfficialProof), &proof) != nil {
		return deny("official_bridge_proof_invalid")
	}
	now := time.Now().UTC()
	expected, valid := canonicalMinecraftUUID0268(join.UUID)
	if !valid || proof.ID != "official-"+expected || proof.ProfileUUID != expected ||
		proof.UserID != join.UserID || proof.LauncherSessionID != join.SessionID ||
		proof.TrustedDeviceID != join.TrustedDeviceID || proof.BindingEpoch != join.BindingEpoch ||
		proof.Status != "active" || proof.CreatedAt.Before(join.CreatedAt.Add(-12*time.Hour)) ||
		proof.CreatedAt.After(join.CreatedAt.Add(5*time.Second)) || !proof.ExpiresAt.After(now) {
		return deny("official_bridge_proof_binding_mismatch")
	}
	// Повторная привязка к другой личности Launcher и отвязка немедленно отзывают
	// ожидающие официальные допуски, в том числе выданные на другом узле API.
	store, ok := s.officialLinkStore0268()
	if !ok {
		return deny("official_bridge_identity_store_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	links, err := store.ListOfficialLinks0268(ctx, join.UserID)
	if err != nil {
		return deny("official_bridge_identity_store_unavailable")
	}
	authorized := false
	for _, link := range links {
		if strings.EqualFold(link.MinecraftUUID, expected) && strings.EqualFold(link.MinecraftName, join.Username) {
			authorized = true
			break
		}
	}
	if !authorized {
		return deny("official_bridge_link_revoked")
	}
	return s.evaluateMinecraftIntegrity0135(proof)
}

// Непрерывный билет Windows Guard привязан к реальному запущенному процессу и
// текущему устройству Launcher. В официальном режиме нет ID MinecraftSession
// проекта/Yggdrasil: сравнивайте свидетельства артефактов с независимо проверенной
// аттестацией запуска, не создавая фиктивный локальный сеанс и не обходя политику
// Guard.
func validateOfficialContinuousGuard0397(ticket model.DeviceChallenge, proof string) error {
	var session model.MinecraftSession
	if json.Unmarshal([]byte(proof), &session) != nil || !session.IntegrityVerified ||
		ticket.CreatedAt.Before(session.CreatedAt.Add(-guardAttestationClockSkew0134)) ||
		metadataString0121(ticket.Metadata, "launcherVersion") != session.LauncherVersion ||
		!strings.EqualFold(metadataString0121(ticket.Metadata, "guardSha256"), session.GuardSHA256) ||
		!strings.EqualFold(metadataString0121(ticket.Metadata, "launcherSha256"), session.LauncherSHA256) {
		return errOfficialBridgeProof0397
	}
	return nil
}
