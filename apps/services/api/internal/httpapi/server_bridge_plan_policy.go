package httpapi

import (
	"encoding/hex"
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/planpolicy02412"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const planProofDomain02412 = "Launcher-Verified-Component-Plan-v1"
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
		writeError(w, http.StatusUnauthorized, "Необходима сессия игрока")
		return
	}
	if !planPolicyRequired02412() {
		writeError(w, http.StatusPreconditionFailed, "Политика проверенного плана отключена")
		return
	}
	policy, err := loadPlanPolicy02412(time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Подписанная политика плана недоступна")
		return
	}
	var req planChallengeRequest02412
	if err = decodeDeviceJSON0121(w, r, &req, 4096); err != nil {
		writeError(w, http.StatusBadRequest, "Некорректный запрос проверки плана")
		return
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if !s.canAccessProject(claims, req.ProjectID) || req.ServerID == "" || req.ProfileID == "" {
		writeError(w, http.StatusForbidden, "Доступ к проекту, профилю или серверу запрещён")
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
		writeError(w, http.StatusForbidden, "Для сервера, профиля и канала отсутствует подписанная политика плана")
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, claims.Sub, claims.SessionID, claims.TrustedDeviceID, claims.BindingEpoch, true)
	if !trust.Allowed {
		writeError(w, http.StatusForbidden, "Для проверенного плана необходимо доверенное устройство")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, claims.TrustedDeviceID)
	if err != nil || device.KeyAlgorithm != "p256" || device.KeyBinding != "hardware" {
		writeError(w, http.StatusForbidden, "Требуется аппаратно привязанный ключ устройства")
		return
	}
	challengeID, err := randomToken("plcid")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось получить случайные данные для проверки")
		return
	}
	secret, err := randomToken("plc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось получить случайные данные для проверки")
		return
	}
	now := canonicalGuardAttestationTime0134(time.Now().UTC())
	record := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: claims.TrustedDeviceID, Purpose: planChallengePurpose02412, ChallengeHash: deviceChallengeHash0121(secret),
		Metadata: map[string]any{"sessionId": claims.SessionID, "bindingEpoch": strconv.FormatInt(claims.BindingEpoch, 10), "serverId": req.ServerID, "projectId": req.ProjectID, "profileId": req.ProfileID, "channel": req.Channel, "policyEpoch": strconv.FormatUint(policy.Epoch, 10)}, CreatedAt: now, ExpiresAt: now.Add(60 * time.Second)}
	if err = s.Repo.SaveDeviceChallenge(r.Context(), record); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Сохранение запроса проверки плана недоступно")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"challengeId": challengeID, "challenge": secret, "expiresAt": record.ExpiresAt, "policyEpoch": policy.Epoch}})
}

// Вычисляйте до создания одноразового билета входа. Погашение challenge — атомарная
// операция репозитория, в том числе при многоузловом PostgreSQL.
func (s Server) verifyPlanForJoin02412(r *http.Request, claims authClaims, req bridgeJoinRequest, guardTicket model.DeviceChallenge) error {
	policy, err := loadPlanPolicy02412(time.Now().UTC())
	if err != nil {
		return err
	}
	e := req.PlanEvidence
	if e == nil {
		return errors.New("Требуется: «verified component plan evidence»")
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if e.UserID != claims.Sub || e.SessionID != claims.SessionID || e.DeviceID != claims.TrustedDeviceID || e.BindingEpoch != claims.BindingEpoch || e.ServerID != req.ServerID || e.ProjectID != req.ProjectID || e.ProfileID != req.ProfileID || e.Channel != req.Channel {
		return errors.New("Несовпадение: «verified component plan session, trusted device or target»")
	}
	if !isHexLength02412(e.ReleaseSignature, 128) || !isHexLength02412(e.CatalogDigest, 64) || !isHexLength02412(e.PlanSHA256, 64) || !isHexLength02412(e.GuardAttestationSHA256, 64) {
		return errors.New("Некорректный формат: «signed component plan measurements»")
	}
	if !planMatches02412(policy, e.ServerID, e.ProjectID, e.ProfileID, e.Channel, e.ReleaseSignature, e.CatalogDigest, e.PlanSHA256) {
		return errors.New("Подписанная политика запрещает рассчитанный план компонентов")
	}
	// Для этого релиза необходима только что завершённая непрерывная аттестация Guard v2. Одного
	// списка модов, хеша плана или подписи P-256 от пользователя НИКОГДА недостаточно.
	if guardTicket.ID == "" || metadataString0121(guardTicket.Metadata, "attestationSha256") != e.GuardAttestationSHA256 {
		return errors.New("Проверенный план не привязан к текущим доказательствам Continuous Guard")
	}
	if e.ChallengeID == "" || e.Challenge == "" || len(e.Challenge) > 160 || len(e.ChallengeID) > 160 || strings.ContainsAny(planEvidencePayload02412(*e), "\r") {
		return errors.New("Некорректное значение: «verified plan challenge»")
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, claims.TrustedDeviceID)
	if err != nil || device.KeyAlgorithm != "p256" || device.KeyBinding != "hardware" {
		return errors.New("Недоступно: «hardware device identity»")
	}
	key, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || key.fingerprint != device.KeyFingerprint {
		return errors.New("Некорректное значение: «device proof key binding»")
	}
	if err = verifyDeviceSignature0123(key, planEvidencePayload02412(*e), e.Signature); err != nil {
		return errors.New("Некорректное значение: «verified plan device proof signature»")
	}
	consumed, err := s.Repo.ConsumeDeviceChallenge(r.Context(), e.ChallengeID, claims.Sub, claims.TrustedDeviceID, planChallengePurpose02412, deviceChallengeHash0121(e.Challenge), time.Now().UTC())
	if err != nil {
		return errors.New("Проверочная задача подтверждённого плана просрочена или использована повторно")
	}
	if metadataString0121(consumed.Metadata, "sessionId") != claims.SessionID || metadataString0121(consumed.Metadata, "bindingEpoch") != strconv.FormatInt(claims.BindingEpoch, 10) || metadataString0121(consumed.Metadata, "serverId") != req.ServerID || metadataString0121(consumed.Metadata, "projectId") != req.ProjectID || metadataString0121(consumed.Metadata, "profileId") != req.ProfileID || metadataString0121(consumed.Metadata, "channel") != req.Channel || metadataString0121(consumed.Metadata, "policyEpoch") != strconv.FormatUint(policy.Epoch, 10) {
		return errors.New("Обнаружено изменение: «verified plan challenge binding/policy epoch»")
	}
	return nil
}

// Подписанная политика, активированная после выдачи билета, делает его
// недействительным. Это также закрывает окно развёртывания, когда старый билет
// входа создавался до включения REQUIRE_PLAN_POLICY.
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
		return errors.New("Билет подключения создан до активной политики проверенного плана")
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
