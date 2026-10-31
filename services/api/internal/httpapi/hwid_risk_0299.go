package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

var hwidSignalHex0299 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type hwidObserveRequest0299 struct {
	Signal string `json:"signal"`
}
type hwidAppealRequest0299 struct {
	Reason string `json:"reason"`
}
type hwidResolveRequest0299 struct {
	Decision string `json:"decision"`
}

// The desktop transmits an *already locally hashed* machine continuity hint.
// HMAC prevents correlation between Never users and makes a database leak
// insufficient for offline matching against known machine IDs. The secret must
// be consistent across all API replicas (the validated AuthTokenSecret).
func hwidAccountDigest0299(secret, userID, signal string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("Launcher HWID risk v1\x00"))
	h.Write([]byte(userID))
	h.Write([]byte{'\x00'})
	h.Write([]byte(signal))
	return hex.EncodeToString(h.Sum(nil))
}

func (s Server) currentHWIDDevice0299(r *http.Request) (authClaims, string, repository.HWIDStore0299, int) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		return authClaims{}, "", nil, http.StatusUnauthorized
	}
	store, ok := s.Repo.(repository.HWIDStore0299)
	if !ok {
		return authClaims{}, "", nil, http.StatusServiceUnavailable
	}
	// An observed signal can only modify the current verified device; never a
	// supplied arbitrary device id or a different user's HWID.
	rec, valid := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !valid || rec.TrustedDeviceID == "" || rec.DeviceTrustState != "verified" {
		return authClaims{}, "", nil, http.StatusPreconditionRequired
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, rec.TrustedDeviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" {
		return authClaims{}, "", nil, http.StatusPreconditionRequired
	}
	return claims, rec.TrustedDeviceID, store, 0
}

func (s Server) authHWIDObserve0299(w http.ResponseWriter, r *http.Request) {
	claims, deviceID, store, status := s.currentHWIDDevice0299(r)
	if status != 0 {
		writeError(w, status, "требуется действующая сессия на подтверждённом устройстве")
		return
	}
	var req hwidObserveRequest0299
	if err := decodeDeviceJSON0121(w, r, &req, 2048); err != nil || !hwidSignalHex0299.MatchString(req.Signal) {
		writeError(w, http.StatusBadRequest, "ожидается локально вычисленный SHA-256 сигнал")
		return
	}
	now := time.Now().UTC()
	digest := hwidAccountDigest0299(s.Config.AuthTokenSecret, claims.Sub, req.Signal)
	obs, err := store.ObserveHWID0299(r.Context(), claims.Sub, deviceID, digest, now)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "не удалось сохранить HWID-наблюдение")
		return
	}
	if obs.State == "changed" {
		s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth:hwid:changed", Target: deviceID, ReasonCode: "hwid-signal-changed", CreatedAt: now})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": repository.PublicHWIDState0299(obs)})
}
func (s Server) authHWIDStatus0299(w http.ResponseWriter, r *http.Request) {
	claims, deviceID, store, status := s.currentHWIDDevice0299(r)
	if status != 0 {
		writeError(w, status, "требуется действующая сессия на подтверждённом устройстве")
		return
	}
	obs, err := store.GetHWID0299(r.Context(), claims.Sub, deviceID, time.Now().UTC())
	if errors.Is(err, repository.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"deviceId": deviceID, "state": "not-observed", "signalIsProofOfIdentity": false, "automaticBan": false}})
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "состояние HWID временно недоступно")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": repository.PublicHWIDState0299(obs)})
}
func (s Server) authHWIDConfirm0299(w http.ResponseWriter, r *http.Request) {
	claims, deviceID, store, status := s.currentHWIDDevice0299(r)
	if status != 0 {
		writeError(w, status, "требуется действующая сессия на подтверждённом устройстве")
		return
	}
	// Re-baselining a changed machine requires independent local proof. This
	// never converts a HWID hint into proof of identity or unbans an account.
	if !freshAuth117(claims, "phishing-resistant", 5*time.Minute) {
		writeStepUpRequired117(w, "phishing-resistant")
		return
	}
	obs, err := store.ConfirmHWID0299(r.Context(), claims.Sub, deviceID, time.Now().UTC())
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusConflict, "нет актуального изменения оборудования")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "не удалось подтвердить новое оборудование")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth:hwid:confirmed", Target: deviceID, ReasonCode: "fresh-phishing-resistant-auth", CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": repository.PublicHWIDState0299(obs)})
}
func (s Server) authHWIDForget0299(w http.ResponseWriter, r *http.Request) {
	claims, deviceID, store, status := s.currentHWIDDevice0299(r)
	if status != 0 {
		writeError(w, status, "требуется действующая сессия на подтверждённом устройстве")
		return
	}
	if err := store.ForgetHWID0299(r.Context(), claims.Sub, deviceID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "не удалось удалить HWID-наблюдения")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth:hwid:forgotten", Target: deviceID, CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"state": "not-observed"}})
}
func publicHWIDAppeal0299(a repository.HWIDAppeal0299) map[string]any {
	return map[string]any{"id": a.ID, "userId": a.UserID, "deviceId": a.DeviceID, "reason": a.Reason, "status": a.Status, "resolution": a.Resolution, "actor": a.Actor, "createdAt": a.CreatedAt, "updatedAt": a.UpdatedAt}
}
func (s Server) authHWIDAppeal0299(w http.ResponseWriter, r *http.Request) {
	claims, deviceID, store, status := s.currentHWIDDevice0299(r)
	if status != 0 {
		writeError(w, status, "требуется действующая сессия на подтверждённом устройстве")
		return
	}
	var req hwidAppealRequest0299
	if err := decodeDeviceJSON0121(w, r, &req, 2048); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len([]rune(req.Reason)) < 8 || len([]rune(req.Reason)) > 500 {
		writeError(w, http.StatusBadRequest, "причина должна содержать 8–500 символов")
		return
	}
	id, err := randomToken("hwa")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать обращение")
		return
	}
	now := time.Now().UTC()
	a := repository.HWIDAppeal0299{ID: id, UserID: claims.Sub, DeviceID: deviceID, Reason: req.Reason, Status: "pending", CreatedAt: now, UpdatedAt: now}
	if err := store.SubmitHWIDAppeal0299(r.Context(), a); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "отсутствует изменение либо обращение уже ожидает решения")
		} else {
			writeError(w, http.StatusServiceUnavailable, "не удалось сохранить обращение")
		}
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth:hwid:appeal", Target: deviceID, ReasonCode: "hardware-change", CreatedAt: now})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": publicHWIDAppeal0299(a)})
}
func (s Server) authHWIDAppeals0299(w http.ResponseWriter, r *http.Request) {
	claims, _, store, status := s.currentHWIDDevice0299(r)
	if status != 0 {
		writeError(w, status, "требуется действующая сессия на подтверждённом устройстве")
		return
	}
	appeals, err := store.ListHWIDAppeals0299(r.Context(), claims.Sub)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "не удалось получить обращения")
		return
	}
	out := make([]any, 0, len(appeals))
	for _, a := range appeals {
		out = append(out, publicHWIDAppeal0299(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": out}})
}
func (s Server) adminHWIDAppeals0299(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.HWIDStore0299)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "HWID store отсутствует")
		return
	}
	appeals, err := store.ListHWIDAppeals0299(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "не удалось получить обращения")
		return
	}
	out := make([]any, 0, len(appeals))
	for _, a := range appeals {
		out = append(out, publicHWIDAppeal0299(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": out}})
}
func (s Server) adminHWIDResolve0299(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительная сессия")
		return
	}
	store, ok := s.Repo.(repository.HWIDStore0299)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "HWID store отсутствует")
		return
	}
	var req hwidResolveRequest0299
	if err := decodeDeviceJSON0121(w, r, &req, 2048); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.Decision != "approved" && req.Decision != "rejected" {
		writeError(w, http.StatusBadRequest, "decision должен быть approved|rejected")
		return
	}
	a, err := store.ResolveHWIDAppeal0299(r.Context(), strings.TrimSpace(r.PathValue("appealId")), claims.Sub, req.Decision, time.Now().UTC())
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "обращение не найдено")
		return
	}
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, http.StatusConflict, "обращение уже обработано или наблюдение изменилось")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "обращение не обработано")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth:hwid:appeal:" + req.Decision, Target: a.DeviceID, ReasonCode: "operator-review", CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": publicHWIDAppeal0299(a)})
}
