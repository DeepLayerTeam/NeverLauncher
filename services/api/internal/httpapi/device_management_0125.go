package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type deviceRevokeRequest0125 struct {
	Reason string `json:"reason,omitempty"`
}

type managedTrustedDevice0125 struct {
	model.TrustedDevice
	Current             bool `json:"current"`
	RevocationPermanent bool `json:"revocationPermanent"`
}

func normalizeDeviceRevokeReason0125(value, fallback string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if value == "" || len(value) > 160 || !utf8.ValidString(value) {
		return "", errors.New("revocation reason must contain 1-160 UTF-8 characters")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", errors.New("revocation reason contains control characters")
		}
	}
	return value, nil
}

func managedDeviceView0125(device model.TrustedDevice, currentDeviceID string) managedTrustedDevice0125 {
	return managedTrustedDevice0125{
		TrustedDevice:       sanitizeTrustedDevice0121(device),
		Current:             device.ID != "" && device.ID == strings.TrimSpace(currentDeviceID),
		RevocationPermanent: true,
	}
}

func currentTrustedDeviceID0125(s Server, claims authClaims) string {
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok || session.Status != "active" || session.DeviceTrustState != "verified" {
		return ""
	}
	return strings.TrimSpace(session.TrustedDeviceID)
}

func applyDeviceRevocationCascade0125(s Server, userID, deviceID, reason string, result *model.DeviceRevocationResult) int {
	if result == nil {
		return 0
	}
	if !result.CascadeHandled {
		ids := s.State.AuthSessions.revokeTrustedDevice121(userID, deviceID, reason)
		result.RevokedSessionIDs = append(result.RevokedSessionIDs, ids...)
		result.RevokedSessions += len(ids)
		result.RevokedRefreshFamilies += len(ids)
		if minecraftRepo, ok := s.Repo.(repository.MinecraftRepository); ok {
			for _, sessionID := range ids {
				result.RevokedMinecraftSessions += minecraftRepo.RevokeMinecraftSessionsByNeverSession(sessionID, reason)
			}
		}
	}
	bridgeJoins := 0
	seen := map[string]struct{}{}
	for _, sessionID := range result.RevokedSessionIDs {
		if sessionID == "" {
			continue
		}
		if _, duplicate := seen[sessionID]; duplicate {
			continue
		}
		seen[sessionID] = struct{}{}
		bridgeJoins += s.State.ServerBridge.invalidateSession(sessionID, "")
	}
	return bridgeJoins
}

func applyDeviceRevocationBatchCascade0125(s Server, userID, reason string, batch *model.DeviceRevocationBatch) int {
	if batch == nil {
		return 0
	}
	if !batch.CascadeHandled {
		for _, device := range batch.Devices {
			ids := s.State.AuthSessions.revokeTrustedDevice121(userID, device.ID, reason)
			batch.RevokedSessionIDs = append(batch.RevokedSessionIDs, ids...)
			batch.RevokedSessions += len(ids)
			batch.RevokedRefreshFamilies += len(ids)
			if minecraftRepo, ok := s.Repo.(repository.MinecraftRepository); ok {
				for _, sessionID := range ids {
					batch.RevokedMinecraftSessions += minecraftRepo.RevokeMinecraftSessionsByNeverSession(sessionID, reason)
				}
			}
		}
	}
	bridgeJoins := 0
	seen := map[string]struct{}{}
	for _, sessionID := range batch.RevokedSessionIDs {
		if sessionID == "" {
			continue
		}
		if _, duplicate := seen[sessionID]; duplicate {
			continue
		}
		seen[sessionID] = struct{}{}
		bridgeJoins += s.State.ServerBridge.invalidateSession(sessionID, "")
	}
	return bridgeJoins
}

func (s Server) authDevices0125(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && status != "active" && status != "revoked" {
		writeError(w, http.StatusBadRequest, "status должен быть active|revoked")
		return
	}
	currentDeviceID := currentTrustedDeviceID0125(s, claims)
	items := s.Repo.ListTrustedDevices(claims.Sub, status)
	views := make([]managedTrustedDevice0125, 0, len(items))
	for _, item := range items {
		views = append(views, managedDeviceView0125(item, currentDeviceID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"items": views, "count": len(views), "currentDeviceId": currentDeviceID,
		"revocation": map[string]any{"permanent": true, "reEnrollmentRequiresNewKey": true},
	}})
}

func (s Server) authDeviceRevoke0125(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req deviceRevokeRequest0125
	if r.Method == http.MethodPost && r.Body != nil && r.ContentLength != 0 {
		if err := decodeDeviceJSON0121(w, r, &req, 4<<10); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
			return
		}
	}
	reason, err := normalizeDeviceRevokeReason0125(req.Reason, "user-device-revoke")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	result, err := s.Repo.RevokeTrustedDevice(r.Context(), claims.Sub, deviceID, reason)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "устройство не найдено")
			return
		}
		writeError(w, http.StatusConflict, "не удалось отозвать устройство")
		return
	}
	bridgeJoins := applyDeviceRevocationCascade0125(s, claims.Sub, deviceID, reason, &result)
	result.Device = sanitizeTrustedDevice0121(result.Device)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:revoke", Target: deviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"device": result.Device, "alreadyRevoked": result.AlreadyRevoked,
		"revokedSessions": result.RevokedSessions, "revokedRefreshFamilies": result.RevokedRefreshFamilies,
		"revokedMinecraftSessions": result.RevokedMinecraftSessions, "invalidatedChallenges": result.InvalidatedChallenges,
		"invalidatedBridgeJoins": bridgeJoins, "reEnrollmentRequiresNewKey": true,
	}})
}

func (s Server) authDeviceRevokeOthers0125(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	currentDeviceID := currentTrustedDeviceID0125(s, claims)
	if currentDeviceID == "" {
		writeError(w, http.StatusConflict, "текущая сессия должна быть привязана к verified trusted device")
		return
	}
	current, err := s.Repo.GetTrustedDevice(claims.Sub, currentDeviceID)
	if err != nil || current.Status != "active" || current.TrustState != "verified" {
		writeError(w, http.StatusConflict, "текущее trusted device больше не активно")
		return
	}
	var req deviceRevokeRequest0125
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeDeviceJSON0121(w, r, &req, 4<<10); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
			return
		}
	}
	reason, err := normalizeDeviceRevokeReason0125(req.Reason, "user-revoke-other-devices")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	batch, err := s.Repo.RevokeOtherTrustedDevices(r.Context(), claims.Sub, currentDeviceID, reason)
	if err != nil {
		writeError(w, http.StatusConflict, "не удалось отозвать другие устройства")
		return
	}
	bridgeJoins := applyDeviceRevocationBatchCascade0125(s, claims.Sub, reason, &batch)
	views := make([]managedTrustedDevice0125, 0, len(batch.Devices))
	for _, device := range batch.Devices {
		views = append(views, managedDeviceView0125(device, currentDeviceID))
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-revoke-others-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:revoke-others", Target: currentDeviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"devices": views, "preservedDeviceId": currentDeviceID, "revokedDevices": batch.RevokedDevices,
		"revokedSessions": batch.RevokedSessions, "revokedRefreshFamilies": batch.RevokedRefreshFamilies,
		"revokedMinecraftSessions": batch.RevokedMinecraftSessions, "invalidatedChallenges": batch.InvalidatedChallenges,
		"invalidatedBridgeJoins": bridgeJoins, "reEnrollmentRequiresNewKey": true,
	}})
}

func (s Server) adminAuthDevices0125(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.URL.Query().Get("userId"))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && status != "active" && status != "revoked" {
		writeError(w, http.StatusBadRequest, "status должен быть active|revoked")
		return
	}
	items := s.Repo.ListTrustedDevices(userID, status)
	views := make([]managedTrustedDevice0125, 0, len(items))
	for _, item := range items {
		views = append(views, managedDeviceView0125(item, ""))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": views, "count": len(views)}})
}

func (s Server) adminAuthDeviceRevoke0125(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req deviceRevokeRequest0125
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeDeviceJSON0121(w, r, &req, 4<<10); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
			return
		}
	}
	reason, err := normalizeDeviceRevokeReason0125(req.Reason, "admin-device-revoke")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	existing, err := s.Repo.GetTrustedDeviceByID(deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	result, err := s.Repo.RevokeTrustedDevice(r.Context(), "", deviceID, reason)
	if err != nil {
		writeError(w, http.StatusConflict, "не удалось отозвать устройство")
		return
	}
	bridgeJoins := applyDeviceRevocationCascade0125(s, existing.UserID, deviceID, reason, &result)
	result.Device = sanitizeTrustedDevice0121(result.Device)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-admin-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:admin-revoke", Target: deviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"device": result.Device, "alreadyRevoked": result.AlreadyRevoked,
		"revokedSessions": result.RevokedSessions, "revokedRefreshFamilies": result.RevokedRefreshFamilies,
		"revokedMinecraftSessions": result.RevokedMinecraftSessions, "invalidatedChallenges": result.InvalidatedChallenges,
		"invalidatedBridgeJoins": bridgeJoins, "reEnrollmentRequiresNewKey": true,
	}})
}
