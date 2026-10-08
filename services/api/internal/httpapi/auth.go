package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/authorization"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type authClaims struct {
	Iss                        string   `json:"iss"`
	Aud                        string   `json:"aud"`
	JTI                        string   `json:"jti"`
	Sub                        string   `json:"sub"`
	Email                      string   `json:"email"`
	RoleID                     string   `json:"roleId"`
	SessionID                  string   `json:"sid"`
	TokenUse                   string   `json:"tokenUse"`
	Permissions                []string `json:"permissions"`
	Iat                        int64    `json:"iat"`
	AuthTime                   int64    `json:"auth_time"`
	AuthMethods                []string `json:"amr"`
	AuthStrength               string   `json:"authStrength"`
	TrustedDeviceID            string   `json:"device_id,omitempty"`
	DeviceTrustState           string   `json:"device_trust,omitempty"`
	DeviceVerifiedAt           int64    `json:"device_verified_at,omitempty"`
	DeviceKeyBinding           string   `json:"device_key_binding,omitempty"`
	DeviceHardwareProvider     string   `json:"device_hardware_provider,omitempty"`
	DeviceAttestationState     string   `json:"device_attestation,omitempty"`
	DeviceAttestationMethod    string   `json:"device_attestation_method,omitempty"`
	DeviceAttestedAt           int64    `json:"device_attested_at,omitempty"`
	DeviceAttestationExpiresAt int64    `json:"device_attestation_expires_at,omitempty"`
	BindingEpoch               int64    `json:"binding_epoch"`
	RiskState                  string   `json:"risk_state,omitempty"`
	RiskScore                  int      `json:"risk_score,omitempty"`
	RiskAction                 string   `json:"risk_action,omitempty"`
	RiskUpdatedAt              int64    `json:"risk_updated_at,omitempty"`
	Exp                        int64    `json:"exp"`
}

var errAuthRequired = errors.New("требуется авторизация")

func (s Server) requireAuthenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.verifyAdminTokenFromRequest(r); err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		next(w, r)
	})
}

func (s Server) hasAnyProjectPermission(r *http.Request, claims authClaims, permission string) bool {
	if s.authorizeClaims(r, claims, permission, "", "global", "").Allowed {
		return true
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		return false
	}
	for projectID := range user.ProjectRoles {
		if s.authorizeClaims(r, claims, permission, projectID, "project", projectID).Allowed {
			return true
		}
	}
	return false
}

func (s Server) requireAnyProjectPermission(permission string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		if !s.hasAnyProjectPermission(r, claims, permission) {
			writeError(w, http.StatusForbidden, "нет доступных проектов с требуемым правом")
			return
		}
		next(w, r)
	})
}

func (s Server) requirePermission(permission string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		decision := s.authorizeClaims(r, claims, permission, "", "global", "")
		if !decision.Allowed {
			writeError(w, http.StatusForbidden, "недостаточно глобальных прав для выполнения операции")
			return
		}
		next(w, r)
	})
}

func (s Server) authorizationService() *authorization.Service {
	if s.Authorization != nil {
		return s.Authorization
	}
	return authorization.New(s.Repo)
}

func (s Server) authorizeClaims(r *http.Request, claims authClaims, action, projectID, resourceKind, resourceID string) authorization.Decision {
	scope := authorization.Scope{Kind: authorization.ScopeGlobal}
	if strings.TrimSpace(projectID) != "" {
		scope = authorization.Scope{Kind: authorization.ScopeProject, ProjectID: strings.TrimSpace(projectID)}
	}
	ctx := r.Context()
	return s.authorizationService().Authorize(ctx, authorization.Actor{Kind: authorization.ActorUser, ID: claims.Sub}, action, scope, authorization.Resource{Kind: resourceKind, ID: resourceID, ProjectID: strings.TrimSpace(projectID)})
}

func (s Server) requireProjectPermission(permission, projectParam, resourceKind string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		projectID := strings.TrimSpace(r.PathValue(projectParam))
		if projectID == "" {
			writeError(w, http.StatusBadRequest, "projectId обязателен")
			return
		}
		resourceID := projectID
		for _, param := range []string{"profileId", "channelId", "versionId", "fileId"} {
			if value := strings.TrimSpace(r.PathValue(param)); value != "" {
				resourceID = value
				break
			}
		}
		if !s.authorizeClaims(r, claims, permission, projectID, resourceKind, resourceID).Allowed {
			writeError(w, http.StatusForbidden, "недостаточно прав в проекте")
			return
		}
		next(w, r)
	})
}

func (s Server) requireServerBridgePermission(permission string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		serverID := strings.TrimSpace(r.PathValue("serverId"))
		if s.State == nil || s.State.ServerBridge == nil {
			writeError(w, http.StatusServiceUnavailable, "serverbridge недоступен")
			return
		}
		node, err := s.State.ServerBridge.getNode0142(serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
			return
		}
		decision := s.authorizeClaims(r, claims, permission, node.ProjectID, "server", serverID)
		if !decision.Allowed {
			writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
			return
		}
		next(w, r)
	})
}

func (s Server) requirePackagePermission(permission string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		lookup, err := s.lookupPackage(r.PathValue("packageId"))
		if err != nil {
			writeError(w, http.StatusNotFound, "package не найден")
			return
		}
		if !s.authorizeClaims(r, claims, permission, lookup.Release.ProjectID, "package", lookup.Release.ID).Allowed {
			// Делать не reveal пакет existence через проект границы.
			writeError(w, http.StatusNotFound, "package не найден")
			return
		}
		next(w, r)
	})
}

func (s Server) authorizeProjectAction(w http.ResponseWriter, r *http.Request, claims authClaims, permission, projectID, resourceKind, resourceID string) bool {
	if strings.TrimSpace(projectID) == "" {
		writeError(w, http.StatusBadRequest, "projectId обязателен")
		return false
	}
	if !s.authorizeClaims(r, claims, permission, projectID, resourceKind, resourceID).Allowed {
		writeError(w, http.StatusForbidden, "недостаточно прав в проекте")
		return false
	}
	return true
}

func (s Server) issueLoginSession(user model.User, r *http.Request, deviceID string) (string, string, authSessionRecord, error) {
	return s.issueLoginSessionWithAuth(user, r, deviceID, []string{"password"}, "single-factor", time.Now().UTC(), "", "local")
}

func (s Server) issueLoginSessionWithAuth(user model.User, r *http.Request, deviceID string, methods []string, strength string, authTime time.Time, identityID, provider string) (string, string, authSessionRecord, error) {
	session, refreshToken, err := s.State.AuthSessions.createWithAuth(user, r, deviceID, methods, strength, authTime, identityID, provider)
	if err != nil {
		return "", "", authSessionRecord{}, err
	}
	_ = s.flushPersistenceState950("auth-session-create")
	accessToken, err := s.issueAccessTokenForSession(user, session)
	if err != nil {
		return "", "", authSessionRecord{}, err
	}
	return accessToken, refreshToken, session, nil
}

func (s Server) issueAccessToken(user model.User, sessionID string) (string, error) {
	session, ok := s.State.AuthSessions.get(sessionID, user.ID)
	if !ok {
		return "", errAuthRequired
	}
	return s.issueAccessTokenForSession(user, session)
}

func (s Server) issueAccessTokenForSession(user model.User, session authSessionRecord) (string, error) {
	now := time.Now().UTC()
	claims := authClaims{
		Sub:              user.ID,
		Email:            user.Email,
		RoleID:           user.RoleID,
		SessionID:        session.ID,
		TokenUse:         "access",
		Permissions:      s.permissionsForRole(user.RoleID),
		Iat:              now.Unix(),
		AuthTime:         session.AuthTime.Unix(),
		AuthMethods:      append([]string(nil), session.AuthMethods...),
		AuthStrength:     session.AuthStrength,
		TrustedDeviceID:  session.TrustedDeviceID,
		DeviceTrustState: firstNonEmpty(session.DeviceTrustState, "unverified"),
		BindingEpoch:     session.BindingEpoch,
		RiskState:        normalizeRiskState118(session.RiskState),
		RiskScore:        session.RiskScore,
		RiskAction:       firstNonEmpty(session.RiskAction, "allow"),
		Exp:              now.Add(accessTokenTTL).Unix(),
	}
	if !session.DeviceVerifiedAt.IsZero() {
		claims.DeviceVerifiedAt = session.DeviceVerifiedAt.Unix()
	}
	if !session.RiskUpdatedAt.IsZero() {
		claims.RiskUpdatedAt = session.RiskUpdatedAt.Unix()
	}
	// keyBinding/provider оставаться informational: запрос-ответ аттестация доказывает
	// possession/freshness регистрировать ключ, не поставщик TPM/Защищённый Анклав происхождение.
	// Устройство аттестация захватывает являются diagnostic и должен не elevate RBAC/MFA сила.
	if session.TrustedDeviceID != "" {
		if device, err := s.Repo.GetTrustedDevice(user.ID, session.TrustedDeviceID); err == nil && device.Status == "active" {
			claims.DeviceKeyBinding = device.KeyBinding
			claims.DeviceHardwareProvider = device.HardwareProvider
			state, _ := effectiveDeviceAttestation0124(device, now)
			claims.DeviceAttestationState = state
			if state == "verified" {
				claims.DeviceAttestationMethod = device.AttestationMethod
				claims.DeviceAttestedAt = device.AttestedAt.Unix()
				claims.DeviceAttestationExpiresAt = device.AttestationExpiresAt.Unix()
			}
		}
	}
	return s.encodeAccessToken118(claims)
}

func (s Server) verifyAdminTokenFromRequest(r *http.Request) (authClaims, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return authClaims{}, errAuthRequired
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == header {
		return authClaims{}, errAuthRequired
	}
	claims, err := s.verifyAdminToken(token)
	if err != nil {
		return authClaims{}, err
	}
	session, ok := s.State.AuthSessions.observe(claims.SessionID, claims.Sub, r)
	if !ok {
		return authClaims{}, errAuthRequired
	}
	session, err = s.reconcileSessionDeviceRisk0126(r, session)
	if err != nil {
		return authClaims{}, errAuthRequired
	}
	if !sessionBindingClaimsMatch0126(claims, session) {
		return authClaims{}, errAuthRequired
	}
	claims.RiskState = normalizeRiskState118(session.RiskState)
	claims.RiskScore = session.RiskScore
	claims.RiskAction = firstNonEmpty(session.RiskAction, "allow")
	if !session.RiskUpdatedAt.IsZero() {
		claims.RiskUpdatedAt = session.RiskUpdatedAt.Unix()
	}
	return claims, nil
}

func (s Server) verifyAdminToken(token string) (authClaims, error) {
	claims, err := s.decodeAccessToken118(token)
	if err != nil {
		return authClaims{}, errAuthRequired
	}
	if claims.AuthStrength == "" {
		claims.AuthStrength = "single-factor"
	}
	if claims.AuthTime == 0 {
		claims.AuthTime = claims.Iat
	}
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok || normalizeRiskState118(session.RiskState) == "compromised" || firstNonEmpty(session.RiskAction, "allow") == "revoke" {
		return authClaims{}, errAuthRequired
	}
	if !sessionBindingClaimsMatch0126(claims, session) {
		return authClaims{}, errAuthRequired
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || strings.TrimSpace(user.Status) != "active" {
		return authClaims{}, errAuthRequired
	}
	return claims, nil
}

func (s Server) findUserByEmail(email string) (model.User, bool) {
	user, err := s.Repo.GetUserByEmail(email)
	return user, err == nil
}

func hashPassword(password string) string {
	encoded, err := hashPasswordArgon2id(password)
	if err != nil {
		// В рабочий ошибка Argon2ID должна останавливать создание/смену пароля.
		// Сигнатура старого Репозиторий interface не возвращает ошибку, поэтому
		// оставляем явный panic вместо тихого возврата слабого SHA-256.
		panic(err)
	}
	return encoded
}

func verifyPassword(password, encoded string) bool {
	if encoded == "" {
		return false
	}
	if strings.HasPrefix(encoded, "$argon2id$") {
		return verifyPasswordArgon2id(password, encoded)
	}
	// Миграционная совместимость с пользователями, созданными до 5.0.1.
	// Новые пароли всегда сохраняются в Argon2ID/PHC формате.
	if strings.HasPrefix(encoded, "sha256:") {
		sum := sha256.Sum256([]byte(password))
		legacy := "sha256:" + hex.EncodeToString(sum[:])
		return hmac.Equal([]byte(legacy), []byte(encoded))
	}
	return false
}

func (s Server) canAccessProject(claims authClaims, projectID string) bool {
	if strings.TrimSpace(projectID) == "" {
		return false
	}
	return s.authorizationService().Authorize(
		context.Background(),
		authorization.Actor{Kind: authorization.ActorUser, ID: claims.Sub},
		"project:read",
		authorization.Scope{Kind: authorization.ScopeProject, ProjectID: projectID},
		authorization.Resource{Kind: "project", ID: projectID, ProjectID: projectID},
	).Allowed
}

func (s Server) permissionsForRole(roleID string) []string {
	for _, role := range s.Repo.ListRoles() {
		if role.ID == roleID {
			return append([]string(nil), role.Permissions...)
		}
	}
	return []string{}
}

func (s Server) adminActor(r *http.Request) string {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil || claims.Email == "" {
		return "unknown"
	}
	return claims.Email
}

func (s Server) adminClaims(r *http.Request) (authClaims, error) {
	return s.verifyAdminTokenFromRequest(r)
}

func signPayload(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
