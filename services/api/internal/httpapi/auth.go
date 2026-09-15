package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type authClaims struct {
	Sub         string   `json:"sub"`
	Email       string   `json:"email"`
	RoleID      string   `json:"roleId"`
	SessionID   string   `json:"sid"`
	TokenUse    string   `json:"tokenUse"`
	Permissions []string `json:"permissions"`
	Exp         int64    `json:"exp"`
}

var errAuthRequired = errors.New("требуется авторизация")

func (s Server) requirePermission(permission string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		if !claims.HasPermission(permission) {
			writeError(w, http.StatusForbidden, "недостаточно прав для выполнения операции")
			return
		}
		next(w, r)
	})
}

func (s Server) issueLoginSession(user model.User, r *http.Request, deviceID string) (string, string, authSessionRecord, error) {
	session, refreshToken, err := s.State.AuthSessions.create(user, r, deviceID)
	if err != nil {
		return "", "", authSessionRecord{}, err
	}
	_ = s.flushPersistenceState950("auth-session-create")
	accessToken, err := s.issueAccessToken(user, session.ID)
	if err != nil {
		return "", "", authSessionRecord{}, err
	}
	return accessToken, refreshToken, session, nil
}

func (s Server) issueAccessToken(user model.User, sessionID string) (string, error) {
	claims := authClaims{
		Sub:         user.ID,
		Email:       user.Email,
		RoleID:      user.RoleID,
		SessionID:   sessionID,
		TokenUse:    "access",
		Permissions: s.permissionsForRole(user.RoleID),
		Exp:         time.Now().UTC().Add(accessTokenTTL).Unix(),
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := signPayload(payload, s.Config.AuthTokenSecret)
	return payload + "." + signature, nil
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
	return s.verifyAdminToken(token)
}

func (s Server) verifyAdminToken(token string) (authClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return authClaims{}, errAuthRequired
	}
	expected := signPayload(parts[0], s.Config.AuthTokenSecret)
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return authClaims{}, errAuthRequired
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return authClaims{}, err
	}
	var claims authClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return authClaims{}, err
	}
	if claims.Exp <= time.Now().UTC().Unix() || claims.TokenUse != "access" || claims.SessionID == "" {
		return authClaims{}, errAuthRequired
	}
	if !s.State.AuthSessions.active(claims.SessionID, claims.Sub) {
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
		// В production ошибка Argon2id должна останавливать создание/смену пароля.
		// Сигнатура старого Repository interface не возвращает ошибку, поэтому
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
	// Новые пароли всегда сохраняются в Argon2id/PHC формате.
	if strings.HasPrefix(encoded, "sha256:") {
		sum := sha256.Sum256([]byte(password))
		legacy := "sha256:" + hex.EncodeToString(sum[:])
		return hmac.Equal([]byte(legacy), []byte(encoded))
	}
	return false
}

func (s Server) canAccessProject(claims authClaims, projectID string) bool {
	if projectID == "" || claims.HasPermission("*") {
		return true
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		return false
	}
	roleID := user.ProjectRoles[projectID]
	if roleID == "" {
		return false
	}
	for _, perm := range s.permissionsForRole(roleID) {
		if perm == "*" || perm == "project:read" || perm == "project:write" {
			return true
		}
	}
	return false
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

func (c authClaims) HasPermission(permission string) bool {
	for _, item := range c.Permissions {
		if item == "*" || item == permission {
			return true
		}
	}
	return false
}

func signPayload(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
