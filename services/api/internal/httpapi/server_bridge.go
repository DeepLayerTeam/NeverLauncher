package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const serverBridgeSchema910 = apiContractVersion

type bridgeServerRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	ProjectID   string    `json:"projectId"`
	ProfileID   string    `json:"profileId,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	TokenHash   string    `json:"-"`
	TokenPrefix string    `json:"tokenPrefix"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	RotatedAt   time.Time `json:"rotatedAt,omitempty"`
}

type bridgeJoinRecord struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	UUID            string    `json:"uuid"`
	UserID          string    `json:"userId"`
	SessionID       string    `json:"sessionId"`
	ServerID        string    `json:"serverId"`
	ProjectID       string    `json:"projectId"`
	ProfileID       string    `json:"profileId"`
	Channel         string    `json:"channel"`
	AccessTokenHash string    `json:"-"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type bridgeTextureRecord struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	SkinURL   string    `json:"skinUrl,omitempty"`
	CapeURL   string    `json:"capeUrl,omitempty"`
	Model     string    `json:"model"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type serverBridgeStore struct {
	mu       sync.Mutex
	servers  map[string]bridgeServerRecord
	joins    map[string]bridgeJoinRecord
	textures map[string]bridgeTextureRecord
}

type registerBridgeServerRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	ProjectID   string `json:"projectId"`
	ProfileID   string `json:"profileId"`
	Fingerprint string `json:"fingerprint"`
}

type bridgeJoinRequest struct {
	Username  string `json:"username,omitempty"`
	ServerID  string `json:"serverId"`
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
}

type bridgeHasJoinedRequest struct {
	Username string `json:"username"`
	ServerID string `json:"serverId"`
	IP       string `json:"ip,omitempty"`
}

type bridgeInvalidateRequest struct {
	ServerID string `json:"serverId,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type authlibAuthRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	ClientToken string `json:"clientToken"`
	RequestUser bool   `json:"requestUser"`
}

type authlibRefreshRequest struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ClientToken  string `json:"clientToken"`
	RequestUser  bool   `json:"requestUser"`
}

type authlibTokenRequest struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

type authlibSignoutRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authlibJoinRequest struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
	ProjectID       string `json:"projectId"`
	ProfileID       string `json:"profileId"`
	Channel         string `json:"channel"`
}

type textureUpdateRequest struct {
	SkinURL string `json:"skinUrl"`
	CapeURL string `json:"capeUrl"`
	Model   string `json:"model"`
}

func (s Server) ecosystemServerBridge(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": s.serverBridgePayload910("ecosystem")})
}

func (s Server) serverBridgeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": s.serverBridgePayload910("status")})
}

func (s Server) serverBridgeSmoke(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": s.serverBridgePayload910("smoke")})
}

func (s Server) serverBridgeServersList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "items": s.State.ServerBridge.listServers(), "summary": s.State.ServerBridge.summary()}})
}

func (s Server) serverBridgeRegister(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req registerBridgeServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	server, token, err := s.State.ServerBridge.registerServer(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.flushPersistenceState950("server-bridge-register")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("server-register"), Actor: claims.Email, Action: "serverbridge:server:register", Target: server.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "registered", "server": server, "serverToken": token, "serverTokenShownOnce": true, "usage": map[string]any{"header": "X-NeverLauncher-Server-Token", "hasJoined": "GET /api/v1/session/has-joined?username=<name>&serverId=<server>"}}})
}

func (s Server) serverBridgeRotateToken(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	serverID := strings.TrimSpace(r.PathValue("serverId"))
	server, token, err := s.State.ServerBridge.rotateToken(serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	_ = s.flushPersistenceState950("server-bridge-token-rotate")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("server-token-rotate"), Actor: claims.Email, Action: "serverbridge:server:token-rotate", Target: server.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "rotated", "server": server, "serverToken": token, "serverTokenShownOnce": true}})
}

func (s Server) sessionJoin(w http.ResponseWriter, r *http.Request) {
	claims, token, err := s.bridgeClaimsFromRequest910(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен игрока")
		return
	}
	var req bridgeJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if !s.canAccessProject(claims, req.ProjectID) {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("join-denied"), Actor: claims.Email, Action: "serverbridge:join:denied", Target: req.ProjectID + "/" + req.ProfileID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusForbidden, "нет доступа к проекту")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	join, err := s.State.ServerBridge.createJoin(user, claims.SessionID, token, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.flushPersistenceState950("server-bridge-join-created")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("join-created"), Actor: user.Email, Action: "serverbridge:session:join", Target: join.ServerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "joined", "join": sanitizeJoinRecord910(join), "expiresInSeconds": int(time.Until(join.ExpiresAt).Seconds()), "next": []string{"server calls /api/v1/session/has-joined with X-NeverLauncher-Server-Token", "server allows player only when has-joined returns status joined"}}})
}

func (s Server) sessionHasJoined(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	serverID := strings.TrimSpace(r.URL.Query().Get("serverId"))
	if r.Method == http.MethodPost {
		var req bridgeHasJoinedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			username = firstNonEmpty(req.Username, username)
			serverID = firstNonEmpty(req.ServerID, serverID)
		}
	}
	if username == "" || serverID == "" {
		writeError(w, http.StatusBadRequest, "username и serverId обязательны")
		return
	}
	server, ok := s.State.ServerBridge.verifyServerToken(serverID, bridgeServerTokenFromRequest910(r))
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-denied"), Actor: "server", Action: "serverbridge:has-joined:denied", Target: serverID + "/" + username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusUnauthorized, "server token недействителен")
		return
	}
	join, ok := s.State.ServerBridge.hasJoined(username, serverID)
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-miss"), Actor: server.ID, Action: "serverbridge:has-joined:miss", Target: username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusNotFound, "активная join-сессия не найдена")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-ok"), Actor: server.ID, Action: "serverbridge:has-joined:ok", Target: join.UUID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"id": join.UUID, "name": join.Username, "properties": []map[string]string{textureProperty910(s.State.ServerBridge.textureFor(join.UUID, join.Username))}, "neverlauncher": map[string]any{"schemaVersion": serverBridgeSchema910, "status": "joined", "projectId": join.ProjectID, "profileId": join.ProfileID, "channel": join.Channel, "serverId": join.ServerID, "expiresAt": join.ExpiresAt}})
}

func (s Server) sessionInvalidate(w http.ResponseWriter, r *http.Request) {
	claims, _, err := s.bridgeClaimsFromRequest910(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req bridgeInvalidateRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	count := s.State.ServerBridge.invalidateSession(claims.SessionID, req.ServerID)
	_ = s.flushPersistenceState950("server-bridge-session-invalidate")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("session-invalidate"), Actor: claims.Email, Action: "serverbridge:session:invalidate", Target: fmt.Sprintf("%s:%d", claims.SessionID, count), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "invalidated", "invalidated": count}})
}

func (s Server) sessionInvalidateAll(w http.ResponseWriter, r *http.Request) {
	claims, _, err := s.bridgeClaimsFromRequest910(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	count := s.State.ServerBridge.invalidateUser(claims.Sub)
	_ = s.flushPersistenceState950("server-bridge-session-invalidate-all")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("session-invalidate-all"), Actor: claims.Email, Action: "serverbridge:session:invalidate-all", Target: fmt.Sprintf("%s:%d", claims.Sub, count), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "invalidated", "invalidated": count}})
}

func (s Server) textureGet(w http.ResponseWriter, r *http.Request) {
	uuid := strings.TrimSpace(r.PathValue("uuid"))
	if uuid == "" {
		writeError(w, http.StatusBadRequest, "uuid обязателен")
		return
	}
	texture := s.State.ServerBridge.textureFor(uuid, uuid)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": textureProfile910(texture)})
}

func (s Server) textureSkinUpdate(w http.ResponseWriter, r *http.Request) {
	claims, _, err := s.bridgeClaimsFromRequest910(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req textureUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	texture := s.State.ServerBridge.updateTexture(playerUUID910(user.ID), user.Email, req)
	_ = s.flushPersistenceState950("server-bridge-texture-update")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("texture-update"), Actor: user.Email, Action: "serverbridge:texture:update", Target: texture.UUID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": textureProfile910(texture)})
}

func (s Server) authlibStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "authlib-compatible", "endpoints": []string{"authenticate", "refresh", "validate", "invalidate", "signout", "join", "hasJoined", "textures"}, "serverBridge": s.State.ServerBridge.summary()}})
}

func (s Server) authlibAuthenticate(w http.ResponseWriter, r *http.Request) {
	var req authlibAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Username))
	user, ok := s.findUserByEmail(email)
	if !ok || user.Status == "disabled" || !verifyPassword(req.Password, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: Invalid credentials")
		return
	}
	accessToken, refreshToken, session, err := s.issueLoginSession(user, r, firstNonEmpty(req.ClientToken, "authlib-client"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать authlib-сессию")
		return
	}
	profile := authlibProfile910(user)
	payload := map[string]any{"accessToken": accessToken, "clientToken": firstNonEmpty(req.ClientToken, session.ID), "availableProfiles": []map[string]string{profile}, "selectedProfile": profile, "refreshToken": refreshToken}
	if req.RequestUser {
		payload["user"] = map[string]any{"id": profile["id"], "username": user.Email, "properties": []any{}}
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("authlib-authenticate"), Actor: user.Email, Action: "authlib:authenticate", Target: session.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, payload)
}

func (s Server) authlibRefresh(w http.ResponseWriter, r *http.Request) {
	var req authlibRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.RefreshToken != "" {
		session, newRefresh, err := s.State.AuthSessions.rotate(req.RefreshToken)
		if err != nil {
			writeError(w, http.StatusForbidden, "ForbiddenOperationException: Invalid token")
			return
		}
		user, err := s.Repo.GetUser(session.UserID)
		if err != nil {
			writeError(w, http.StatusForbidden, "ForbiddenOperationException: User not found")
			return
		}
		access, err := s.issueAccessToken(user, session.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "не удалось выпустить access token")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"accessToken": access, "clientToken": firstNonEmpty(req.ClientToken, session.ID), "refreshToken": newRefresh, "selectedProfile": authlibProfile910(user)})
		return
	}
	claims, err := s.verifyAdminToken(req.AccessToken)
	if err != nil {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: Invalid token")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: User not found")
		return
	}
	access, err := s.issueAccessToken(user, claims.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить access token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accessToken": access, "clientToken": firstNonEmpty(req.ClientToken, claims.SessionID), "selectedProfile": authlibProfile910(user)})
}

func (s Server) authlibValidate(w http.ResponseWriter, r *http.Request) {
	var req authlibTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if _, err := s.verifyAdminToken(req.AccessToken); err != nil {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: Invalid token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) authlibInvalidate(w http.ResponseWriter, r *http.Request) {
	var req authlibTokenRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if claims, err := s.verifyAdminToken(req.AccessToken); err == nil {
		s.State.AuthSessions.revoke(claims.SessionID, "authlib-invalidate")
		_ = s.flushPersistenceState950("authlib-invalidate")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) authlibSignout(w http.ResponseWriter, r *http.Request) {
	var req authlibSignoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	user, ok := s.findUserByEmail(strings.ToLower(strings.TrimSpace(req.Username)))
	if !ok || !verifyPassword(req.Password, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: Invalid credentials")
		return
	}
	s.State.AuthSessions.revokeUser(user.ID, "authlib-signout")
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) authlibJoin(w http.ResponseWriter, r *http.Request) {
	var req authlibJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	claims, err := s.verifyAdminToken(req.AccessToken)
	if err != nil {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: Invalid token")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: User not found")
		return
	}
	join, err := s.State.ServerBridge.createJoin(user, claims.SessionID, req.AccessToken, bridgeJoinRequest{ServerID: req.ServerID, ProjectID: req.ProjectID, ProfileID: req.ProfileID, Channel: firstNonEmpty(req.Channel, "stable")})
	if err != nil {
		writeError(w, http.StatusForbidden, "ForbiddenOperationException: "+err.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("authlib-join"), Actor: user.Email, Action: "authlib:join", Target: join.ServerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) authlibHasJoined(w http.ResponseWriter, r *http.Request) {
	s.sessionHasJoined(w, r)
}

func (s Server) bridgeClaimsFromRequest910(r *http.Request) (authClaims, string, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return authClaims{}, "", errAuthRequired
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == header || token == "" {
		return authClaims{}, "", errAuthRequired
	}
	claims, err := s.verifyAdminToken(token)
	return claims, token, err
}

func (s Server) serverBridgePayload910(kind string) map[string]any {
	base := map[string]any{
		"schemaVersion": serverBridgeSchema910,
		"toolVersion":   s.Version,
		"release":       "NeverLauncher 0.10.0 ServerBridge & AuthBridge",
		"mode":          "minecraft-session-bridge",
		"parentMode":    "launcherops-ecosystem-platform",
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"summary":       s.State.ServerBridge.summary(),
		"endpoints": []string{
			"POST /api/v1/server-bridge/servers/register",
			"POST /api/v1/server-bridge/servers/{serverId}/rotate-token",
			"POST /api/v1/session/join",
			"GET /api/v1/session/has-joined",
			"POST /api/v1/session/invalidate",
			"POST /api/v1/auth/login",
			"POST /api/v1/session/join",
			"GET /api/v1/session/has-joined",
			"GET /api/v1/textures/{uuid}",
		},
	}
	switch kind {
	case "ecosystem":
		base["status"] = "serverbridge-ready"
		base["implemented"] = []string{"server token registration and rotation", "player session join", "server has-joined validation", "authlib-compatible authenticate/refresh/validate/invalidate/signout/join/hasJoined", "texture profile service", "join audit events"}
		base["productFlow"] = []string{"admin registers Velocity/Paper/Purpur server", "Desktop/player logs in and receives access token", "Desktop sends session join with project/profile/channel", "server plugin calls has-joined with server token", "Backend returns profile/texture metadata or denies access", "session revoke invalidates future joins"}
	case "smoke":
		base["status"] = "checkable"
		base["requiredCommands"] = []string{"go test -tags neverlauncher_nopgx ./internal/httpapi", "bash e2e/scripts/run-minecraft-e2e.sh"}
		base["checks"] = []map[string]string{{"id": "server-registration", "status": "implemented"}, {"id": "join-session", "status": "implemented"}, {"id": "has-joined", "status": "implemented"}, {"id": "authlib", "status": "implemented"}, {"id": "textures", "status": "implemented"}}
	default:
		base["status"] = "active"
	}
	return base
}

func (b *serverBridgeStore) registerServer(req registerBridgeServerRequest) (bridgeServerRecord, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		req.ID = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.Name), " ", "-"))
	}
	if req.ID == "" || strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.ProjectID) == "" {
		return bridgeServerRecord{}, "", fmt.Errorf("id/name/projectId сервера обязательны")
	}
	if req.Kind == "" {
		req.Kind = "velocity"
	}
	token := randomBridgeToken910("nlsrv")
	server := bridgeServerRecord{ID: req.ID, Name: strings.TrimSpace(req.Name), Kind: strings.ToLower(strings.TrimSpace(req.Kind)), ProjectID: strings.TrimSpace(req.ProjectID), ProfileID: strings.TrimSpace(req.ProfileID), Fingerprint: strings.TrimSpace(req.Fingerprint), TokenHash: tokenHash910(token), TokenPrefix: tokenPrefix910(token), Status: "active", CreatedAt: now}
	if existing, ok := b.servers[server.ID]; ok {
		server.CreatedAt = existing.CreatedAt
		server.RotatedAt = now
	}
	b.servers[server.ID] = server
	return server, token, nil
}

func (b *serverBridgeStore) rotateToken(serverID string) (bridgeServerRecord, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return bridgeServerRecord{}, "", fmt.Errorf("server bridge record not found")
	}
	token := randomBridgeToken910("nlsrv")
	server.TokenHash = tokenHash910(token)
	server.TokenPrefix = tokenPrefix910(token)
	server.RotatedAt = time.Now().UTC()
	b.servers[server.ID] = server
	return server, token, nil
}

func (b *serverBridgeStore) listServers() []bridgeServerRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	items := make([]bridgeServerRecord, 0, len(b.servers))
	for _, item := range b.servers {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (b *serverBridgeStore) verifyServerToken(serverID, token string) (bridgeServerRecord, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok || server.Status != "active" || token == "" {
		return bridgeServerRecord{}, false
	}
	return server, server.TokenHash == tokenHash910(token)
}

func validMinecraftUsername910(value string) bool {
	if len(value) < 3 || len(value) > 16 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func minecraftUsernameFromAccount910(email, userID string) string {
	base := strings.TrimSpace(strings.SplitN(email, "@", 2)[0])
	var b strings.Builder
	for _, ch := range base {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			b.WriteRune(ch)
		}
	}
	value := b.String()
	if len(value) > 16 {
		value = value[:16]
	}
	if len(value) >= 3 {
		return value
	}
	suffix := strings.ReplaceAll(strings.TrimSpace(userID), "-", "")
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	value = "NL_" + suffix
	if len(value) > 16 {
		value = value[:16]
	}
	if len(value) < 3 {
		return "NL_Player"
	}
	return value
}

func (b *serverBridgeStore) createJoin(user model.User, sessionID, accessToken string, req bridgeJoinRequest) (bridgeJoinRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.TrimSpace(req.ServerID) == "" || strings.TrimSpace(req.ProjectID) == "" || strings.TrimSpace(req.ProfileID) == "" {
		return bridgeJoinRecord{}, fmt.Errorf("serverId, projectId и profileId обязательны")
	}
	server, ok := b.servers[req.ServerID]
	if !ok || server.Status != "active" {
		return bridgeJoinRecord{}, fmt.Errorf("server bridge record не найден или не активен")
	}
	if server.ProjectID != "" && server.ProjectID != req.ProjectID {
		return bridgeJoinRecord{}, fmt.Errorf("server не привязан к projectId %s", req.ProjectID)
	}
	if server.ProfileID != "" && server.ProfileID != req.ProfileID {
		return bridgeJoinRecord{}, fmt.Errorf("server не привязан к profileId %s", req.ProfileID)
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = minecraftUsernameFromAccount910(user.Email, user.ID)
	}
	if !validMinecraftUsername910(username) {
		return bridgeJoinRecord{}, fmt.Errorf("username должен соответствовать Minecraft Java: 3-16 символов A-Z, a-z, 0-9 или _")
	}
	now := time.Now().UTC()
	uuid := playerUUID910(user.ID)
	join := bridgeJoinRecord{ID: "join-" + randomSuffix910(8), Username: username, UUID: uuid, UserID: user.ID, SessionID: sessionID, ServerID: req.ServerID, ProjectID: req.ProjectID, ProfileID: req.ProfileID, Channel: firstNonEmpty(req.Channel, "stable"), AccessTokenHash: tokenHash910(accessToken), Status: "active", CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	b.joins[b.joinKey(username, req.ServerID)] = join
	b.textures[uuid] = b.textureForLocked(uuid, username)
	return join, nil
}

func (b *serverBridgeStore) hasJoined(username, serverID string) (bridgeJoinRecord, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	join, ok := b.joins[b.joinKey(username, serverID)]
	if !ok || join.Status != "active" || join.ExpiresAt.Before(time.Now().UTC()) {
		return bridgeJoinRecord{}, false
	}
	return join, true
}

func (b *serverBridgeStore) invalidateSession(sessionID, serverID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for key, join := range b.joins {
		if join.SessionID == sessionID && (serverID == "" || join.ServerID == serverID) && join.Status == "active" {
			join.Status = "invalidated"
			b.joins[key] = join
			count++
		}
	}
	return count
}

func (b *serverBridgeStore) invalidateUser(userID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for key, join := range b.joins {
		if join.UserID == userID && join.Status == "active" {
			join.Status = "invalidated"
			b.joins[key] = join
			count++
		}
	}
	return count
}

func (b *serverBridgeStore) updateTexture(uuid, username string, req textureUpdateRequest) bridgeTextureRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	modelName := strings.TrimSpace(req.Model)
	if modelName == "" {
		modelName = "classic"
	}
	texture := bridgeTextureRecord{UUID: uuid, Username: username, SkinURL: strings.TrimSpace(req.SkinURL), CapeURL: strings.TrimSpace(req.CapeURL), Model: modelName, UpdatedAt: time.Now().UTC()}
	b.textures[uuid] = texture
	return texture
}

func (b *serverBridgeStore) textureFor(uuid, username string) bridgeTextureRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.textureForLocked(uuid, username)
}

func (b *serverBridgeStore) textureForLocked(uuid, username string) bridgeTextureRecord {
	if texture, ok := b.textures[uuid]; ok {
		return texture
	}
	return bridgeTextureRecord{UUID: uuid, Username: username, Model: "classic", UpdatedAt: time.Now().UTC()}
}

func (b *serverBridgeStore) summary() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	activeJoins := 0
	for _, join := range b.joins {
		if join.Status == "active" && join.ExpiresAt.After(time.Now().UTC()) {
			activeJoins++
		}
	}
	return map[string]any{"servers": len(b.servers), "activeJoins": activeJoins, "textures": len(b.textures), "joinTtlSeconds": 120, "serverToken": "required-for-has-joined"}
}

func (b *serverBridgeStore) joinKey(username, serverID string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "@" + strings.TrimSpace(serverID)
}

func sanitizeJoinRecord910(join bridgeJoinRecord) map[string]any {
	return map[string]any{"id": join.ID, "username": join.Username, "uuid": join.UUID, "userId": join.UserID, "sessionId": join.SessionID, "serverId": join.ServerID, "projectId": join.ProjectID, "profileId": join.ProfileID, "channel": join.Channel, "status": join.Status, "createdAt": join.CreatedAt, "expiresAt": join.ExpiresAt}
}

func bridgeServerTokenFromRequest910(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-NeverLauncher-Server-Token")); token != "" {
		return token
	}
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	return ""
}

func playerUUID910(seed string) string {
	sum := sha256.Sum256([]byte("neverlauncher-player:" + seed))
	hexed := hex.EncodeToString(sum[:16])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

func authlibProfile910(user model.User) map[string]string {
	return map[string]string{"id": playerUUID910(user.ID), "name": user.Email}
}

func textureProperty910(texture bridgeTextureRecord) map[string]string {
	payload := textureProfile910(texture)
	encoded, _ := json.Marshal(payload)
	return map[string]string{"name": "textures", "value": base64.StdEncoding.EncodeToString(encoded)}
}

func textureProfile910(texture bridgeTextureRecord) map[string]any {
	textures := map[string]any{}
	if texture.SkinURL != "" {
		textures["SKIN"] = map[string]any{"url": texture.SkinURL, "metadata": map[string]string{"model": texture.Model}}
	}
	if texture.CapeURL != "" {
		textures["CAPE"] = map[string]any{"url": texture.CapeURL}
	}
	return map[string]any{"schemaVersion": serverBridgeSchema910, "timestamp": time.Now().UTC().UnixMilli(), "profileId": texture.UUID, "profileName": texture.Username, "textures": textures}
}

func randomBridgeToken910(prefix string) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return prefix + "_" + time.Now().UTC().Format("20060102150405") + randomSuffix910(8)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buf)
}

func randomSuffix910(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func tokenHash910(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func tokenPrefix910(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}

func bridgeAuditID910(kind string) string {
	return "serverbridge-" + kind + "-" + time.Now().UTC().Format("20060102150405") + "-" + randomSuffix910(3)
}
