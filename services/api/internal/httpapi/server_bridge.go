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
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const serverBridgeSchema910 = apiContractVersion
const serverBridgeProtocolV2 = 2

type bridgeServerRecord struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Kind                string    `json:"kind"`
	ProjectID           string    `json:"projectId"`
	ProfileID           string    `json:"profileId,omitempty"`
	Fingerprint         string    `json:"fingerprint,omitempty"`
	TokenHash           string    `json:"-"`
	TokenPrefix         string    `json:"-"`
	KeyAlgorithm        string    `json:"keyAlgorithm"`
	PublicKey           string    `json:"-"`
	KeyFingerprint      string    `json:"keyFingerprint"`
	IdentityEpoch       int64     `json:"identityEpoch"`
	IdentityRotatedAt   time.Time `json:"identityRotatedAt,omitempty"`
	Status              string    `json:"status"`
	PluginVersion       string    `json:"pluginVersion,omitempty"`
	PluginSHA256        string    `json:"pluginSha256,omitempty"`
	IntegrityStatus     string    `json:"integrityStatus,omitempty"`
	IntegrityVerifiedAt time.Time `json:"integrityVerifiedAt,omitempty"`
	LastHeartbeatAt     time.Time `json:"lastHeartbeatAt,omitempty"`
	ProtocolVersion     int       `json:"protocolVersion"`
	CreatedAt           time.Time `json:"createdAt"`
	RotatedAt           time.Time `json:"rotatedAt,omitempty"`
}

type bridgeJoinRecord struct {
	ID                     string    `json:"id"`
	TicketVersion          int       `json:"ticketVersion"`
	Username               string    `json:"username"`
	UUID                   string    `json:"uuid"`
	UserID                 string    `json:"userId"`
	SessionID              string    `json:"sessionId"`
	ServerID               string    `json:"serverId"`
	ProjectID              string    `json:"projectId"`
	ProfileID              string    `json:"profileId"`
	Channel                string    `json:"channel"`
	AccessTokenHash        string    `json:"-"`
	TrustedDeviceID        string    `json:"trustedDeviceId,omitempty"`
	BindingEpoch           int64     `json:"bindingEpoch"`
	MinecraftSessionID     string    `json:"minecraftSessionId,omitempty"`
	ProtocolVersion        int       `json:"protocolVersion"`
	IssuedIdentityEpoch    int64     `json:"issuedIdentityEpoch"`
	IssuedKeyFingerprint   string    `json:"issuedKeyFingerprint"`
	Status                 string    `json:"status"`
	CreatedAt              time.Time `json:"createdAt"`
	ExpiresAt              time.Time `json:"expiresAt"`
	ConsumedAt             time.Time `json:"consumedAt,omitempty"`
	RedeemedIdentityEpoch  int64     `json:"redeemedIdentityEpoch,omitempty"`
	RedeemedKeyFingerprint string    `json:"redeemedKeyFingerprint,omitempty"`
	RedeemedNonceHash      string    `json:"redeemedNonceHash,omitempty"`
	RedeemedByIP           string    `json:"redeemedByIp,omitempty"`
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
	mu         sync.Mutex
	servers    map[string]bridgeServerRecord
	joins      map[string]bridgeJoinRecord
	textures   map[string]bridgeTextureRecord
	nodeNonces map[string]time.Time
	backend    repository.ServerBridgeRepository
}

type registerBridgeServerRequest struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	ProjectID    string `json:"projectId"`
	ProfileID    string `json:"profileId"`
	Fingerprint  string `json:"fingerprint"`
	KeyAlgorithm string `json:"keyAlgorithm"`
	PublicKey    string `json:"publicKey"`
}

type rotateBridgeIdentityRequest struct {
	KeyAlgorithm string `json:"keyAlgorithm"`
	PublicKey    string `json:"publicKey"`
}

type bridgeJoinRequest struct {
	Username             string `json:"username,omitempty"`
	ServerID             string `json:"serverId"`
	ProjectID            string `json:"projectId"`
	ProfileID            string `json:"profileId"`
	Channel              string `json:"channel"`
	MinecraftAccessToken string `json:"minecraftAccessToken,omitempty"`
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
	server, err := s.State.ServerBridge.registerServer(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.flushPersistenceState950("server-bridge-register")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("server-register"), Actor: claims.Email, Action: "serverbridge:server:register", Target: server.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{
		"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "registered", "server": server,
		"nodeIdentity": map[string]any{"keyAlgorithm": server.KeyAlgorithm, "keyFingerprint": server.KeyFingerprint, "identityEpoch": server.IdentityEpoch},
		"usage":        map[string]any{"authentication": "Ed25519 signed request headers", "privateKey": "remains on the ServerBridge node and is never sent to Backend"},
	}})
}

func (s Server) serverBridgeRotateIdentity(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	serverID := strings.TrimSpace(r.PathValue("serverId"))
	var req rotateBridgeIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	server, err := s.State.ServerBridge.rotateIdentity(serverID, req)
	if err != nil {
		if isBridgeNotFoundV2(err) {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	_ = s.flushPersistenceState950("server-bridge-identity-rotate")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("server-identity-rotate"), Actor: claims.Email, Action: "serverbridge:server:identity-rotate", Target: server.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "identity-rotated", "server": server, "nodeIdentity": map[string]any{"keyAlgorithm": server.KeyAlgorithm, "keyFingerprint": server.KeyFingerprint, "identityEpoch": server.IdentityEpoch}}})
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
	_, trust := s.evaluateGameplayTrust0127(r, claims.Sub, claims.SessionID, claims.TrustedDeviceID, claims.BindingEpoch, true)
	if !trust.Allowed {
		s.writeGameplayTrustRequirement0127(w, trust)
		return
	}
	minecraftSession, err := s.requireMinecraftIntegrityForBridgeSession0135(claims.Sub, claims.SessionID, trust.TrustedDeviceID, trust.BindingEpoch, req.MinecraftAccessToken)
	if err != nil {
		writeError(w, http.StatusPreconditionFailed, err.Error())
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	if minecraftSession.ID != "" {
		profile, profileErr := s.minecraftRepo119()
		if profileErr == nil {
			if minecraftProfile, getErr := profile.GetMinecraftProfileByUUID(minecraftSession.ProfileUUID); getErr == nil && req.Username != "" && !strings.EqualFold(req.Username, minecraftProfile.Name) {
				writeError(w, http.StatusPreconditionFailed, "username не совпадает с integrity-verified Minecraft profile")
				return
			}
		}
	}
	join, err := s.State.ServerBridge.createJoin(user, claims.SessionID, token, trust.TrustedDeviceID, trust.BindingEpoch, minecraftSession.ID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.flushPersistenceState950("server-bridge-join-created")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("join-created"), Actor: user.Email, Action: "serverbridge:session:join", Target: join.ServerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": map[string]any{"schemaVersion": serverBridgeSchema910, "toolVersion": s.Version, "status": "joined", "oneTime": true, "ticketId": join.ID, "ticketVersion": join.TicketVersion, "join": sanitizeJoinRecord910(join), "expiresInSeconds": int(time.Until(join.ExpiresAt).Seconds()), "next": []string{"server redeems this authorization exactly once with its signed Protocol v2 request", "a replay, expired ticket, or rotated node identity is denied"}}})
}

func (s Server) sessionHasJoined(w http.ResponseWriter, r *http.Request) {
	server, authErr := s.authenticateBridgeNodeRequest0142(r)
	if authErr != nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-denied-identity"), Actor: "server", Action: "serverbridge:has-joined:identity-denied", Target: strings.TrimSpace(r.URL.Query().Get("serverId")), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeBridgeNodeAuthError0142(w, authErr)
		return
	}
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
	if server.ID != serverID {
		writeError(w, http.StatusForbidden, "serverbridge_node_server_id_mismatch")
		return
	}
	bridgeIntegrity := s.evaluateRegisteredBridgeIntegrity0135(server)
	if !bridgeIntegrity.Allowed {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-bridge-integrity-denied"), Actor: server.ID, Action: "serverbridge:has-joined:bridge-integrity-denied", Target: username + ":" + bridgeIntegrity.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusPreconditionFailed, "server bridge integrity denied join: "+bridgeIntegrity.Reason)
		return
	}
	join, ok := s.State.ServerBridge.hasJoined(username, serverID)
	if !ok {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-miss"), Actor: server.ID, Action: "serverbridge:has-joined:miss", Target: username, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusNotFound, "активная join-сессия не найдена")
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, join.UserID, join.SessionID, join.TrustedDeviceID, join.BindingEpoch, true)
	if !trust.Allowed {
		if gameplayTrustPermanentFailure0127(trust.Reason) {
			s.State.ServerBridge.invalidateJoin(username, serverID)
			_ = s.flushPersistenceState950("server-bridge-trust-invalidate")
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-trust-denied"), Actor: server.ID, Action: "serverbridge:has-joined:trust-denied", Target: join.UUID + ":" + trust.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusForbidden, "trust policy denied join: "+trust.Reason)
		return
	}
	_, integrity := s.evaluateServerBridgeJoinIntegrity0135(join)
	if !integrity.Allowed {
		if minecraftIntegrityPermanentFailure0135(integrity.Reason) || integrity.Reason == "minecraft_integrity_session_required" || integrity.Reason == "minecraft_integrity_binding_mismatch" {
			s.State.ServerBridge.invalidateJoin(username, serverID)
			_ = s.flushPersistenceState950("server-bridge-integrity-invalidate")
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-integrity-denied"), Actor: server.ID, Action: "serverbridge:has-joined:integrity-denied", Target: join.UUID + ":" + integrity.Reason, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusForbidden, "integrity policy denied join: "+integrity.Reason)
		return
	}
	redemption, redemptionErr := bridgeJoinRedemption0143(r, server)
	if redemptionErr != nil {
		writeError(w, http.StatusServiceUnavailable, "serverbridge_join_redemption_proof_unavailable")
		return
	}
	consumed, consumedOK := s.State.ServerBridge.consumeJoinV2(join, redemption)
	if !consumedOK {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-replay"), Actor: server.ID, Action: "serverbridge:has-joined:replay-denied", Target: join.UUID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusConflict, "join ticket уже использован")
		return
	}
	join = consumed
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("has-joined-ok"), Actor: server.ID, Action: "serverbridge:has-joined:ok", Target: join.UUID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"id": join.UUID, "name": join.Username, "properties": []map[string]string{textureProperty910(s.State.ServerBridge.textureFor(join.UUID, join.Username))}, "neverlauncher": map[string]any{"schemaVersion": serverBridgeSchema910, "protocolVersion": serverBridgeProtocolV2, "status": "joined", "projectId": join.ProjectID, "profileId": join.ProfileID, "channel": join.Channel, "serverId": join.ServerID, "nodeKeyFingerprint": server.KeyFingerprint, "identityEpoch": server.IdentityEpoch, "expiresAt": join.ExpiresAt, "trust": trust, "integrity": integrity}})
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
	texture, err := s.State.ServerBridge.updateTexture(playerUUID910(user.ID), user.Email, req)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "ServerBridge texture state не сохранён")
		return
	}
	_ = s.flushPersistenceState950("server-bridge-texture-update")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("texture-update"), Actor: user.Email, Action: "serverbridge:texture:update", Target: texture.UUID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": serverBridgeSchema910, "data": textureProfile910(texture)})
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
	claims, err := s.verifyAdminTokenFromRequest(r)
	return claims, token, err
}

func (s Server) serverBridgePayload910(kind string) map[string]any {
	base := map[string]any{
		"schemaVersion": serverBridgeSchema910,
		"toolVersion":   s.Version,
		"release":       "NeverLauncher 0.14.3 One-Time Join Tickets",
		"mode":          "serverbridge-protocol-v2",
		"parentMode":    "launcherops-ecosystem-platform",
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"summary":       s.State.ServerBridge.summary(),
		"endpoints": []string{
			"POST /api/v1/server-bridge/servers/register",
			"POST /api/v1/server-bridge/servers/{serverId}/rotate-identity",
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
		base["implemented"] = []string{"PostgreSQL source of truth", "Protocol v2 node identity", "Ed25519 signed node requests", "PostgreSQL nonce replay protection", "one-time atomic join tickets", "identity-bound one-time join tickets", "atomic redemption proof persistence", "consume-once Yggdrasil joins", "cryptographic identity enrollment and rotation", "player session join", "server has-joined validation", "authlib-compatible authenticate/refresh/validate/invalidate/signout/join/hasJoined", "live session/device/risk trust enforcement", "binding-epoch credential invalidation", "texture profile service", "join audit events"}
		base["trustPolicy"] = gameplayTrustPolicy0127
		base["trustEnforcement"] = "required"
		base["productFlow"] = []string{"node generates a local Ed25519 key and admin enrolls its public key in PostgreSQL", "Desktop/player logs in and binds a verified trusted device", "Desktop sends session join with project/profile/channel and Backend snapshots device binding", "server plugin signs validate-join/has-joined with its local Ed25519 private key", "Backend re-checks parent session, device, binding epoch and risk policy", "Backend returns profile/texture metadata or a concrete trust denial", "re-bind/revoke/permanent risk invalidates stale gameplay credentials"}
	case "smoke":
		base["status"] = "checkable"
		base["requiredCommands"] = []string{"go test -tags neverlauncher_nopgx ./internal/httpapi", "bash e2e/scripts/run-minecraft-e2e.sh"}
		base["checks"] = []map[string]string{{"id": "protocol-v2", "status": "implemented"}, {"id": "postgresql-source-of-truth", "status": "implemented"}, {"id": "one-time-join-consume", "status": "implemented"}, {"id": "identity-bound-ticket", "status": "implemented"}, {"id": "yggdrasil-consume-once", "status": "implemented"}, {"id": "cryptographic-node-identity", "status": "implemented"}, {"id": "node-nonce-replay-protection", "status": "implemented"}, {"id": "server-registration", "status": "implemented"}, {"id": "join-session", "status": "implemented"}, {"id": "has-joined", "status": "implemented"}, {"id": "authlib", "status": "implemented"}, {"id": "gameplay-trust-enforcement", "status": "implemented"}, {"id": "binding-epoch-invalidation", "status": "implemented"}, {"id": "textures", "status": "implemented"}}
	default:
		base["status"] = "active"
	}
	return base
}

func (b *serverBridgeStore) registerServer(req registerBridgeServerRequest) (bridgeServerRecord, error) {
	now := time.Now().UTC()
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		req.ID = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.Name), " ", "-"))
	}
	if req.ID == "" || strings.TrimSpace(req.ProjectID) == "" {
		return bridgeServerRecord{}, fmt.Errorf("id и projectId сервера обязательны")
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = req.ID
	}
	if req.Kind == "" {
		req.Kind = "velocity"
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if !validBridgeServerKindV2(kind) {
		return bridgeServerRecord{}, fmt.Errorf("kind должен быть velocity, bungeecord, waterfall, bukkit, spigot, paper, purpur, folia или fabric")
	}
	algorithm, publicKey, keyFingerprint, err := validateBridgeNodeIdentity0142(req.KeyAlgorithm, req.PublicKey)
	if err != nil {
		return bridgeServerRecord{}, err
	}
	server := bridgeServerRecord{
		ID: req.ID, Name: strings.TrimSpace(req.Name), Kind: kind, ProjectID: strings.TrimSpace(req.ProjectID), ProfileID: strings.TrimSpace(req.ProfileID),
		Fingerprint: strings.TrimSpace(req.Fingerprint), KeyAlgorithm: algorithm, PublicKey: publicKey, KeyFingerprint: keyFingerprint,
		IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: serverBridgeProtocolV2, CreatedAt: now,
	}
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		if _, err := backend.GetServerBridgeNode(ctx, server.ID); err == nil {
			return bridgeServerRecord{}, fmt.Errorf("ServerBridge node уже зарегистрирован; используйте rotate-identity")
		} else if !isBridgeNotFoundV2(err) {
			return bridgeServerRecord{}, err
		}
		stored, err := backend.SaveServerBridgeNode(ctx, bridgeServerToModelV2(server))
		if err != nil {
			return bridgeServerRecord{}, err
		}
		return bridgeServerFromModelV2(stored), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.servers[server.ID]; ok {
		return bridgeServerRecord{}, fmt.Errorf("ServerBridge node уже зарегистрирован; используйте rotate-identity")
	}
	for _, existing := range b.servers {
		if existing.KeyFingerprint == server.KeyFingerprint {
			return bridgeServerRecord{}, fmt.Errorf("этот node public key уже зарегистрирован")
		}
	}
	b.servers[server.ID] = server
	return server, nil
}

func (b *serverBridgeStore) rotateIdentity(serverID string, req rotateBridgeIdentityRequest) (bridgeServerRecord, error) {
	algorithm, publicKey, fingerprint, err := validateBridgeNodeIdentity0142(req.KeyAlgorithm, req.PublicKey)
	if err != nil {
		return bridgeServerRecord{}, err
	}
	now := time.Now().UTC()
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		current, err := backend.GetServerBridgeNode(ctx, strings.TrimSpace(serverID))
		if err != nil {
			return bridgeServerRecord{}, err
		}
		if current.KeyFingerprint != "" && current.KeyFingerprint == fingerprint {
			return bridgeServerRecord{}, fmt.Errorf("новый public key должен отличаться от текущей node identity")
		}
		server, err := backend.RotateServerBridgeNodeIdentity(ctx, strings.TrimSpace(serverID), algorithm, publicKey, fingerprint, now)
		if err != nil {
			return bridgeServerRecord{}, err
		}
		return bridgeServerFromModelV2(server), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	server, ok := b.servers[serverID]
	if !ok {
		return bridgeServerRecord{}, repository.ErrNotFound
	}
	if server.KeyFingerprint != "" && server.KeyFingerprint == fingerprint {
		return bridgeServerRecord{}, fmt.Errorf("новый public key должен отличаться от текущей node identity")
	}
	for id, existing := range b.servers {
		if id != serverID && existing.KeyFingerprint == fingerprint {
			return bridgeServerRecord{}, fmt.Errorf("этот node public key уже зарегистрирован")
		}
	}
	server.TokenHash = ""
	server.TokenPrefix = ""
	server.KeyAlgorithm = algorithm
	server.PublicKey = publicKey
	server.KeyFingerprint = fingerprint
	server.IdentityEpoch++
	if server.IdentityEpoch < 1 {
		server.IdentityEpoch = 1
	}
	server.IdentityRotatedAt = now
	server.Status = "active"
	server.ProtocolVersion = serverBridgeProtocolV2
	server.PluginVersion = ""
	server.PluginSHA256 = ""
	server.IntegrityStatus = ""
	server.IntegrityVerifiedAt = time.Time{}
	server.LastHeartbeatAt = time.Time{}
	b.servers[server.ID] = server
	for key := range b.nodeNonces {
		if strings.HasPrefix(key, server.ID+":") {
			delete(b.nodeNonces, key)
		}
	}
	for key, join := range b.joins {
		if join.ServerID == server.ID && join.Status == "active" {
			join.Status = "invalidated"
			b.joins[key] = join
		}
	}
	return server, nil
}

func (b *serverBridgeStore) listServers() []bridgeServerRecord {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		items, err := backend.ListServerBridgeNodes(ctx)
		if err != nil {
			return nil
		}
		out := make([]bridgeServerRecord, 0, len(items))
		for _, v := range items {
			out = append(out, bridgeServerFromModelV2(v))
		}
		return out
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	items := make([]bridgeServerRecord, 0, len(b.servers))
	for _, item := range b.servers {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
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

func (b *serverBridgeStore) createJoin(user model.User, sessionID, accessToken, trustedDeviceID string, bindingEpoch int64, minecraftSessionID string, req bridgeJoinRequest) (bridgeJoinRecord, error) {
	if strings.TrimSpace(req.ServerID) == "" || strings.TrimSpace(req.ProjectID) == "" || strings.TrimSpace(req.ProfileID) == "" {
		return bridgeJoinRecord{}, fmt.Errorf("serverId, projectId и profileId обязательны")
	}
	var server bridgeServerRecord
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		node, err := backend.GetServerBridgeNode(ctx, req.ServerID)
		if err != nil {
			return bridgeJoinRecord{}, fmt.Errorf("server bridge record не найден или не активен")
		}
		server = bridgeServerFromModelV2(node)
	} else {
		b.mu.Lock()
		server = b.servers[req.ServerID]
		b.mu.Unlock()
	}
	if server.ID == "" || server.Status != "active" {
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
	if bindingEpoch < 1 {
		bindingEpoch = 1
	}
	if server.IdentityEpoch < 1 || len(server.KeyFingerprint) != 64 {
		return bridgeJoinRecord{}, fmt.Errorf("server bridge node cryptographic identity is not enrolled")
	}
	ticketID, err := newServerBridgeJoinTicketID0143()
	if err != nil {
		return bridgeJoinRecord{}, err
	}
	join := bridgeJoinRecord{ID: ticketID, TicketVersion: serverBridgeJoinTicketVersion0143, Username: username, UUID: uuid, UserID: user.ID, SessionID: sessionID, ServerID: req.ServerID, ProjectID: req.ProjectID, ProfileID: req.ProfileID, Channel: firstNonEmpty(req.Channel, "stable"), AccessTokenHash: tokenHash910(accessToken), TrustedDeviceID: strings.TrimSpace(trustedDeviceID), BindingEpoch: bindingEpoch, MinecraftSessionID: strings.TrimSpace(minecraftSessionID), ProtocolVersion: serverBridgeProtocolV2, IssuedIdentityEpoch: server.IdentityEpoch, IssuedKeyFingerprint: server.KeyFingerprint, Status: "active", CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		stored, err := backend.CreateServerBridgeJoinTicket(ctx, bridgeJoinToModelV2(join))
		if err != nil {
			return bridgeJoinRecord{}, err
		}
		return bridgeJoinFromModelV2(stored), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Keep the in-memory dev/test path aligned with PostgreSQL: identity rotation
	// between the initial lookup and ticket insertion must fail closed rather than
	// minting a ticket bound to a retired key epoch.
	current := b.servers[req.ServerID]
	if current.ID == "" || current.Status != "active" || current.IdentityEpoch != server.IdentityEpoch ||
		!strings.EqualFold(current.KeyFingerprint, server.KeyFingerprint) {
		return bridgeJoinRecord{}, fmt.Errorf("server bridge node identity changed while issuing join ticket")
	}
	b.joins[b.joinKey(username, req.ServerID)] = join
	b.textures[uuid] = b.textureForLocked(uuid, username)
	return join, nil
}

func (b *serverBridgeStore) hasJoined(username, serverID string) (bridgeJoinRecord, bool) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		j, err := backend.GetActiveServerBridgeJoinTicket(ctx, username, serverID, time.Now().UTC())
		if err != nil {
			return bridgeJoinRecord{}, false
		}
		return bridgeJoinFromModelV2(j), true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	join, ok := b.joins[b.joinKey(username, serverID)]
	if !ok || join.Status != "active" || join.ExpiresAt.Before(time.Now().UTC()) {
		return bridgeJoinRecord{}, false
	}
	return join, true
}

func (b *serverBridgeStore) invalidateJoin(username, serverID string) bool {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		j, err := backend.GetActiveServerBridgeJoinTicket(ctx, username, serverID, time.Now().UTC())
		if err != nil {
			return false
		}
		ok, err := backend.InvalidateServerBridgeJoinTicket(ctx, j.ID, time.Now().UTC())
		return err == nil && ok
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := b.joinKey(username, serverID)
	join, ok := b.joins[key]
	if !ok || join.Status != "active" {
		return false
	}
	join.Status = "invalidated"
	b.joins[key] = join
	return true
}

func (b *serverBridgeStore) invalidateSession(sessionID, serverID string) int {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		n, err := backend.InvalidateServerBridgeSession(ctx, sessionID, serverID, time.Now().UTC())
		if err != nil {
			return 0
		}
		return n
	}
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
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		n, err := backend.InvalidateServerBridgeUser(ctx, userID, time.Now().UTC())
		if err != nil {
			return 0
		}
		return n
	}
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

func (b *serverBridgeStore) updateTexture(uuid, username string, req textureUpdateRequest) (bridgeTextureRecord, error) {
	modelName := strings.TrimSpace(req.Model)
	if modelName == "" {
		modelName = "classic"
	}
	if modelName != "classic" && modelName != "slim" {
		modelName = "classic"
	}
	texture := bridgeTextureRecord{UUID: uuid, Username: username, SkinURL: strings.TrimSpace(req.SkinURL), CapeURL: strings.TrimSpace(req.CapeURL), Model: modelName, UpdatedAt: time.Now().UTC()}
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		stored, err := backend.SaveServerBridgeTexture(ctx, bridgeTextureToModelV2(texture))
		if err != nil {
			return bridgeTextureRecord{}, err
		}
		return bridgeTextureFromModelV2(stored), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.textures[uuid] = texture
	return texture, nil
}

func (b *serverBridgeStore) textureFor(uuid, username string) bridgeTextureRecord {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		t, err := backend.GetServerBridgeTexture(ctx, uuid)
		if err == nil {
			return bridgeTextureFromModelV2(t)
		}
		return bridgeTextureRecord{UUID: uuid, Username: username, Model: "classic", UpdatedAt: time.Now().UTC()}
	}
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
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		summary, err := backend.ServerBridgeSummary(ctx, time.Now().UTC())
		if err == nil {
			return summary
		}
		return map[string]any{"protocolVersion": 2, "sourceOfTruth": "postgresql", "status": "unavailable"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	activeJoins := 0
	for _, join := range b.joins {
		if join.Status == "active" && join.ExpiresAt.After(time.Now().UTC()) {
			activeJoins++
		}
	}
	return map[string]any{"servers": len(b.servers), "activeJoins": activeJoins, "textures": len(b.textures), "joinTtlSeconds": 120, "nodeAuthentication": "ed25519-signed-requests", "replayProtection": "memory-single-use-nonce", "protocolVersion": 2, "sourceOfTruth": "memory-dev-test"}
}

func (b *serverBridgeStore) joinKey(username, serverID string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "@" + strings.TrimSpace(serverID)
}

func sanitizeJoinRecord910(join bridgeJoinRecord) map[string]any {
	return map[string]any{"id": join.ID, "ticketVersion": join.TicketVersion, "username": join.Username, "uuid": join.UUID, "serverId": join.ServerID, "projectId": join.ProjectID, "profileId": join.ProfileID, "channel": join.Channel, "protocolVersion": join.ProtocolVersion, "issuedIdentityEpoch": join.IssuedIdentityEpoch, "issuedKeyFingerprint": join.IssuedKeyFingerprint, "status": join.Status, "oneTime": true, "createdAt": join.CreatedAt, "expiresAt": join.ExpiresAt}
}

func playerUUID910(seed string) string {
	sum := sha256.Sum256([]byte("neverlauncher-player:" + seed))
	hexed := hex.EncodeToString(sum[:16])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
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

func validBridgeServerKindV2(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia", "fabric":
		return true
	default:
		return false
	}
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

func bridgeAuditID910(kind string) string {
	return "serverbridge-" + kind + "-" + time.Now().UTC().Format("20060102150405") + "-" + randomSuffix910(3)
}
