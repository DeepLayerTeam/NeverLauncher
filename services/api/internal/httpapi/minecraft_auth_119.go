package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

const minecraftSessionTTL119 = 24 * time.Hour
const minecraftJoinTTL119 = 2 * time.Minute

type minecraftSessionRequest119 struct {
	ClientToken            string `json:"clientToken,omitempty"`
	GuardAttestationTicket string `json:"guardAttestationTicket"`
}

type yggdrasilAuthenticateRequest119 struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientToken  string `json:"clientToken,omitempty"`
	RequestUser  bool   `json:"requestUser,omitempty"`
	ProviderID   string `json:"providerId,omitempty"`
	TOTP         string `json:"totp,omitempty"`
	RecoveryCode string `json:"recoveryCode,omitempty"`
}

type yggdrasilRefreshRequest119 struct {
	AccessToken     string `json:"accessToken"`
	ClientToken     string `json:"clientToken,omitempty"`
	RequestUser     bool   `json:"requestUser,omitempty"`
	SelectedProfile *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"selectedProfile,omitempty"`
}

type yggdrasilTokenRequest119 struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken,omitempty"`
}

type yggdrasilSignoutRequest119 struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	ProviderID string `json:"providerId,omitempty"`
}

type yggdrasilJoinRequest119 struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

func (s Server) minecraftRepo119() (repository.MinecraftRepository, error) {
	repo, ok := s.Repo.(repository.MinecraftRepository)
	if !ok {
		return nil, errors.New("minecraft repository is unavailable")
	}
	return repo, nil
}

func minecraftUUID119(userID string) string {
	sum := sha256.Sum256([]byte("neverlauncher:minecraft-profile:v2:" + strings.TrimSpace(userID)))
	b := append([]byte(nil), sum[:16]...)
	b[6] = (b[6] & 0x0f) | 0x80 // RFC 9562 UUIDv8/custom name-derived UUID.
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func minecraftID119(uuid string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(uuid)), "-", "")
}

func minecraftName119(user model.User) string {
	for _, raw := range []string{user.DisplayName, strings.SplitN(user.Email, "@", 2)[0], user.ID} {
		var b strings.Builder
		for _, ch := range raw {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
				b.WriteRune(ch)
			}
		}
		v := b.String()
		if len(v) > 16 {
			v = v[:16]
		}
		if len(v) >= 3 {
			return v
		}
	}
	return "NL_Player"
}

func (s Server) ensureMinecraftProfile119(user model.User) (model.MinecraftProfile, error) {
	repo, err := s.minecraftRepo119()
	if err != nil {
		return model.MinecraftProfile{}, err
	}
	if item, err := repo.GetMinecraftProfileByUser(user.ID); err == nil {
		return item, nil
	}
	base := minecraftName119(user)
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			suffix := fmt.Sprintf("_%x", sha256.Sum256([]byte(user.ID+fmt.Sprint(i))))[:5]
			cut := 16 - len(suffix)
			if cut < 3 {
				cut = 3
			}
			if len(base) > cut {
				name = base[:cut] + suffix
			} else {
				name = base + suffix
			}
		}
		if existing, err := repo.GetMinecraftProfileByName(name); err == nil && existing.UserID != user.ID {
			continue
		}
		profile, err := repo.SaveMinecraftProfile(model.MinecraftProfile{UserID: user.ID, UUID: minecraftUUID119(user.ID), Name: name})
		if err == nil {
			return profile, nil
		}
		// Another instance may have created either this user's profile or the
		// same case-insensitive name between our lookup and INSERT. Resolve the
		// winner and retry only the name conflict; do not hide other DB errors.
		if existing, getErr := repo.GetMinecraftProfileByUser(user.ID); getErr == nil {
			return existing, nil
		}
		if existing, getErr := repo.GetMinecraftProfileByName(name); getErr == nil && existing.UserID != user.ID {
			continue
		}
		return model.MinecraftProfile{}, err
	}
	return model.MinecraftProfile{}, fmt.Errorf("unable to allocate unique Minecraft profile name")
}

func (s Server) issueMinecraftSession119(user model.User, neverSessionID, clientToken string) (model.MinecraftSession, string, model.MinecraftProfile, error) {
	parentSession, ok := s.State.AuthSessions.get(neverSessionID, user.ID)
	if !ok {
		return model.MinecraftSession{}, "", model.MinecraftProfile{}, errAuthRequired
	}
	if parentSession.BindingEpoch < 1 {
		parentSession.BindingEpoch = 1
	}
	return s.issueMinecraftSessionWithTrust119(user, neverSessionID, clientToken, parentSession.TrustedDeviceID, parentSession.BindingEpoch)
}

// issueMinecraftSessionWithTrust119 persists the exact device/binding snapshot
// that was already authorized by the caller. It never "upgrades" a request to
// a newer concurrent binding: if a re-bind wins before this check, issuance
// fails; if it wins after this check, the persisted old snapshot is rejected by
// the next live trust evaluation. This closes a token-issuance TOCTOU window.
func (s Server) issueMinecraftSessionWithTrust119(user model.User, neverSessionID, clientToken, trustedDeviceID string, bindingEpoch int64) (model.MinecraftSession, string, model.MinecraftProfile, error) {
	return s.issueMinecraftSessionWithTrustAndIntegrity119(user, neverSessionID, clientToken, trustedDeviceID, bindingEpoch, nil)
}

func (s Server) issueMinecraftSessionWithTrustAndIntegrity119(user model.User, neverSessionID, clientToken, trustedDeviceID string, bindingEpoch int64, integrity *minecraftIntegritySnapshot0135) (model.MinecraftSession, string, model.MinecraftProfile, error) {
	repo, err := s.minecraftRepo119()
	if err != nil {
		return model.MinecraftSession{}, "", model.MinecraftProfile{}, err
	}
	parentSession, ok := s.State.AuthSessions.get(neverSessionID, user.ID)
	if !ok {
		return model.MinecraftSession{}, "", model.MinecraftProfile{}, errAuthRequired
	}
	if parentSession.BindingEpoch < 1 {
		parentSession.BindingEpoch = 1
	}
	trustedDeviceID = strings.TrimSpace(trustedDeviceID)
	if bindingEpoch < 1 {
		bindingEpoch = 1
	}
	if parentSession.BindingEpoch != bindingEpoch || strings.TrimSpace(parentSession.TrustedDeviceID) != trustedDeviceID {
		return model.MinecraftSession{}, "", model.MinecraftProfile{}, errAuthRequired
	}
	profile, err := s.ensureMinecraftProfile119(user)
	if err != nil {
		return model.MinecraftSession{}, "", model.MinecraftProfile{}, err
	}
	token, err := randomToken("nlmc")
	if err != nil {
		return model.MinecraftSession{}, "", model.MinecraftProfile{}, err
	}
	if strings.TrimSpace(clientToken) == "" {
		clientToken, err = randomToken("nlct")
		if err != nil {
			return model.MinecraftSession{}, "", model.MinecraftProfile{}, err
		}
	}
	now := time.Now().UTC()
	session := model.MinecraftSession{ID: "mcs-" + strings.TrimPrefix(token, "nlmc_"), UserID: user.ID, NeverSessionID: neverSessionID, ProfileUUID: profile.UUID, TrustedDeviceID: trustedDeviceID, BindingEpoch: bindingEpoch, ClientToken: clientToken, AccessTokenHash: tokenHash910(token), Status: "active", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(minecraftSessionTTL119)}
	if integrity != nil {
		session.IntegrityVerified = true
		session.GuardAttestationSHA256 = integrity.GuardAttestationSHA256
		session.GuardEvidenceSHA256 = integrity.GuardEvidenceSHA256
		session.GuardSHA256 = integrity.GuardSHA256
		session.LauncherSHA256 = integrity.LauncherSHA256
		session.LauncherVersion = integrity.LauncherVersion
		session.IntegrityVerifiedAt = integrity.VerifiedAt
	}
	session, err = repo.SaveMinecraftSession(session)
	return session, token, profile, err
}

func (s Server) validateMinecraftToken119(token string) (model.MinecraftSession, model.MinecraftProfile, model.User, error) {
	repo, err := s.minecraftRepo119()
	if err != nil {
		return model.MinecraftSession{}, model.MinecraftProfile{}, model.User{}, err
	}
	session, err := repo.GetMinecraftSessionByTokenHash(tokenHash910(strings.TrimSpace(token)))
	if err != nil || session.Status != "active" || !session.ExpiresAt.After(time.Now().UTC()) {
		return model.MinecraftSession{}, model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	_, trust := s.evaluateGameplayTrust0127(nil, session.UserID, session.NeverSessionID, session.TrustedDeviceID, session.BindingEpoch, false)
	if !trust.Allowed {
		if gameplayTrustPermanentFailure0127(trust.Reason) {
			_ = repo.RevokeMinecraftSession(session.ID, "trust-policy:"+trust.Reason)
		}
		return model.MinecraftSession{}, model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	integrity := s.evaluateMinecraftIntegrity0135(session)
	if !integrity.Allowed {
		if minecraftIntegrityPermanentFailure0135(integrity.Reason) {
			_ = repo.RevokeMinecraftSession(session.ID, "integrity-policy:"+integrity.Reason)
		}
		return model.MinecraftSession{}, model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	user, err := s.Repo.GetUser(session.UserID)
	if err != nil || user.Status == "disabled" {
		return model.MinecraftSession{}, model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	profile, err := repo.GetMinecraftProfileByUUID(session.ProfileUUID)
	if err != nil {
		return model.MinecraftSession{}, model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	_, _ = repo.TouchMinecraftSession(session.ID)
	return session, profile, user, nil
}

func minecraftProfileJSON119(profile model.MinecraftProfile, texture map[string]string) map[string]any {
	properties := []map[string]string{}
	if texture != nil {
		properties = append(properties, texture)
	}
	return map[string]any{"id": minecraftID119(profile.UUID), "name": profile.Name, "properties": properties}
}

func (s Server) minecraftTexture119(profile model.MinecraftProfile) map[string]string {
	return textureProperty910(s.State.ServerBridge.textureFor(profile.UUID, profile.Name))
}

func (s Server) minecraftSessionExchange119(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req minecraftSessionRequest119
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if err := dec.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "тело запроса должно содержать один JSON-объект")
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, claims.Sub, claims.SessionID, claims.TrustedDeviceID, claims.BindingEpoch, true)
	if !trust.Allowed {
		s.writeGameplayTrustRequirement0127(w, trust)
		return
	}
	var guardTicket model.DeviceChallenge
	guardRequired, err := s.guardAttestationRequiredForSession0134(claims)
	if err != nil {
		writeError(w, http.StatusPreconditionFailed, "не удалось определить NeverGuard policy для trusted device")
		return
	}
	var integritySnapshot *minecraftIntegritySnapshot0135
	if guardRequired {
		guardTicket, err = s.consumeGuardLaunchTicket0134(r, claims, req.GuardAttestationTicket)
		if err != nil {
			writeError(w, http.StatusPreconditionFailed, err.Error())
			return
		}
		snapshot, snapshotErr := snapshotFromGuardLaunchTicket0135(guardTicket)
		if snapshotErr != nil {
			writeError(w, http.StatusPreconditionFailed, snapshotErr.Error())
			return
		}
		integritySnapshot = &snapshot
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	session, token, profile, err := s.issueMinecraftSessionWithTrustAndIntegrity119(user, claims.SessionID, req.ClientToken, trust.TrustedDeviceID, trust.BindingEpoch, integritySnapshot)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать Minecraft session")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("minecraft-session"), Actor: user.Email, Action: "minecraft:session:issued", Target: session.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	if guardTicket.ID != "" {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("guard-launch"), Actor: user.Email, Action: "neverguard:launch-ticket:consumed", Target: guardTicket.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"accessToken": token, "clientToken": session.ClientToken, "expiresAt": session.ExpiresAt, "profile": minecraftProfileJSON119(profile, s.minecraftTexture119(profile)), "integrity": integrityMetadataFromMinecraftSession0135(session)}})
}

func (s Server) minecraftProfileCurrent119(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	profile, err := s.ensureMinecraftProfile119(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось получить Minecraft profile")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": minecraftProfileJSON119(profile, s.minecraftTexture119(profile))})
}

func decodeYggdrasil119(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
func writeYggdrasilError119(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": "ForbiddenOperationException", "errorMessage": message})
}

func (s Server) yggdrasilAuthenticate119(w http.ResponseWriter, r *http.Request) {
	var req yggdrasilAuthenticateRequest119
	if decodeYggdrasil119(w, r, &req) != nil {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid request")
		return
	}
	result, err := s.Federation.AuthenticatePassword(r.Context(), req.ProviderID, authconnector.PasswordRequest{Identifier: strings.TrimSpace(req.Username), Secret: req.Password})
	if err != nil {
		status := federationHTTPStatus112(err)
		if status < 400 || status >= 500 {
			status = http.StatusForbidden
		}
		writeYggdrasilError119(w, status, "Invalid credentials")
		return
	}
	mfa, err := s.evaluateLoginMFA117(result.User, result.AuthMethods, req.TOTP, req.RecoveryCode)
	if err != nil || mfa.NeedPasskey {
		writeYggdrasilError119(w, http.StatusForbidden, "MFA requires NeverLauncher session exchange")
		return
	}
	_, _, neverSession, err := s.issueLoginSessionWithAuth(result.User, r, "minecraft-authlib", mfa.Methods, mfa.Strength, time.Now().UTC(), result.Identity.ID, result.Provider.ID)
	if err != nil {
		writeYggdrasilError119(w, http.StatusInternalServerError, "Session creation failed")
		return
	}
	mcSession, token, profile, err := s.issueMinecraftSession119(result.User, neverSession.ID, req.ClientToken)
	if err != nil {
		s.State.AuthSessions.revoke(neverSession.ID, "minecraft-session-failed")
		writeYggdrasilError119(w, http.StatusInternalServerError, "Minecraft session creation failed")
		return
	}
	payload := map[string]any{"accessToken": token, "clientToken": mcSession.ClientToken, "availableProfiles": []any{minecraftProfileJSON119(profile, nil)}, "selectedProfile": minecraftProfileJSON119(profile, nil)}
	if req.RequestUser {
		payload["user"] = map[string]any{"id": result.User.ID, "properties": []any{}}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s Server) yggdrasilRefresh119(w http.ResponseWriter, r *http.Request) {
	var req yggdrasilRefreshRequest119
	if decodeYggdrasil119(w, r, &req) != nil {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid request")
		return
	}
	old, profile, user, err := s.validateMinecraftToken119(req.AccessToken)
	if err != nil {
		writeYggdrasilError119(w, http.StatusForbidden, "Invalid token")
		return
	}
	repo, _ := s.minecraftRepo119()
	if err := repo.RevokeMinecraftSession(old.ID, "yggdrasil-refresh"); err != nil {
		writeYggdrasilError119(w, http.StatusForbidden, "Invalid token")
		return
	}
	var integritySnapshot *minecraftIntegritySnapshot0135
	if old.IntegrityVerified {
		integritySnapshot = &minecraftIntegritySnapshot0135{
			GuardAttestationSHA256: old.GuardAttestationSHA256, GuardEvidenceSHA256: old.GuardEvidenceSHA256,
			GuardSHA256: old.GuardSHA256, LauncherSHA256: old.LauncherSHA256, LauncherVersion: old.LauncherVersion, VerifiedAt: old.IntegrityVerifiedAt,
		}
	}
	fresh, token, profile, err := s.issueMinecraftSessionWithTrustAndIntegrity119(user, old.NeverSessionID, firstNonEmpty(req.ClientToken, old.ClientToken), old.TrustedDeviceID, old.BindingEpoch, integritySnapshot)
	if err != nil {
		writeYggdrasilError119(w, http.StatusInternalServerError, "Session refresh failed")
		return
	}
	payload := map[string]any{"accessToken": token, "clientToken": fresh.ClientToken, "selectedProfile": minecraftProfileJSON119(profile, nil)}
	if req.RequestUser {
		payload["user"] = map[string]any{"id": user.ID, "properties": []any{}}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s Server) yggdrasilValidate119(w http.ResponseWriter, r *http.Request) {
	var req yggdrasilTokenRequest119
	if decodeYggdrasil119(w, r, &req) != nil {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid request")
		return
	}
	session, _, _, err := s.validateMinecraftToken119(req.AccessToken)
	if err != nil || (req.ClientToken != "" && req.ClientToken != session.ClientToken) {
		writeYggdrasilError119(w, http.StatusForbidden, "Invalid token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s Server) yggdrasilInvalidate119(w http.ResponseWriter, r *http.Request) {
	var req yggdrasilTokenRequest119
	if decodeYggdrasil119(w, r, &req) == nil {
		if repo, err := s.minecraftRepo119(); err == nil {
			if session, err := repo.GetMinecraftSessionByTokenHash(tokenHash910(req.AccessToken)); err == nil && (req.ClientToken == "" || req.ClientToken == session.ClientToken) {
				_ = repo.RevokeMinecraftSession(session.ID, "yggdrasil-invalidate")
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) yggdrasilSignout119(w http.ResponseWriter, r *http.Request) {
	var req yggdrasilSignoutRequest119
	if decodeYggdrasil119(w, r, &req) != nil {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid request")
		return
	}
	result, err := s.Federation.AuthenticatePassword(r.Context(), req.ProviderID, authconnector.PasswordRequest{Identifier: strings.TrimSpace(req.Username), Secret: req.Password})
	if err != nil {
		if errors.Is(err, federation.ErrCapabilityUnsupported) {
			writeYggdrasilError119(w, http.StatusForbidden, "Provider does not support password signout")
			return
		}
		writeYggdrasilError119(w, http.StatusForbidden, "Invalid credentials")
		return
	}
	s.State.AuthSessions.revokeUser(result.User.ID, "yggdrasil-signout")
	if repo, err := s.minecraftRepo119(); err == nil {
		repo.RevokeMinecraftSessionsByUser(result.User.ID, "yggdrasil-signout")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) yggdrasilJoin119(w http.ResponseWriter, r *http.Request) {
	var req yggdrasilJoinRequest119
	if decodeYggdrasil119(w, r, &req) != nil {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid request")
		return
	}
	session, profile, _, err := s.validateMinecraftToken119(req.AccessToken)
	if err != nil || minecraftID119(profile.UUID) != strings.ReplaceAll(strings.ToLower(strings.TrimSpace(req.SelectedProfile)), "-", "") {
		writeYggdrasilError119(w, http.StatusForbidden, "Invalid token or profile")
		return
	}
	if strings.TrimSpace(req.ServerID) == "" {
		writeYggdrasilError119(w, http.StatusBadRequest, "serverId is required")
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, session.UserID, session.NeverSessionID, session.TrustedDeviceID, session.BindingEpoch, true)
	if !trust.Allowed {
		writeYggdrasilError119(w, http.StatusForbidden, "NeverLauncher trust policy denied join: "+trust.Reason)
		return
	}
	repo, _ := s.minecraftRepo119()
	now := time.Now().UTC()
	err = repo.SaveMinecraftJoin(model.MinecraftJoin{Username: profile.Name, UsernameNormalized: strings.ToLower(profile.Name), ProfileUUID: profile.UUID, UserID: session.UserID, MinecraftSessionID: session.ID, ServerID: req.ServerID, IP: clientIP(r), CreatedAt: now, ExpiresAt: now.Add(minecraftJoinTTL119)})
	if err != nil {
		writeYggdrasilError119(w, http.StatusInternalServerError, "Join persistence failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s Server) yggdrasilHasJoined119(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	serverID := strings.TrimSpace(r.URL.Query().Get("serverId"))
	if username == "" || serverID == "" {
		writeYggdrasilError119(w, http.StatusBadRequest, "username and serverId are required")
		return
	}
	repo, err := s.minecraftRepo119()
	if err != nil {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Minecraft repository unavailable")
		return
	}
	join, err := repo.GetMinecraftJoin(username, serverID)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if requestedIP := strings.TrimSpace(r.URL.Query().Get("ip")); requestedIP != "" && join.IP != "" && requestedIP != join.IP {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	session, err := repo.GetMinecraftSession(join.MinecraftSessionID)
	if err != nil || session.Status != "active" || !session.ExpiresAt.After(time.Now().UTC()) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, trust := s.evaluateGameplayTrust0127(r, session.UserID, session.NeverSessionID, session.TrustedDeviceID, session.BindingEpoch, true)
	if !trust.Allowed {
		if gameplayTrustPermanentFailure0127(trust.Reason) {
			_ = repo.RevokeMinecraftSession(session.ID, "trust-policy:"+trust.Reason)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	integrity := s.evaluateMinecraftIntegrity0135(session)
	if !integrity.Allowed {
		if minecraftIntegrityPermanentFailure0135(integrity.Reason) {
			_ = repo.RevokeMinecraftSession(session.ID, "integrity-policy:"+integrity.Reason)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	profile, err := repo.GetMinecraftProfileByUUID(join.ProfileUUID)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, minecraftProfileJSON119(profile, s.minecraftTexture119(profile)))
}

func (s Server) yggdrasilProfile119(w http.ResponseWriter, r *http.Request) {
	repo, err := s.minecraftRepo119()
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	profile, err := repo.GetMinecraftProfileByUUID(r.PathValue("uuid"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, minecraftProfileJSON119(profile, s.minecraftTexture119(profile)))
}
func (s Server) yggdrasilProfileByName119(w http.ResponseWriter, r *http.Request) {
	repo, err := s.minecraftRepo119()
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	profile, err := repo.GetMinecraftProfileByName(r.PathValue("username"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": minecraftID119(profile.UUID), "name": profile.Name})
}

func (s Server) yggdrasilMetadata119(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(strings.TrimSpace(s.Config.PublicURL), "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"meta": map[string]any{
			"serverName":              "NeverLauncher",
			"implementationName":      "NeverLauncher Minecraft Auth Compatibility",
			"implementationVersion":   s.Version,
			"feature.non_email_login": true,
			"links":                   map[string]string{"homepage": base},
		},
		"skinDomains":        []string{},
		"signaturePublickey": "",
	})
}
