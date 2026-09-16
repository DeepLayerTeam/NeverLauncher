package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

func (s Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	identifier := strings.TrimSpace(firstNonEmpty(req.Identifier, req.Email))
	rateKey := strings.ToLower(identifier)
	if identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "identifier/email и пароль обязательны")
		return
	}
	if allowed, retry := s.State.Security.allowLogin(rateKey, clientIP(r)); !allowed {
		s.audit(r, identifier, "admin:login:rate-limited", "admin-panel")
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("слишком много неудачных входов; повторите после %s", retry.Format(time.RFC3339)))
		return
	}
	result, authErr := s.Federation.AuthenticatePassword(r.Context(), req.ProviderID, authconnector.PasswordRequest{Identifier: identifier, Secret: req.Password})
	if authErr != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		_ = s.flushPersistenceState950("admin-login-failed")
		s.audit(r, identifier, "admin:login:failed", "admin-panel")
		status := federationHTTPStatus112(authErr)
		if status >= 500 {
			writeError(w, status, "auth provider временно недоступен")
			return
		}
		if status == http.StatusForbidden {
			writeError(w, status, "пользователь отключён или identity не связана")
			return
		}
		if status == http.StatusBadRequest {
			writeError(w, status, "auth provider не поддерживает password login")
			return
		}
		if status == http.StatusConflict {
			writeError(w, status, "external identity конфликтует с существующей учётной записью; требуется явное связывание")
			return
		}
		writeError(w, http.StatusUnauthorized, "неверный email или пароль")
		return
	}
	user := result.User
	mfa, mfaErr := s.evaluateLoginMFA117(user, result.AuthMethods, req.TOTP, req.RecoveryCode)
	if mfaErr != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		_ = s.flushPersistenceState950("admin-login-failed")
		s.audit(r, user.Email, "admin:login:mfa-failed", mfaErr.Error())
		writeError(w, http.StatusUnauthorized, "требуется действительный настроенный метод MFA")
		return
	}
	if mfa.NeedPasskey {
		continuation, err := s.startPasskeyMFAContinuation117(user, result.Provider.ID, result.Identity.ID, "admin-panel", mfa.Methods)
		if err != nil {
			writeError(w, http.StatusForbidden, "MFA policy требует зарегистрированный passkey")
			return
		}
		s.audit(r, user.Email, "admin:login:passkey-required", result.Provider.ID)
		writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": continuation})
		return
	}
	s.State.Security.recordLoginSuccess(rateKey, clientIP(r))
	_ = s.flushPersistenceState950("admin-login-success")
	if updated, err := s.Repo.TouchUserLogin(user.ID); err == nil {
		user = updated
	}
	token, refreshToken, session, err := s.issueLoginSessionWithAuth(user, r, "admin-panel", mfa.Methods, mfa.Strength, time.Now().UTC(), result.Identity.ID, result.Provider.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать серверную сессию")
		return
	}
	s.audit(r, user.Email, "admin:login", session.ID)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "admin-federation-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:federation:authenticated", Target: result.Provider.ID + "/" + result.Identity.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, model.AdminSession{Token: token, RefreshToken: refreshToken, SessionID: session.ID, User: user, ExpiresAt: time.Now().UTC().Add(accessTokenTTL), RefreshExpiresAt: session.ExpiresAt})
}

func (s Server) adminMe(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "permissions": claims.Permissions, "expiresAt": time.Unix(claims.Exp, 0).UTC()})
}

func (s Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	s.State.AuthSessions.revoke(claims.SessionID, "admin-logout")
	s.audit(r, claims.Email, "admin:logout", claims.SessionID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged-out", "sessionId": claims.SessionID, "message": "серверная сессия отозвана; удалите access/refresh token на клиенте"})
}

func (s Server) adminUserCreate(w http.ResponseWriter, r *http.Request) {
	var req userWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.RoleID == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email, roleId и password обязательны")
		return
	}
	user := model.User{Email: req.Email, DisplayName: req.DisplayName, RoleID: req.RoleID, Status: "active", ProjectRoles: req.ProjectRoles, PasswordHash: hashPassword(req.Password), PasswordUpdatedAt: time.Now().UTC()}
	saved, err := s.Repo.SaveUser(user)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "user:create", saved.ID)
	writeJSON(w, http.StatusCreated, saved)
}

func (s Server) adminUserUpdate(w http.ResponseWriter, r *http.Request) {
	user, err := s.Repo.GetUser(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	var req userWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if strings.TrimSpace(req.Email) != "" {
		user.Email = strings.TrimSpace(req.Email)
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.RoleID != "" {
		user.RoleID = req.RoleID
	}
	if req.ProjectRoles != nil {
		user.ProjectRoles = req.ProjectRoles
	}
	saved, err := s.Repo.SaveUser(user)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "user:update", saved.ID)
	writeJSON(w, http.StatusOK, saved)
}

func (s Server) adminUserPassword(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, "пароль должен быть не короче 12 символов")
		return
	}
	user, err := s.Repo.SetUserPassword(r.PathValue("userId"), hashPassword(req.Password))
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	revoked := s.State.AuthSessions.revokeUser(user.ID, "password-reset")
	s.audit(r, s.adminActor(r), "user:password:reset", user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "revokedSessions": revoked})
}

func (s Server) adminUserDisable(w http.ResponseWriter, r *http.Request) {
	user, err := s.Repo.SetUserDisabled(r.PathValue("userId"), true)
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	revoked := s.State.AuthSessions.revokeUser(user.ID, "user-disabled")
	s.audit(r, s.adminActor(r), "user:disable", user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "revokedSessions": revoked})
}

func (s Server) adminUserEnable(w http.ResponseWriter, r *http.Request) {
	user, err := s.Repo.SetUserDisabled(r.PathValue("userId"), false)
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	s.audit(r, s.adminActor(r), "user:enable", user.ID)
	writeJSON(w, http.StatusOK, user)
}
func (s Server) adminOverview(w http.ResponseWriter, r *http.Request) {
	projects := s.Repo.ListProjects()
	var projectID string
	if len(projects) > 0 {
		projectID = projects[0].ID
	}
	profiles, _ := s.Repo.ListProfiles(projectID)
	channels, _ := s.Repo.ListChannels(projectID)
	versions, _ := s.Repo.ListVersions(projectID)
	files, _ := s.Repo.ListFiles(projectID, "")
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "projects": projects, "profiles": profiles, "channels": channels, "versions": versions, "files": files, "users": s.Repo.ListUsers(), "roles": s.Repo.ListRoles(), "audit": s.Repo.ListAuditEvents(), "telemetry": s.Repo.ListTelemetryEvents(), "crashReports": s.Repo.ListCrashReports()})
}

func (s Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.Repo.ListUsers()})
}
func (s Server) adminRoles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.Repo.ListRoles()})
}
func (s Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.Repo.ListAuditEvents()})
}

func (s Server) adminStorageHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.Storage.Health(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"driver": s.Storage.Driver(), "status": "error", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"driver": s.Storage.Driver(), "status": "ok"})
}

func (s Server) adminPublish(w http.ResponseWriter, r *http.Request) {
	var req publishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.ProfileID == "" {
		req.ProfileID = "vanilla"
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	release, err := s.publishSigned(r.PathValue("projectId"), req.ProfileID, req.Channel, req.Version)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект или профиль не найден")
		return
	}
	s.audit(r, s.adminActor(r), "release:publish", release.ID)
	writeJSON(w, http.StatusCreated, release)
}

func (s Server) adminVersionCreate(w http.ResponseWriter, r *http.Request) {
	var req createVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.ProfileID == "" {
		req.ProfileID = "vanilla"
	}
	if req.Channel == "" {
		req.Channel = "dev"
	}
	release, err := s.Repo.CreateVersion(r.PathValue("projectId"), req.ProfileID, req.Channel, req.Version)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект или профиль не найден")
		return
	}
	s.audit(r, s.adminActor(r), "release:create", release.ID)
	writeJSON(w, http.StatusCreated, release)
}

func (s Server) adminVersionPublish(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	versionID := r.PathValue("versionId")
	versions, err := s.Repo.ListVersions(projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	for _, item := range versions {
		if item.ID == versionID {
			release, err := s.publishSigned(projectID, item.ProfileID, item.Channel, item.Version)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.audit(r, s.adminActor(r), "release:publish", release.ID)
			writeJSON(w, http.StatusOK, release)
			return
		}
	}
	writeError(w, http.StatusNotFound, "версия не найдена")
}

func (s Server) adminFileUpload(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	versionID := r.PathValue("versionId")
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes())
	// ParseMultipartForm keeps only a bounded prefix in RAM and spools larger
	// file parts to disk. Storage.Save then consumes the file as a stream.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "не удалось прочитать multipart-запрос или превышен лимит размера")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	relativePath := r.FormValue("path")
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "поле file обязательно")
		return
	}
	defer file.Close()

	if relativePath == "" {
		relativePath = header.Filename
	}
	if relativePath == "" {
		writeError(w, http.StatusBadRequest, "path обязателен")
		return
	}
	executable, targetOS, metadataErr := releaseFileMetadata(r)
	if metadataErr != nil {
		writeError(w, http.StatusBadRequest, metadataErr.Error())
		return
	}

	hasher := sha256.New()
	reader := io.TeeReader(file, hasher)
	_, size, err := s.Storage.Save(projectID, versionID, relativePath, reader)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	object := model.FileObject{
		ID:         fmt.Sprintf("file-%d", time.Now().UTC().UnixNano()),
		ProjectID:  projectID,
		VersionID:  versionID,
		Path:       relativePath,
		Size:       size,
		SHA256:     hex.EncodeToString(hasher.Sum(nil)),
		URL:        fmt.Sprintf("%s/api/v1/files/%s/%s/%s", strings.TrimRight(s.Config.PublicURL, "/"), projectID, versionID, relativePath),
		Required:   true,
		Executable: executable,
		TargetOS:   targetOS,
	}
	saved, err := s.Repo.AddFile(object)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект или версия не найдены")
		return
	}
	s.audit(r, s.adminActor(r), "file:upload", saved.ID)
	writeJSON(w, http.StatusCreated, saved)
}

func (s Server) audit(r *http.Request, actor, action, target string) {
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: actor, Action: action, Target: target, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
}

func (s Server) adminProjectExport(w http.ResponseWriter, r *http.Request) {
	export, err := s.Repo.ExportProject(r.PathValue("projectId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	s.audit(r, s.adminActor(r), "project:export", r.PathValue("projectId"))
	writeJSON(w, http.StatusOK, export)
}

func (s Server) adminProjectImport(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if err := s.Repo.ImportProject(payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "project:import", "import")
	writeJSON(w, http.StatusCreated, map[string]any{"status": "imported"})
}
