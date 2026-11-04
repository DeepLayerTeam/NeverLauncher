package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/protection"
)

// Ban checks always read the authoritative repository, rather than a per-replica
// snapshot. Storage outage on a mandatory protection gate denies access.
type banHandler0298 struct{ store repository.ProtectionBanStore }

func (h banHandler0298) Name() string { return "account-ban" }
func (h banHandler0298) Evaluate(ctx context.Context, req protection.Request) (protection.Decision, error) {
	if strings.TrimSpace(req.UserID) == "" {
		return protection.Decision{Action: protection.Deny, Reason: "user_identity_missing"}, nil
	}
	_, blocked, err := h.store.ActiveProtectionBan(ctx, req.UserID, time.Now().UTC())
	if err != nil {
		return protection.Decision{}, err
	}
	if blocked {
		return protection.Decision{Action: protection.Deny, Reason: "account_banned"}, nil
	}
	return protection.Decision{Action: protection.Allow, Reason: "no_active_ban"}, nil
}

// Account state and permissions are checked against the live user record. The
// session check uses the same authoritative session store as token validation.
type accountHandler0298 struct {
	repo     repository.Repository
	sessions *authSessionStore
}

func (h accountHandler0298) Name() string { return "account-session-role" }
func (h accountHandler0298) Evaluate(ctx context.Context, req protection.Request) (protection.Decision, error) {
	if ctx.Err() != nil {
		return protection.Decision{}, ctx.Err()
	}
	user, err := h.repo.GetUser(req.UserID)
	if ctx.Err() != nil {
		return protection.Decision{}, ctx.Err()
	}
	if err != nil {
		return protection.Decision{Action: protection.Deny, Reason: "account_missing"}, nil
	}
	if user.Status != "active" {
		return protection.Decision{Action: protection.Deny, Reason: "account_disabled"}, nil
	}
	if req.RoleID != "" && user.RoleID != req.RoleID {
		return protection.Decision{Action: protection.Deny, Reason: "role_changed"}, nil
	}
	if req.SessionID != "" {
		if h.sessions == nil {
			return protection.Decision{Action: protection.Deny, Reason: "session_store_unavailable"}, nil
		}
		if _, ok := h.sessions.get(req.SessionID, user.ID); !ok {
			return protection.Decision{Action: protection.Deny, Reason: "session_inactive"}, nil
		}
	}
	return protection.Decision{Action: protection.Allow, Reason: "account_active"}, nil
}
func (s Server) evaluateProtection0298(ctx context.Context, req protection.Request) protection.Decision {
	store, ok := s.Repo.(repository.ProtectionBanStore)
	if !ok {
		return protection.Decision{Action: protection.Deny, Reason: "ban_store_unavailable", Handler: "account-ban"}
	}
	builtIn := protection.New(2 * time.Second)
	if err := builtIn.Register(0, true, []protection.Stage{protection.BeforeAuth, protection.AfterAuth, protection.BeforeLaunch, protection.BeforeJoin}, banHandler0298{store}); err != nil {
		return protection.Decision{Action: protection.Deny, Reason: "ban_handler_registration_failed", Handler: "engine"}
	}
	var sessions *authSessionStore
	if s.State != nil {
		sessions = s.State.AuthSessions
	}
	if err := builtIn.Register(1, true, []protection.Stage{protection.BeforeAuth, protection.AfterAuth, protection.BeforeLaunch, protection.BeforeJoin}, accountHandler0298{repo: s.Repo, sessions: sessions}); err != nil {
		return protection.Decision{Action: protection.Deny, Reason: "account_handler_registration_failed", Handler: "engine"}
	}
	decision := builtIn.Evaluate(ctx, req)
	if !decision.Allowed() {
		return decision
	}
	if s.Protection != nil {
		return s.Protection.Evaluate(ctx, req)
	}
	return decision
}
func (s Server) enforceProtection0298(w http.ResponseWriter, r *http.Request, stage protection.Stage, userID, sessionID, deviceID, roleID string) bool {
	decision := s.evaluateProtection0298(r.Context(), protection.Request{Stage: stage, UserID: userID, SessionID: sessionID, DeviceID: deviceID, RoleID: roleID})
	if decision.Allowed() {
		return true
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: userID, Action: "protection:denied", Target: string(stage), ReasonCode: decision.Reason, CorrelationID: correlationID02111(r), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	status := http.StatusForbidden
	if decision.Action == protection.StepUp || decision.Action == protection.Reattest {
		status = http.StatusPreconditionRequired
	}
	if decision.Reason == "ban_store_unavailable" || decision.Reason == "policy_handler_unavailable" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": status, "message": "protection policy denied", "reason": decision.Reason, "action": decision.Action, "stage": stage}})
	return false
}
func (s Server) protectionBanStore0298() (repository.ProtectionBanStore, bool) {
	v, ok := s.Repo.(repository.ProtectionBanStore)
	return v, ok
}

type protectionBanInput0298 struct {
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

func (s Server) adminProtectionBan0298(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	store, ok := s.protectionBanStore0298()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "protection store unavailable")
		return
	}
	userID := strings.TrimSpace(r.PathValue("userId"))
	if userID == claims.Sub {
		writeError(w, http.StatusForbidden, "cannot ban current administrator")
		return
	}
	if _, err := s.Repo.GetUser(userID); err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	var input protectionBanInput0298
	if !decodeSensitiveRequest0300(w, r, &input) {
		return
	}

	input.Reason = strings.TrimSpace(input.Reason)
	if len(input.Reason) < 3 || len(input.Reason) > 512 || (input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC())) {
		writeError(w, http.StatusBadRequest, "reason length 3..512 and future expiry required")
		return
	}
	ban := repository.ProtectionBan{UserID: userID, Actor: claims.Sub, Reason: input.Reason, ExpiresAt: input.ExpiresAt}
	if err := store.SetProtectionBan(r.Context(), ban); err != nil {
		writeError(w, http.StatusServiceUnavailable, "ban transaction failed")
		return
	}
	// DB trigger performs the cross-replica revocation transaction before Set returns.
	// Development mode has no trigger and must explicitly revoke in-memory sessions.
	s.State.AuthSessions.revokeUser(userID, "protection-ban")
	if mc, err := s.minecraftRepo119(); err == nil {
		mc.RevokeMinecraftSessionsByUser(userID, "protection-ban")
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "protection:ban", Target: userID, ReasonCode: "admin-ban", CorrelationID: correlationID02111(r), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"status": "banned", "userId": userID, "reason": input.Reason, "expiresAt": input.ExpiresAt})
}
func (s Server) adminProtectionUnban0298(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	store, ok := s.protectionBanStore0298()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "protection store unavailable")
		return
	}
	userID := strings.TrimSpace(r.PathValue("userId"))
	changed, err := store.RevokeProtectionBan(r.Context(), userID, claims.Sub)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unban failed")
		return
	}
	if !changed {
		writeError(w, http.StatusNotFound, "active ban not found")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "protection:unban", Target: userID, ReasonCode: "admin-unban", CorrelationID: correlationID02111(r), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"status": "unbanned", "userId": userID, "sessionsRestored": false})
}
func (s Server) adminProtectionBans0298(w http.ResponseWriter, r *http.Request) {
	store, ok := s.protectionBanStore0298()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "protection store unavailable")
		return
	}
	bans, err := store.ListProtectionBans(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "protection store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": bans})
}
