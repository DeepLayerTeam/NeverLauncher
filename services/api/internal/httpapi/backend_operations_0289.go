package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// BackendLifecycle0289 is a one-way request to the process owner. HTTP never
// executes commands, sends signals to arbitrary PIDs, or starts a shell.
type BackendLifecycle0289 struct {
	InstanceID string
	StartedAt  time.Time
	Enabled    bool
	mu         sync.Mutex
	requested  bool
	shutdown   chan struct{}
}

func NewBackendLifecycle0289(enabled bool) (*BackendLifecycle0289, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &BackendLifecycle0289{InstanceID: hex.EncodeToString(b[:]), StartedAt: time.Now().UTC(), Enabled: enabled, shutdown: make(chan struct{}, 1)}, nil
}
func (l *BackendLifecycle0289) RestartRequested() <-chan struct{} { return l.shutdown }
func (l *BackendLifecycle0289) ScheduleRestart() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.Enabled || l.requested {
		return false
	}
	l.requested = true
	// Delay avoids closing the HTTP connection before the 202 response has been
	// flushed. Graceful HTTP shutdown in main waits for in-flight requests.
	go func() { time.Sleep(350 * time.Millisecond); l.shutdown <- struct{}{} }()
	return true
}
func (l *BackendLifecycle0289) IsDraining() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requested
}

// Only nonsecret configuration reloads without restarting. Deployment secrets,
// signing keys, HTTP listen address and DB connection need a supervised restart.
func (s Server) backendConfigReload0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.OperationalConfigStore)
	if !ok {
		writeError(w, 503, "operational config store unavailable")
		return
	}
	revision, err := store.GetOperationalConfig(r.Context())
	if err != nil {
		writeError(w, 503, "operational config store unavailable")
		return
	}
	if err := revision.Settings.Validate(); err != nil {
		writeError(w, 503, "invalid operational configuration")
		return
	}
	s.audit(r, s.adminActor(r), "backend:config:reload", "revision")
	writeJSON(w, 200, map[string]any{"appliedRevision": revision.Revision, "reloadScope": "dynamic-operational-settings", "restartRequiredForStaticSettings": true})
}

func (s Server) backendInstanceStatus0289(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	l := s.State.BackendLifecycle0289
	if l == nil {
		writeError(w, 503, "backend lifecycle not initialized")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	checks := map[string]string{}
	if checker, ok := s.Repo.(interface{ Health(context.Context) error }); ok {
		if err := checker.Health(ctx); err != nil {
			checks["repository"] = "unavailable"
		} else {
			checks["repository"] = "ok"
		}
	} else {
		checks["repository"] = "not_available"
	}
	if s.Storage != nil {
		if err := s.Storage.Health(ctx); err != nil {
			checks["storage"] = "unavailable"
		} else {
			checks["storage"] = "ok"
		}
	}
	revision := int64(0)
	if store, ok := s.Repo.(repository.OperationalConfigStore); ok {
		if value, err := store.GetOperationalConfig(ctx); err == nil {
			revision = value.Revision
		} else {
			checks["operationalSettings"] = "unavailable"
		}
	}
	recent := backendRecentClients0289(s.State.AuthSessions.listFiltered118("", "", "active", ""), time.Now().UTC(), 5*time.Minute)
	launcherCount := 0
	if store, ok := s.Repo.(repository.BackendMinecraftClientStore0289); ok {
		if clients, err := store.ListRecentMinecraftClients0289(ctx, time.Now().UTC(), 5*time.Minute); err == nil {
			launcherCount = len(clients)
		} else {
			checks["launcherSessions"] = "unavailable"
		}
	}
	writeJSON(w, 200, map[string]any{"instanceId": l.InstanceID, "version": s.Version, "commit": s.SourceCommit,
		"startedAt": l.StartedAt, "uptimeSeconds": int(time.Since(l.StartedAt).Seconds()),
		"supervisedRestartEnabled": l.Enabled, "draining": l.IsDraining(),
		"environment": s.Config.Environment, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver,
		"checks": checks, "operationalConfigRevision": revision, "recentAdminSessions": len(recent), "recentLauncherSessions": launcherCount,
		"sessionMetric": "active auth / launcher sessions observed within 5 minutes (not open sockets)"})
}

type backendClient0289 struct {
	SessionID  string    `json:"sessionId"`
	UserID     string    `json:"userId"`
	Provider   string    `json:"provider"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func backendRecentClients0289(sessions []authSessionRecord, now time.Time, fresh time.Duration) []backendClient0289 {
	out := make([]backendClient0289, 0)
	for _, it := range sessions {
		if it.Status != "active" || !it.ExpiresAt.After(now) || it.LastSeenAt.After(now.Add(time.Minute)) || now.Sub(it.LastSeenAt) > fresh {
			continue
		}
		out = append(out, backendClient0289{SessionID: it.ID, UserID: it.UserID, Provider: it.Provider, LastSeenAt: it.LastSeenAt, ExpiresAt: it.ExpiresAt})
		if len(out) == 100 {
			break
		}
	}
	return out
}
func (s Server) backendConnectedClients0289(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()
	admins := backendRecentClients0289(s.State.AuthSessions.listFiltered118("", "", "active", ""), now, 5*time.Minute)
	store, ok := s.Repo.(repository.BackendMinecraftClientStore0289)
	if !ok {
		writeError(w, 503, "launcher sessions store unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	launchers, err := store.ListRecentMinecraftClients0289(ctx, now, 5*time.Minute)
	if err != nil {
		writeError(w, 503, "launcher sessions unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"adminSessions": admins, "launcherSessions": launchers,
		"adminCount": len(admins), "launcherCount": len(launchers), "sampledAt": now, "freshnessSeconds": 300,
		"source":     "auth_sessions.last_seen_at / minecraft_sessions.last_seen_at",
		"limitation": "recently observed authorization sessions, not guaranteed connected sockets or online Minecraft players", "limitPerType": 100})
}

type backendRestartRequest0289 struct {
	InstanceID   string `json:"instanceId"`
	Confirmation string `json:"confirmation"`
}

func (s Server) backendRestart0289(w http.ResponseWriter, r *http.Request) {
	l := s.State.BackendLifecycle0289
	// Never let a server which isn't managed by an explicit restarting service die.
	if l == nil || !l.Enabled {
		writeError(w, 503, "restart requires an explicitly configured external process supervisor")
		return
	}
	journal, ok := s.Repo.(repository.BackendRestartJournal)
	if !ok {
		writeError(w, 503, "restart requires a durable PostgreSQL command journal")
		return
	}
	if os.Getenv("NEVERLAUNCHER_BACKEND_SUPERVISED_RESTART") != "true" {
		writeError(w, 503, "external supervised restart is not enabled")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "invalid authentication")
		return
	}
	if _, err = repository.BackendRestartKey0289(claims.Sub, key); err != nil {
		writeError(w, 400, "Idempotency-Key must be 16-128 ASCII letters/digits/-/_/. characters")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	var req backendRestartRequest0289
	if err = dec.Decode(&req); err != nil {
		writeError(w, 400, "invalid restart request")
		return
	}
	var trailing any
	if err = dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, 400, "unexpected trailing data")
		return
	}
	if req.InstanceID != l.InstanceID || req.Confirmation != "RESTART "+l.InstanceID {
		writeError(w, 409, "runtime identity or explicit confirmation mismatch")
		return
	}
	rec, claimed, err := journal.ClaimBackendRestart0289(r.Context(), claims.Sub, key, l.InstanceID)
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, 409, "restart for this runtime already accepted with another idempotency key")
		return
	}
	if err != nil {
		writeError(w, 503, "cannot durably record restart request")
		return
	}
	if !claimed {
		writeJSON(w, 200, map[string]any{"operation": rec, "rescheduled": false, "note": "duplicate key never repeats the external effect"})
		return
	}
	s.audit(r, claims.Email, "backend:restart:accepted", rec.ID)
	if !l.ScheduleRestart() {
		// Already persisted as accepted, but not executed. Never report success.
		writeJSON(w, 202, map[string]any{"operation": rec, "state": "indeterminate", "note": "restart already in progress; check supervisor and instance identity"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 202, map[string]any{"operation": rec, "state": "accepted", "note": "external supervisor must restart the process after graceful shutdown"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// These are user-targeted, persisted notifications consumed by authenticated API
// clients. They are NOT ServerBridge broadcasts or host commands.
type backendNoticeWrite0289 struct {
	UserID  string `json:"userId"`
	Message string `json:"message"`
}

func (s Server) backendSendNotice0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.BackendNoticeStore0289)
	if !ok {
		writeError(w, 503, "durable backend notification store unavailable")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "not authenticated")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if _, err = repository.BackendRestartKey0289(claims.Sub, key); err != nil {
		writeError(w, 400, "invalid Idempotency-Key")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	var req backendNoticeWrite0289
	if err = dec.Decode(&req); err != nil {
		writeError(w, 400, "invalid notice JSON")
		return
	}
	var extra any
	if err = dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, 400, "unexpected JSON fields")
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.Message = strings.TrimSpace(req.Message)
	if err = repository.ValidateBackendNotice0289(req.UserID, req.Message); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if user, err := s.Repo.GetUser(req.UserID); err != nil || user.Status != "active" {
		writeError(w, 404, "recipient user not found or inactive")
		return
	}
	notice, created, err := store.EnqueueBackendNotice0289(r.Context(), claims.Sub, key, req.UserID, req.Message)
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, 409, "idempotency key already used with different notification")
		return
	}
	if err != nil {
		writeError(w, 503, "could not save notification")
		return
	}
	if created {
		s.audit(r, claims.Email, "backend:notice:queued", notice.ID)
	}
	writeJSON(w, 200, map[string]any{"notice": notice, "queued": created, "delivery": "recipient polls authenticated inbox and acknowledges"})
}
func (s Server) backendInbox0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.BackendNoticeStore0289)
	if !ok {
		writeError(w, 503, "backend inbox unavailable")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "not authenticated")
		return
	}
	items, err := store.ListBackendNotices0289(r.Context(), claims.Sub)
	if err != nil {
		writeError(w, 503, "backend inbox unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"items": items, "delivery": "durable-poll", "ackRequired": true})
}
func (s Server) backendNoticeAck0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.BackendNoticeStore0289)
	if !ok {
		writeError(w, 503, "backend inbox unavailable")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "not authenticated")
		return
	}
	id := r.PathValue("noticeId")
	if len(id) != 64 {
		writeError(w, 404, "notice not found")
		return
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			writeError(w, 404, "notice not found")
			return
		}
	}
	success, err := store.AckBackendNotice0289(r.Context(), claims.Sub, id)
	if err != nil {
		writeError(w, 503, "unable to acknowledge notice")
		return
	}
	if !success {
		writeError(w, 404, "notice not found or already acknowledged")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "acknowledged", "id": id})
}
