package httpapi

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	co "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcutover"
)

type migrationCutoverStore03311 interface {
	MigrationCutovers03311(context.Context, string) ([]co.Route, error)
	StageMigrationCutover03311(context.Context, string, co.Stage, ed25519.PublicKey) (co.Route, error)
	ActivateMigrationCutover03311(context.Context, string, co.Activate, ed25519.PublicKey) (co.Route, error)
	CancelMigrationCutover03311(context.Context, string, string, string, int64) (co.Route, error)
}

func (s Server) registerMigrationCutoverRoutes03311(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/cutovers", s.requirePermission("settings:manage", s.migrationCutoverList03311))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/cutovers/stage", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationCutoverStage03311))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/cutovers/activate", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationCutoverActivate03311))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/cutovers/cancel", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationCutoverCancel03311))
}
func (s Server) cutoverAccess03311(w http.ResponseWriter, r *http.Request) (migrationCutoverStore03311, string, bool) {
	store, ok := s.Repo.(migrationCutoverStore03311)
	if !ok {
		writeError(w, 503, "staged cutover requires PostgreSQL")
		return nil, "", false
	}
	run, e := s.migrationStoreRead03310(w, r)
	if e != nil {
		return nil, "", false
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "authentication required")
		return nil, "", false
	}
	if !s.authorizeProjectAction(w, r, claims, "settings:manage", run.ProjectID, "project", run.ProjectID) {
		return nil, "", false
	}
	return store, run.ID, true
}
func (s Server) cutoverKey03311(w http.ResponseWriter) (ed25519.PublicKey, bool) {
	private, e := s.manifestSigningPrivateKey()
	if e != nil {
		writeError(w, 503, "Never release signing key not configured")
		return nil, false
	}
	return private.Public().(ed25519.PublicKey), true
}
func (s Server) migrationCutoverList03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	items, e := store.MigrationCutovers03311(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": items})
}
func (s Server) migrationCutoverStage03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-Cutover-Confirm") != id {
		writeError(w, 400, "exact migration run confirmation required")
		return
	}
	input, ok := migrationRead0331[co.Stage](w, r)
	if !ok {
		return
	}
	key, ok := s.cutoverKey03311(w)
	if !ok {
		return
	}
	v, e := store.StageMigrationCutover03311(r.Context(), id, input, key)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:cutover-staged", v.ProjectID+":"+v.ProfileID+":"+v.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
func (s Server) migrationCutoverActivate03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	// Source fencing is out-of-band and must have been completed and audited by
	// the operator. This acknowledgement is retained but not cryptographic proof.
	if r.Header.Get("X-Migration-Cutover-Confirm") != id || r.Header.Get("X-Migration-Source-Fenced") != "true" {
		writeError(w, 400, "migration run and independently fenced source must be confirmed")
		return
	}
	input, ok := migrationRead0331[co.Activate](w, r)
	if !ok {
		return
	}
	key, ok := s.cutoverKey03311(w)
	if !ok {
		return
	}
	v, e := store.ActivateMigrationCutover03311(r.Context(), id, input, key)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:cutover-activated", v.ProjectID+":"+v.ProfileID+":"+v.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
func (s Server) migrationCutoverCancel03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-Cutover-Confirm") != id {
		writeError(w, 400, "exact migration run confirmation required")
		return
	}
	input, ok := migrationRead0331[struct {
		ProfileID        string `json:"profileId"`
		Channel          string `json:"channel"`
		ExpectedRevision int64  `json:"expectedRevision"`
	}](w, r)
	if !ok {
		return
	}
	v, e := store.CancelMigrationCutover03311(r.Context(), id, input.ProfileID, input.Channel, input.ExpectedRevision)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:cutover-cancelled", v.ProjectID+":"+v.ProfileID+":"+v.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
