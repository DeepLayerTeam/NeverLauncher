package httpapi

import (
	"context"
	"encoding/json"
	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
	"io"
	"net/http"
	"time"
)

type migrationRehearsalStore03310 interface {
	GetMigrationRehearsal03310(context.Context, string) (gr.Report, error)
	SaveMigrationRehearsal03310(context.Context, string, gr.Report) (gr.Report, error)
}

func (s Server) registerMigrationRehearsalRoutes03310(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/rehearsal", s.requirePermission("settings:manage", s.migrationRehearsalGet03310))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/rehearsal", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationRehearsalPost03310))
}
func (s Server) migrationRehearsalGet03310(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(migrationRehearsalStore03310)
	if !ok {
		writeError(w, 503, "rehearsal requires PostgreSQL")
		return
	}
	run, e := s.migrationStoreRead03310(w, r)
	if e != nil {
		return
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "project:read", run.ProjectID, "project", run.ProjectID) {
		return
	}
	v, e := store.GetMigrationRehearsal03310(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
func (s Server) migrationRehearsalPost03310(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(migrationRehearsalStore03310)
	if !ok {
		writeError(w, 503, "rehearsal requires PostgreSQL")
		return
	}
	run, e := s.migrationStoreRead03310(w, r)
	if e != nil {
		return
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "settings:manage", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if r.Header.Get("X-Migration-Rehearsal-Confirm") != run.ID {
		writeError(w, 400, "run confirmation required")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, 415, "expected application/json")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, gr.MaxReportBytes))
	dec.DisallowUnknownFields()
	var report gr.Report
	if e = dec.Decode(&report); e != nil {
		writeError(w, 400, "invalid rehearsal evidence")
		return
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		writeError(w, 400, "trailing rehearsal evidence")
		return
	}
	saved, e := store.SaveMigrationRehearsal03310(r.Context(), run.ID, report)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-rehearsal-checked", run.ProjectID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": saved})
}
func (s Server) migrationStoreRead03310(w http.ResponseWriter, r *http.Request) (struct{ ID, ProjectID string }, error) {
	result := struct{ ID, ProjectID string }{}
	store, ok := s.migrationStore0331(w)
	if !ok {
		return result, context.Canceled
	}
	run, e := store.GetMigration0331(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return result, e
	}
	result.ID, result.ProjectID = run.ID, run.ProjectID
	return result, nil
}
