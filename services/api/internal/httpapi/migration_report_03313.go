package httpapi

import (
	"context"
	"net/http"
	"time"

	rr "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitreport"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type migrationReportStore03313 interface {
	BuildMigrationReport03313(context.Context, string) (rr.Report, error)
	ReviewMigrationReport03313(context.Context, string, string, string, string, string) (repository.MigrationReview03313, error)
	GetReviewedMigrationReport03313(context.Context, string) (repository.MigrationReview03313, error)
}

func (s Server) registerMigrationReportRoutes03313(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/report", s.requirePermission("settings:manage", s.migrationReportGet03313))
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/report/review", s.requirePermission("settings:manage", s.migrationReportReviewGet03313))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/report/review", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationReportReview03313))
}
func (s Server) migrationReportAccess03313(w http.ResponseWriter, r *http.Request) (migrationReportStore03313, string, bool) {
	store, ok := s.Repo.(migrationReportStore03313)
	if !ok {
		writeError(w, 503, "migration reports require PostgreSQL")
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
func (s Server) migrationReportGet03313(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.migrationReportAccess03313(w, r)
	if !ok {
		return
	}
	report, e := store.BuildMigrationReport03313(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
func (s Server) migrationReportReviewGet03313(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.migrationReportAccess03313(w, r)
	if !ok {
		return
	}
	report, e := store.GetReviewedMigrationReport03313(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
func (s Server) migrationReportReview03313(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.migrationReportAccess03313(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-RC-Confirm") != id {
		writeError(w, 400, "exact migration run ID confirmation required")
		return
	}
	input, ok := migrationRead0331[struct {
		ReportSHA256      string `json:"reportSha256"`
		EvidenceSHA256    string `json:"evidenceSha256"`
		EvidenceReference string `json:"evidenceReference"`
	}](w, r)
	if !ok {
		return
	}
	if len(input.ReportSHA256) != 64 || len(input.EvidenceSHA256) != 64 {
		writeError(w, 400, "SHA-256 report and evidence required")
		return
	}
	out, e := store.ReviewMigrationReport03313(r.Context(), id, input.ReportSHA256, s.adminActor(r), input.EvidenceReference, input.EvidenceSHA256)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	// A human review is deliberately NOT a GA compatibility/cutover certificate.
	s.audit(r, s.adminActor(r), "migration:rc-reviewed", id+":"+input.ReportSHA256)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": out})
}
