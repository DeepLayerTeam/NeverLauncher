package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

type migrationCompatibilityStore0332 interface {
	GetMigrationCompatibility0332(context.Context, string) (gd.Report, error)
	SaveMigrationCompatibility0332(context.Context, string, gd.Report) (gd.Report, error)
}

func (s Server) registerMigrationCompatibilityRoutes0332(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/compatibility", s.requirePermission("settings:manage", s.migrationCompatibilityGet0332))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/compatibility", s.requirePermission("settings:manage", s.migrationCompatibilityAssess0332))
}
func (s Server) migrationCompatibilityStore0332(w http.ResponseWriter) (migrationCompatibilityStore0332, bool) {
	v, ok := s.Repo.(migrationCompatibilityStore0332)
	if !ok {
		writeError(w, 503, "Gravit compatibility inspection requires PostgreSQL")
		return nil, false
	}
	return v, true
}
func (s Server) migrationCompatibilityGet0332(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationCompatibilityStore0332(w)
	if !ok {
		return
	}
	report, err := store.GetMigrationCompatibility0332(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"data": report})
}
func (s Server) migrationCompatibilityAssess0332(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationCompatibilityStore0332(w)
	if !ok {
		return
	}
	workflow, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	id := r.PathValue("runId")
	run, err := workflow.GetMigration0331(r.Context(), id)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if run.SourceKind != "gravit" || run.Step != "source_assessment" || run.Status != "prepared" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	// application/zip binary request, not a path on the backend host; prevents
	// arbitrary file reads and extraction. No uploaded bytes are persisted.
	if t := r.Header.Get("Content-Type"); !strings.EqualFold(strings.TrimSpace(strings.Split(t, ";")[0]), "application/zip") {
		writeError(w, 415, "upload a ZIP as application/zip")
		return
	}
	// The same two-slot bounded staging and ZIP validation as inventory.
	// Do not buffer an entire 512 MiB modpack into the API process.
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "source inspection capacity is busy; retry after another upload finishes")
		return
	}
	if r.ContentLength > gd.MaxArchiveBytes {
		writeError(w, 413, "Gravit source ZIP exceeds 512 MiB")
		return
	}
	src, size, digest, err := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, gd.MaxArchiveBytes))
	if err != nil {
		writeError(w, 413, "unable to stage bounded Gravit ZIP: "+err.Error())
		return
	}
	defer func() { src.Close(); _ = os.Remove(src.Name()) }()
	report, err := gd.AssessReader(r.Context(), src, size, digest, r.Header.Get("X-Gravit-Version"))
	if err != nil {
		writeError(w, 422, "invalid Gravit source archive: "+err.Error())
		return
	}
	saved, err := store.SaveMigrationCompatibility0332(r.Context(), id, report)
	if err != nil {
		if errors.Is(err, mw.ErrBusy) || errors.Is(err, mw.ErrConflict) || errors.Is(err, mw.ErrNotFound) {
			migrationHTTPError0331(w, err)
		} else {
			writeError(w, 503, "unable to persist compatibility report")
		}
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-compatibility", run.ProjectID)
	writeJSON(w, 200, map[string]any{"data": saved})
}
