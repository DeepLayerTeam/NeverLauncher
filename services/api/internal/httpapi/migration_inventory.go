package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// Limits concurrent temporary ZIP staging to protect a production API host.
var gravitinventorySlots0333 = make(chan struct{}, 2)

type migrationInventoryStore0333 interface {
	GetMigrationInventory0333(context.Context, string) (inv.Inventory, error)
	SaveMigrationInventory0333(context.Context, string, inv.Inventory) (inv.Inventory, error)
}

func (s Server) registerMigrationInventoryRoutes0333(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/inventory", s.requirePermission("settings:manage", s.migrationInventoryGet0333))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/inventory", s.requirePermission("settings:manage", s.migrationInventoryPost0333))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/export", s.requirePermission("settings:manage", s.migrationInventoryExport0333))
}
func (s Server) migrationInventoryStore0333(w http.ResponseWriter) (migrationInventoryStore0333, bool) {
	store, ok := s.Repo.(migrationInventoryStore0333)
	if !ok {
		writeError(w, 503, "Gravit source inventory requires PostgreSQL")
		return nil, false
	}
	return store, true
}
func (s Server) migrationInventoryGet0333(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationInventoryStore0333(w)
	if !ok {
		return
	}
	v, e := store.GetMigrationInventory0333(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}

// Source is not kept server-side; spool only for the duration of the request.
// No local paths, credentials or source content enter logs/database.
func (s Server) migrationInventoryUpload0333(w http.ResponseWriter, r *http.Request, export bool) {
	store, ok := s.migrationInventoryStore0333(w)
	if !ok {
		return
	}
	workflow, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	id := r.PathValue("runId")
	run, e := workflow.GetMigration0331(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if run.Status != "prepared" || run.Step != "source_assessment" || run.SourceKind != "gravit" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/zip") {
		writeError(w, 415, "upload a ZIP as application/zip")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "source inventory capacity is busy; retry after another upload finishes")
		return
	}
	if r.ContentLength > inv.MaxSourceBytes {
		writeError(w, 413, "source ZIP exceeds 512 MiB")
		return
	}
	src, n, digest, e := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if e != nil {
		writeError(w, 413, "unable to read bounded source ZIP: "+e.Error())
		return
	}
	defer func() { src.Close(); _ = os.Remove(src.Name()) }()
	report, e := inv.Inspect(r.Context(), src, n, digest)
	if e != nil {
		writeError(w, 422, "source inventory failed: "+e.Error())
		return
	}
	if !export {
		saved, e := store.SaveMigrationInventory0333(r.Context(), id, report)
		if e != nil {
			migrationHTTPError0331(w, e)
			return
		}
		s.audit(r, s.adminActor(r), "migration:gravit-source-inventory", run.ProjectID)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"data": saved})
		return
	}
	saved, e := store.GetMigrationInventory0333(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if saved.SourceSHA256 != digest || saved.ManifestSHA256 != report.ManifestSHA256 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	// Preflight checks completed before writing the response. The exported ZIP
	// may be large: stream with backpressure, never buffer it in memory.
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="gravit-source-verified.zip"`)
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Migration-Manifest-SHA256", saved.ManifestSHA256)
	w.WriteHeader(http.StatusOK)
	if err := inv.Export(r.Context(), w, src, n, saved); err != nil {
		// The client must treat an interrupted/truncated download as failure.
		// No second HTTP status can be sent once streaming has started.
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-source-export", run.ProjectID)
}
func (s Server) migrationInventoryPost0333(w http.ResponseWriter, r *http.Request) {
	s.migrationInventoryUpload0333(w, r, false)
}
func (s Server) migrationInventoryExport0333(w http.ResponseWriter, r *http.Request) {
	s.migrationInventoryUpload0333(w, r, true)
}
