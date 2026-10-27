package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"

	gc "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcredentials"
	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

type migrationAuthStore0335 interface {
	ImportMigrationCredentials0335(context.Context, string, string, string, []gc.Credential, bool) (gc.Result, error)
	GetMigrationCredentials0335(context.Context, string) (gc.Result, error)
}

func (s Server) registerMigrationAuthRoutes0335(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/credentials", s.requirePermission("settings:manage", s.migrationAuthGet0335))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/credentials/preview", s.requirePermission("settings:manage", s.migrationAuthPreview0335))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/credentials/import", s.requirePermission("settings:manage", s.migrationAuthImport0335))
}
func (s Server) migrationAuthGet0335(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(migrationAuthStore0335)
	if !ok {
		writeError(w, 503, "auth migration requires PostgreSQL")
		return
	}
	report, e := store.GetMigrationCredentials0335(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
func (s Server) migrationAuthPreview0335(w http.ResponseWriter, r *http.Request) {
	s.migrationAuthUpload0335(w, r, true)
}
func (s Server) migrationAuthImport0335(w http.ResponseWriter, r *http.Request) {
	s.migrationAuthUpload0335(w, r, false)
}
func (s Server) migrationAuthUpload0335(w http.ResponseWriter, r *http.Request, dryRun bool) {
	store, ok := s.Repo.(migrationAuthStore0335)
	if !ok {
		writeError(w, 503, "auth migration requires PostgreSQL")
		return
	}
	flow, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	inventoryStore, ok := s.migrationInventoryStore0333(w)
	if !ok {
		return
	}
	identityStore, ok := s.identityStore0334(w)
	if !ok {
		return
	}
	run, e := flow.GetMigration0331(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if run.Status != "prepared" || run.Step != "source_assessment" || run.SourceKind != "gravit" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	if !dryRun && r.Header.Get("X-Migration-Import-Confirm") != run.ID {
		writeError(w, 400, "explicit X-Migration-Import-Confirm run ID is required")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/zip") {
		writeError(w, 415, "source ZIP must use application/zip")
		return
	}
	algorithm := strings.TrimSpace(r.Header.Get("X-Gravit-Password-Format"))
	if len(algorithm) > 40 {
		writeError(w, 400, "invalid FileAuth password format")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "source reader capacity exceeded")
		return
	}
	snapshot, e := inventoryStore.GetMigrationInventory0333(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	mapping, e := identityStore.GetMigrationIdentities0334(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if mapping.Summary["blocked"] > 0 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	if r.ContentLength > inv.MaxSourceBytes {
		writeError(w, 413, "source archive exceeds inventory limit")
		return
	}
	src, n, sha, e := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if e != nil {
		writeError(w, 413, "could not stage source archive")
		return
	}
	defer func() { _ = src.Close(); _ = os.Remove(src.Name()) }()
	if sha != snapshot.SourceSHA256 || n != snapshot.SourceBytes || sha != mapping.SourceSHA256 || snapshot.ManifestSHA256 != mapping.InventorySHA256 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	credentials, e := gc.Extract(r.Context(), src, n, snapshot, algorithm)
	if e != nil {
		writeError(w, 422, "unsupported credential source: "+e.Error())
		return
	}
	result, e := store.ImportMigrationCredentials0335(r.Context(), run.ID, sha, algorithm, credentials, dryRun)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if !dryRun {
		s.audit(r, s.adminActor(r), "migration:gravit-credentials-import", run.ProjectID)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": result})
}
