package httpapi

import (
	"context"
	"errors"
	"fmt"
	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
	"io"
	"net/http"
	"os"
	"strings"

	gi "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

type migrationIdentityStore0334 interface {
	SaveMigrationIdentities0334(context.Context, string, string, string, []gi.Account) (gi.Report, error)
	GetMigrationIdentities0334(context.Context, string) (gi.Report, error)
	VerifyMigrationIdentities0334(context.Context, string) (gi.Report, error)
}

func (s Server) registerMigrationIdentityRoutes0334(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/identities", s.requirePermission("settings:manage", s.migrationIdentityGet0334))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/identities", s.requirePermission("settings:manage", s.migrationIdentityMap0334))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/identities/verify", s.requirePermission("settings:manage", s.migrationIdentityVerify0334))
}
func (s Server) identityStore0334(w http.ResponseWriter) (migrationIdentityStore0334, bool) {
	v, ok := s.Repo.(migrationIdentityStore0334)
	if !ok {
		writeError(w, 503, "identity mapping requires PostgreSQL")
		return nil, false
	}
	return v, true
}
func (s Server) migrationIdentityGet0334(w http.ResponseWriter, r *http.Request) {
	store, ok := s.identityStore0334(w)
	if !ok {
		return
	}
	out, e := store.GetMigrationIdentities0334(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": out})
}
func (s Server) migrationIdentityMap0334(w http.ResponseWriter, r *http.Request) {
	store, ok := s.identityStore0334(w)
	if !ok {
		return
	}
	invStore, ok := s.migrationInventoryStore0333(w)
	if !ok {
		return
	}
	flow, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	id := r.PathValue("runId")
	run, e := flow.GetMigration0331(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if run.Status != "prepared" || run.Step != "source_assessment" || run.SourceKind != "gravit" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	saved, e := invStore.GetMigrationInventory0333(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/zip") {
		writeError(w, 415, "identity mapping expects the same application/zip as inventory")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "identity scanner busy")
		return
	}
	if r.ContentLength > saved.SourceBytes && r.ContentLength >= 0 {
		writeError(w, 413, "source exceeds previously inventoried ZIP")
		return
	}
	// The spool and inspection share the bounded, streaming, untrusted ZIP reader.
	src, size, digest, e := spoolIdentity0334(w, r)
	if e != nil {
		writeError(w, 413, "unable to read source identity ZIP")
		return
	}
	defer func() { src.Close(); _ = os.Remove(src.Name()) }()
	if digest != saved.SourceSHA256 || size != saved.SourceBytes {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	accounts, e := gi.Extract(r.Context(), src, size, saved)
	if e != nil {
		writeError(w, 422, "identity source parse failed: "+e.Error())
		return
	}
	out, e := store.SaveMigrationIdentities0334(r.Context(), id, digest, saved.ManifestSHA256, accounts)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-identities-mapped", run.ProjectID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": out})
}
func (s Server) migrationIdentityVerify0334(w http.ResponseWriter, r *http.Request) {
	store, ok := s.identityStore0334(w)
	if !ok {
		return
	}
	flow, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	run, e := flow.GetMigration0331(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	out, e := store.VerifyMigrationIdentities0334(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-identities-verified", run.ProjectID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": out})
}

func spoolIdentity0334(w http.ResponseWriter, r *http.Request) (*os.File, int64, string, error) {
	if r.ContentLength > inv.MaxSourceBytes {
		return nil, 0, "", errors.New("too large")
	}
	f, n, sha, e := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if e != nil {
		return nil, 0, "", fmt.Errorf("read archive: %w", e)
	}
	if n == 0 {
		f.Close()
		return nil, 0, "", io.ErrUnexpectedEOF
	}
	return f, n, sha, nil
}
