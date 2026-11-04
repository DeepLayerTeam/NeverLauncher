package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// The 0.33.1 executable workers only collect target-state baseline information.
// In particular, 'prepared' does not authorize import, cutover, or rollback.
func (s Server) registerMigrationRoutes0331(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/admin/migration-runs", s.requirePermission("settings:manage", s.migrationCreate0331))
	mux.Handle("GET /api/v1/admin/migration-runs", s.requirePermission("settings:manage", s.migrationList0331))
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}", s.requirePermission("settings:manage", s.migrationGet0331))
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/events", s.requirePermission("settings:manage", s.migrationEvents0331))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/execute", s.requirePermission("settings:manage", s.migrationExecute0331))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/pause", s.requirePermission("settings:manage", s.migrationPause0331))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/resume", s.requirePermission("settings:manage", s.migrationResume0331))
}
func (s Server) migrationStore0331(w http.ResponseWriter) (mw.Store, bool) {
	v, ok := s.Repo.(mw.Store)
	if !ok {
		writeError(w, 503, "durable migration requires PostgreSQL SQLRepository")
		return nil, false
	}
	return v, true
}
func migrationRead0331[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		writeError(w, 400, "invalid migration request JSON")
		return v, false
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		// io.EOF is the only acceptable second decode result.
		writeError(w, 400, "trailing migration request JSON")
		return v, false
	}
	return v, true
}
func migrationHTTPError0331(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mw.ErrNotFound):
		writeError(w, 404, "migration run not found")
	case errors.Is(err, mw.ErrBusy), errors.Is(err, mw.ErrConflict):
		writeError(w, 409, err.Error())
	default:
		writeError(w, 503, "migration repository operation failed")
	}
}
func (s Server) migrationCreate0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	req, ok := migrationRead0331[struct {
		ProjectID      string `json:"projectId"`
		IdempotencyKey string `json:"idempotencyKey"`
		SourceKind     string `json:"sourceKind"`
	}](w, r)
	if !ok {
		return
	}
	if len(req.ProjectID) < 1 || len(req.ProjectID) > 128 || len(req.IdempotencyKey) < 8 || len(req.IdempotencyKey) > 128 || req.SourceKind != "gravit" {
		writeError(w, 400, "projectId, idempotencyKey (8..128), sourceKind=gravit required")
		return
	}
	if _, err := s.Repo.GetProject(req.ProjectID); err != nil {
		writeError(w, 404, "target project not found")
		return
	}
	run, err := store.CreateMigration0331(r.Context(), req.ProjectID, req.SourceKind, req.IdempotencyKey)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "migration:created", req.ProjectID)
	writeJSON(w, 200, map[string]any{"data": run})
}
func (s Server) migrationList0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	project := r.URL.Query().Get("projectId")
	if project == "" || len(project) > 128 {
		writeError(w, 400, "projectId is required")
		return
	}
	result, err := store.ListMigrations0331(r.Context(), project)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"data": result})
}
func (s Server) migrationGet0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	run, err := store.GetMigration0331(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"data": run})
}
func (s Server) migrationEvents0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	id := r.PathValue("runId")
	if _, err := store.GetMigration0331(r.Context(), id); err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if r.URL.Query().Get("after") == "" {
		after = 0
		err = nil
	}
	if err != nil || after < 0 {
		writeError(w, 400, "invalid event cursor")
		return
	}
	events, err := store.MigrationEvents0331(r.Context(), id, after, 100)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"data": events})
}
func migrationOwner0331() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func (s Server) migrationBaseline0331(ctx context.Context, run mw.Run) (json.RawMessage, error) {
	switch run.Step {
	case "target_check":
		project, err := s.Repo.GetProject(run.ProjectID)
		if err != nil {
			return nil, err
		}
		value := map[string]any{"projectId": project.ID, "name": project.Name, "verifiedAt": time.Now().UTC(), "kind": "target-present"}
		return json.Marshal(value)
	case "target_inventory":
		if _, err := s.Repo.GetProject(run.ProjectID); err != nil {
			return nil, err
		}
		profiles, err := s.Repo.ListProfiles(run.ProjectID)
		if err != nil {
			return nil, err
		}
		channels, err := s.Repo.ListChannels(run.ProjectID)
		if err != nil {
			return nil, err
		}
		versions, err := s.Repo.ListVersions(run.ProjectID)
		if err != nil {
			return nil, err
		}
		// Do not include secrets, authentication credentials or user account information.
		inventory := map[string]any{"projectId": run.ProjectID, "profiles": len(profiles), "channels": len(channels), "releases": len(versions), "kind": "target-inventory", "sourceCompatibility": "not-assessed"}
		raw, err := json.Marshal(inventory)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		return json.Marshal(map[string]any{"inventory": inventory, "sha256": hex.EncodeToString(digest[:])})
	default:
		return nil, errors.New("no executable source step registered; run is not migration-complete")
	}
}
func (s Server) migrationExecute0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	id := r.PathValue("runId")
	// Each request executes at most two short, read-only steps; no background
	// goroutine or best-effort job is started after the HTTP response.
	var run mw.Run
	for i := 0; i < 2; i++ {
		owner, err := migrationOwner0331()
		if err != nil {
			writeError(w, 503, "secure lease owner unavailable")
			return
		}
		lease, err := store.ClaimMigration0331(r.Context(), id, owner, 45*time.Second)
		if err != nil {
			if i > 0 {
				break
			}
			migrationHTTPError0331(w, err)
			return
		}
		result, err := s.migrationBaseline0331(r.Context(), lease.Run)
		if err != nil {
			_, failErr := store.FailMigration0331(r.Context(), lease, "baseline step failed: "+err.Error())
			if failErr != nil {
				migrationHTTPError0331(w, failErr)
				return
			}
			writeError(w, 409, "target baseline failed; inspect run and resume after repair")
			return
		}
		run, err = store.CheckpointMigration0331(r.Context(), lease, lease.Run.Step, result)
		if err != nil {
			migrationHTTPError0331(w, err)
			return
		}
		if run.Status == "prepared" {
			break
		}
	}
	if run.ID == "" {
		var err error
		run, err = store.GetMigration0331(r.Context(), id)
		if err != nil {
			migrationHTTPError0331(w, err)
			return
		}
	}
	s.audit(r, s.adminActor(r), "migration:baseline", run.ProjectID)
	writeJSON(w, 200, map[string]any{"data": run})
}
func (s Server) migrationPause0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	run, err := store.PauseMigration0331(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "migration:paused", run.ProjectID)
	writeJSON(w, 200, map[string]any{"data": run})
}
func (s Server) migrationResume0331(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	run, err := store.ResumeMigration0331(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "migration:resumed", run.ProjectID)
	writeJSON(w, 200, map[string]any{"data": run})
}
