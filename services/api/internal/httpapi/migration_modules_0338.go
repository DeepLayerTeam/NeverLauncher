package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

type migrationModulesStore0338 interface {
	GetMigrationModules0338(context.Context, string) (gm.Report, error)
	SaveMigrationModules0338(context.Context, string, gm.Report) (gm.Report, error)
	GetMigrationWrapperEnrollment0338(context.Context, string, string) (string, string, error)
	RecordMigrationWrapperEnrollment0338(context.Context, string, string, string, string) error
}

func (s Server) registerMigrationModulesRoutes0338(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/modules", s.requirePermission("settings:manage", s.migrationModulesGet0338))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/modules/analyze", s.requirePermission("settings:manage", s.migrationModulesAnalyze0338))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/modules/enroll-serverbridge", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationModulesEnroll0338))
}
func (s Server) migrationModulesStore0338(w http.ResponseWriter) (migrationModulesStore0338, bool) {
	v, ok := s.Repo.(migrationModulesStore0338)
	if !ok {
		writeError(w, 503, "Gravit MIG08 requires PostgreSQL")
		return nil, false
	}
	return v, true
}
func (s Server) migrationModulesGet0338(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationModulesStore0338(w)
	if !ok {
		return
	}
	report, err := store.GetMigrationModules0338(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
func (s Server) migrationModulesAnalyze0338(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationModulesStore0338(w)
	if !ok {
		return
	}
	runs, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	inventoryStore, ok := s.migrationInventoryStore0333(w)
	if !ok {
		return
	}
	run, err := runs.GetMigration0331(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if run.SourceKind != "gravit" || run.Status != "prepared" || run.Step != "source_assessment" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "project:read", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/zip") {
		writeError(w, 415, "expected application/zip")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "inventory upload capacity exhausted")
		return
	}
	snapshot, err := inventoryStore.GetMigrationInventory0333(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if r.ContentLength > inv.MaxSourceBytes || (r.ContentLength >= 0 && r.ContentLength != snapshot.SourceBytes) {
		writeError(w, 413, "ZIP size differs from inventoried source")
		return
	}
	file, n, digest, err := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if err != nil {
		writeError(w, 413, "unable to spool source ZIP")
		return
	}
	defer func() { file.Close(); os.Remove(file.Name()) }()
	if n != snapshot.SourceBytes || digest != snapshot.SourceSHA256 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	report, err := gm.Analyze(r.Context(), file, n, snapshot)
	if err != nil {
		writeError(w, 422, "module inspection: "+err.Error())
		return
	}
	saved, err := store.SaveMigrationModules0338(r.Context(), run.ID, report)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-modules-reviewed", run.ProjectID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": saved})
}

var migrationSafeServerID0338 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type moduleEnrollmentRequest0338 struct {
	WrapperPath string `json:"wrapperPath"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	ProfileID   string `json:"profileId"`
	PublicKey   string `json:"publicKey"`
}

// Real ServerBridge registration (with a newly generated Ed25519 public key),
// NEVER adoption of a Gravit checkServer token. A durable enrollment receipt
// makes retries observable if registration succeeded but the response was lost.
func (s Server) migrationModulesEnroll0338(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationModulesStore0338(w)
	if !ok {
		return
	}
	runs, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	run, err := runs.GetMigration0331(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if run.SourceKind != "gravit" || run.Status != "prepared" || run.Step != "source_assessment" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "settings:manage", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if r.Header.Get("X-Migration-Modules-Confirm") != run.ID || r.Header.Get("X-Migration-Fresh-Keys-Confirmed") != "true" {
		writeError(w, 400, "explicit migration run confirmation required")
		return
	}
	report, err := store.GetMigrationModules0338(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if !report.Ready || len(report.Blockers) != 0 {
		writeError(w, 409, "unresolved module blockers; enrollment denied")
		return
	}
	var req moduleEnrollmentRequest0338
	if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeError(w, 400, "invalid enrollment JSON")
		return
	}
	found := false
	for _, v := range report.Wrappers {
		if v.Path == req.WrapperPath && v.Status == "manual" {
			found = true
			break
		}
	}
	if !found || !migrationSafeServerID0338.MatchString(req.ID) || !migrationSafeServerID0338.MatchString(req.ProfileID) || req.Kind == "" || req.PublicKey == "" || len(req.Name) > 128 {
		writeError(w, 422, "invalid wrapper or ServerBridge enrollment request")
		return
	}
	_, key, fingerprint, err := validateBridgeNodeIdentity0142("ed25519", req.PublicKey)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	// An already enrolled node is only reusable when its independent identity
	// and ownership exactly match; unrelated IDs are never silently adopted.
	previousID, previousFP, lookupErr := store.GetMigrationWrapperEnrollment0338(r.Context(), run.ID, req.WrapperPath)
	if lookupErr == nil && (previousID != req.ID || previousFP != fingerprint) {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	if lookupErr != nil && !errors.Is(lookupErr, mw.ErrNotFound) {
		migrationHTTPError0331(w, lookupErr)
		return
	}
	node, existingErr := s.State.ServerBridge.getNode0142(req.ID)
	if existingErr == nil {
		if lookupErr != nil || node.ProjectID != run.ProjectID || node.ProfileID != req.ProfileID || node.KeyFingerprint != fingerprint {
			migrationHTTPError0331(w, mw.ErrConflict)
			return
		}
	} else {
		if !errors.Is(existingErr, os.ErrNotExist) && !isBridgeNotFoundV2(existingErr) {
			writeError(w, 503, "ServerBridge lookup failed")
			return
		}
		// Persist an immutable enrollment intent BEFORE the external
		// ServerBridge write. On a crash, only a node tied to that intent
		// can be adopted by the same run with the exact same public key.
		if err = store.RecordMigrationWrapperEnrollment0338(r.Context(), run.ID, req.WrapperPath, req.ID, fingerprint); err != nil {
			migrationHTTPError0331(w, err)
			return
		}
		node, err = s.State.ServerBridge.registerServer(registerBridgeServerRequest{ID: req.ID, Name: req.Name, Kind: req.Kind, ProjectID: run.ProjectID, ProfileID: req.ProfileID, KeyAlgorithm: "ed25519", PublicKey: key})
		if err != nil {
			writeError(w, 409, "ServerBridge registration: "+err.Error())
			return
		}
	}
	_ = s.flushPersistenceState950("migration-serverbridge-enroll")
	s.audit(r, s.adminActor(r), "migration:serverbridge-new-identity", run.ProjectID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": map[string]any{"serverId": node.ID, "projectId": run.ProjectID, "profileId": req.ProfileID, "keyFingerprint": fingerprint, "status": "registered-new-trust", "requiresFreshHeartbeat": true}})
}
