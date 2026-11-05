package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	gp "gitflic.ru/skif4er/launcher/services/api/internal/gravitplan"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

type migrationPlanStore0442 interface {
	GetMigrationPlan0442(context.Context, string) (gp.Plan, error)
	SaveMigrationPlan0442(context.Context, gp.Plan) (gp.Plan, error)
}

func (s Server) registerMigrationPlanRoutes0442(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/dry-run", s.requirePermission("settings:manage", s.migrationDryRun0442))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/dry-run-all", s.requirePermission("settings:manage", s.migrationBatch0492))
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/dry-run", s.requirePermission("settings:manage", s.migrationPlanGet0442))
}
func (s Server) migrationTargetSnapshot0442(projectID string) (string, map[string]bool, error) {
	project, e := s.Repo.GetProject(projectID)
	if e != nil {
		return "", nil, e
	}
	profiles, e := s.Repo.ListProfiles(projectID)
	if e != nil {
		return "", nil, e
	}
	channels, e := s.Repo.ListChannels(projectID)
	if e != nil {
		return "", nil, e
	}
	releases, e := s.Repo.ListVersions(projectID)
	if e != nil {
		return "", nil, e
	}
	pids := map[string]bool{}
	items := make([]string, 0, len(profiles)+len(channels)+len(releases)+1)
	encode := func(v any) error {
		b, er := json.Marshal(v)
		if er == nil {
			items = append(items, string(b))
		}
		return er
	}
	if e = encode(project); e != nil {
		return "", nil, e
	}
	for _, p := range profiles {
		pids[p.ID] = true
		if e = encode(p); e != nil {
			return "", nil, e
		}
	}
	for _, c := range channels {
		if e = encode(c); e != nil {
			return "", nil, e
		}
	}
	for _, v := range releases {
		if e = encode(v); e != nil {
			return "", nil, e
		}
	}
	sort.Strings(items)
	b, e := json.Marshal(items)
	if e != nil {
		return "", nil, e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), pids, nil
}
func (s Server) migrationPlanGet0442(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(migrationPlanStore0442)
	if !ok {
		writeError(w, 503, "Для сохраняемого плана миграции требуется PostgreSQL")
		return
	}
	run, e := s.migrationStoreRead03310(w, r)
	if e != nil {
		return
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "project:read", run.ProjectID, "project", run.ProjectID) {
		return
	}
	p, e := store.GetMigrationPlan0442(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	digest, _, e := s.migrationTargetSnapshot0442(run.ProjectID)
	if e != nil {
		writeError(w, 503, "cannot verify current target")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": struct {
		gp.Plan
		TargetUnchanged bool `json:"targetUnchanged"`
	}{p, p.TargetSHA256 == digest}})
}
func (s Server) migrationDryRun0442(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(migrationPlanStore0442)
	if !ok {
		writeError(w, 503, "Для сохраняемого плана миграции требуется PostgreSQL")
		return
	}
	runs, ok := s.migrationStore0331(w)
	if !ok {
		return
	}
	invStore, ok := s.migrationInventoryStore0333(w)
	if !ok {
		return
	}
	compatStore, ok := s.migrationCompatibilityStore0332(w)
	if !ok {
		return
	}
	run, e := runs.GetMigration0331(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if run.SourceKind != "gravit" || run.Step != "source_assessment" || run.Status != "prepared" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "project:read", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/zip") {
		writeError(w, 415, "Ожидается тип содержимого application/zip")
		return
	}
	path, id, name, loader, channel, version := migrationContentHeaders0337(r)
	if path == "" || id == "" || loader == "" || channel == "" || version == "" || len(path) > 1024 || len(id) > 128 || len(name) > 120 || len(loader) > 24 || len(channel) > 128 || len(version) > 128 {
		writeError(w, 400, "target profile/path/loader/channel/version required")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "Достигнут предел загрузки перечня файлов")
		return
	}
	saved, e := invStore.GetMigrationInventory0333(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	previous, e := compatStore.GetMigrationCompatibility0332(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if r.ContentLength > inv.MaxSourceBytes || (r.ContentLength >= 0 && r.ContentLength != saved.SourceBytes) {
		writeError(w, 413, "source size differs from approved inventory")
		return
	}
	f, n, digest, e := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if e != nil {
		writeError(w, 413, "unable to stage verified source ZIP")
		return
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if digest != saved.SourceSHA256 || n != saved.SourceBytes || previous.SourceSHA256 != digest {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	actual, e := inv.Inspect(r.Context(), f, n, digest)
	if e != nil {
		writeError(w, 422, "source validation failed: "+e.Error())
		return
	}
	if actual.ManifestSHA256 != saved.ManifestSHA256 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	compat, e := gd.AssessReader(r.Context(), f, n, digest, previous.ClaimedVersion)
	if e != nil {
		writeError(w, 422, "compatibility analysis failed: "+e.Error())
		return
	}
	if compat.FilesSHA256 != previous.FilesSHA256 || compat.VersionStatus != previous.VersionStatus || compat.DetectedVersion != previous.DetectedVersion {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	modules, e := gm.Analyze(r.Context(), f, n, saved)
	if e != nil {
		writeError(w, 422, "Не удалось проверить модуль: "+e.Error())
		return
	}
	content, e := gc.Prepare(r.Context(), f, n, saved, path, run.ProjectID, id, name, loader, strings.TrimSpace(r.Header.Get("X-Loader-Version")))
	if e != nil {
		writeError(w, 422, "content preview failed: "+e.Error())
		return
	}
	ids := gp.IdentityPreview{State: "blocked", Reason: "no supported source identity snapshot"}
	accounts, identityErr := gi.Extract(r.Context(), f, n, saved)
	if identityErr != nil {
		ids.Reason = identityErr.Error()
	} else {
		_, summary := gi.Reconcile(accounts, nil)
		ids.SourceAccounts = len(accounts)
		ids.DuplicateOrConflicting = summary["blocked"]
		if ids.DuplicateOrConflicting > 0 {
			ids.Reason = "duplicate UUID, provider ID or username in source accounts"
		} else {
			ids.State = "review_required"
			ids.Reason = "source IDs extracted; target UUID ownership and password verifiers still require independent reconciliation"
		}
	}
	target, existing, e := s.migrationTargetSnapshot0442(run.ProjectID)
	if e != nil {
		writeError(w, 503, "Целевой снимок недоступен")
		return
	}
	d := gp.Destination{ProfilePath: path, ProfileID: id, ProfileName: name, Loader: loader, LoaderVersion: strings.TrimSpace(r.Header.Get("X-Loader-Version")), Channel: channel, Version: version}
	p, e := gp.Build(run.ID, run.ProjectID, target, d, saved, compat, modules, content, existing[id], ids)
	if e != nil {
		writeError(w, 422, "cannot calculate migration plan: "+e.Error())
		return
	}
	// Отклоняйте целевой объект, изменившийся во время потенциально длительного
	// анализа источника.
	latest, _, e := s.migrationTargetSnapshot0442(run.ProjectID)
	if e != nil || latest != target {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	p, e = store.SaveMigrationPlan0442(r.Context(), p)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:dry-run", run.ID+":"+p.PlanSHA256)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": struct {
		gp.Plan
		TargetUnchanged bool `json:"targetUnchanged"`
	}{p, true}})
}
func (s Server) migrationCheckContentPlan0442(ctx context.Context, runID, expectedDigest string, d gp.Destination, content gc.Plan) error {
	store, ok := s.Repo.(migrationPlanStore0442)
	if !ok {
		return mw.ErrConflict
	}
	if len(expectedDigest) != 64 {
		return mw.ErrConflict
	}
	p, e := store.GetMigrationPlan0442(ctx, runID)
	if e != nil {
		return e
	}
	if p.PlanSHA256 != expectedDigest || p.Status == "blocked" || p.Destination != d || p.Content.FilesSHA256 != content.FilesSHA256 || p.Content.Ready != content.Ready || p.SourceSHA256 != content.SourceSHA256 || p.InventorySHA256 != content.InventorySHA256 {
		return mw.ErrConflict
	}
	current, _, e := s.migrationTargetSnapshot0442(p.ProjectID)
	if e != nil {
		return e
	}
	if current != p.TargetSHA256 {
		// После успешного импорта новый профиль меняет целевой хеш. Разрешайте только
		// идемпотентный повтор импорта строго того же содержимого.
		contentStore, ok := s.Repo.(migrationContentStore0337)
		if !ok {
			return mw.ErrConflict
		}
		previous, ws, err := contentStore.GetMigrationContent0337(ctx, runID, d.ProfilePath)
		if err != nil || previous.FilesSHA256 != content.FilesSHA256 || previous.SourceSHA256 != content.SourceSHA256 ||
			ws.ProfileID != d.ProfileID || ws.Channel != d.Channel || ws.Version != d.Version || ws.ProjectID != p.ProjectID {
			return mw.ErrConflict
		}
	}
	return nil
}
