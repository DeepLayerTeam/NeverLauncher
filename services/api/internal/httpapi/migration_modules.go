package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	gp "gitflic.ru/skif4er/launcher/services/api/internal/gravitplan"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
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
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/modules/serverbridge-status", s.requirePermission("settings:manage", s.migrationModulesBridgeStatus0446))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/modules/enroll-serverbridge", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationModulesEnroll0338))
}
func (s Server) migrationModulesStore0338(w http.ResponseWriter) (migrationModulesStore0338, bool) {
	v, ok := s.Repo.(migrationModulesStore0338)
	if !ok {
		writeError(w, 503, "Для Gravit MIG08 необходим PostgreSQL")
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
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "Исчерпана ёмкость загрузки инвентаризации")
		return
	}
	snapshot, err := inventoryStore.GetMigrationInventory0333(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if r.ContentLength > inv.MaxSourceBytes || (r.ContentLength >= 0 && r.ContentLength != snapshot.SourceBytes) {
		writeError(w, 413, "Размер ZIP не соответствует инвентаризованному источнику")
		return
	}
	file, n, digest, err := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if err != nil {
		writeError(w, 413, "Не удалось сохранить исходный ZIP во временное хранилище")
		return
	}
	defer func() { file.Close(); os.Remove(file.Name()) }()
	if n != snapshot.SourceBytes || digest != snapshot.SourceSHA256 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	report, err := gm.Analyze(r.Context(), file, n, snapshot)
	if err != nil {
		writeError(w, 422, "Проверка модулей: "+err.Error())
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

// Настоящая регистрация ServerBridge с новым открытым ключом Ed25519,
// а НЕ принятие токена Gravit checkServer. Устойчивая квитанция регистрации
// позволяет отследить повтор при успешной записи, если ответ потерялся.
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
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "settings:manage", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if r.Header.Get("X-Migration-Modules-Confirm") != run.ID || r.Header.Get("X-Migration-Fresh-Keys-Confirmed") != "true" {
		writeError(w, 400, "Необходимо явно подтвердить запуск миграции")
		return
	}
	report, err := store.GetMigrationModules0338(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if !report.Ready || len(report.Blockers) != 0 {
		writeError(w, 409, "Есть неустранённые препятствия в модулях; регистрация отклонена")
		return
	}
	var req moduleEnrollmentRequest0338
	if err = decodeMigrationEnrollment0446(http.MaxBytesReader(w, r.Body, 8192), &req); err != nil {
		writeError(w, 400, "Некорректный JSON регистрации")
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
		writeError(w, 422, "Некорректная оболочка или запрос регистрации ServerBridge")
		return
	}
	// Регистрация должна относиться к профилю, который оператор действительно
	// просмотрел и импортировал. Одного разрешения на проект недостаточно, чтобы
	// привязать новый игровой узел к любому его профилю.
	if err = s.migrationBridgeTarget0446(r.Context(), run.ID, run.ProjectID, req.ProfileID, report); err != nil {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	if !validBridgeServerKindV2(strings.ToLower(strings.TrimSpace(req.Kind))) {
		writeError(w, 422, "Неподдерживаемый тип ServerBridge")
		return
	}
	_, key, fingerprint, err := validateBridgeNodeIdentity0142("ed25519", req.PublicKey)
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	// Уже зарегистрированный узел можно использовать повторно лишь при точном
	// совпадении его независимой идентичности и владельца; посторонние ID не принимаются.
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
			writeError(w, 503, "Не удалось найти ServerBridge")
			return
		}
		// Сохраняем неизменяемое намерение регистрации ДО внешней записи
		// в ServerBridge. После сбоя тот же запуск может принять только узел,
		// связанный с этим намерением и точно тем же открытым ключом.
		if err = store.RecordMigrationWrapperEnrollment0338(r.Context(), run.ID, req.WrapperPath, req.ID, fingerprint); err != nil {
			migrationHTTPError0331(w, err)
			return
		}
		node, err = s.State.ServerBridge.registerServer(registerBridgeServerRequest{ID: req.ID, Name: req.Name, Kind: req.Kind, ProjectID: run.ProjectID, ProfileID: req.ProfileID, KeyAlgorithm: "ed25519", PublicKey: key})
		if err != nil {
			writeError(w, 409, "Регистрация ServerBridge: "+err.Error())
			return
		}
	}
	if err = s.flushPersistenceState950("migration-serverbridge-enroll"); err != nil {
		writeError(w, 503, "Сохранение регистрации ServerBridge не подтверждено; повторите тот же запрос")
		return
	}
	s.audit(r, s.adminActor(r), "migration:serverbridge-new-identity", run.ProjectID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": map[string]any{"serverId": node.ID, "projectId": run.ProjectID, "profileId": req.ProfileID, "keyFingerprint": fingerprint, "status": "registered-new-trust", "requiresFreshHeartbeat": true}})
}

// migrationBridgeTarget0446 привязывает новый узел к точно закреплённому плану
// миграции И уже сохранённому импортированному клиентскому профилю.
// На основе предварительного просмотра или постороннего профиля узел не создаётся.
func (s Server) migrationBridgeTarget0446(ctx context.Context, runID, projectID, profileID string, modules gm.Report) error {
	plans, ok := s.Repo.(interface {
		GetMigrationPlan0442(context.Context, string) (gp.Plan, error)
	})
	if !ok {
		return mw.ErrConflict
	}
	contents, ok := s.Repo.(interface {
		GetMigrationContent0337(context.Context, string, string) (gc.Plan, repository.BuildWorkspace, error)
	})
	if !ok {
		return mw.ErrConflict
	}
	p, err := plans.GetMigrationPlan0442(ctx, runID)
	if err != nil {
		return err
	}
	if p.Status == "blocked" || p.ProjectID != projectID || p.Destination.ProfileID != profileID ||
		p.SourceSHA256 != modules.SourceSHA256 || p.InventorySHA256 != modules.InventorySHA256 ||
		!modulesMatch0446(p.Modules, modules) {
		return mw.ErrConflict
	}
	content, workspace, err := contents.GetMigrationContent0337(ctx, runID, p.Destination.ProfilePath)
	if err != nil {
		return err
	}
	if content.SourceSHA256 != p.SourceSHA256 || content.InventorySHA256 != p.InventorySHA256 ||
		workspace.ProjectID != projectID || workspace.ProfileID != profileID ||
		content.Profile.Profile.ID != profileID || content.Profile.Profile.ProjectID != projectID {
		return mw.ErrConflict
	}
	return nil
}

func modulesMatch0446(a, b gm.Report) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && string(x) == string(y)
}

// Резервирование регистрации НЕ доказывает наличие активного соединения ServerBridge.
// Проверяем фактическое состояние узла после подписанного heartbeat среды выполнения;
// наличие строки БД или открытого ключа само по себе не означает готовности.
func migrationBridgeLive0446(node bridgeServerRecord, project, profile, fingerprint string, now time.Time) (string, string) {
	if node.ProjectID != project || node.ProfileID != profile || node.KeyAlgorithm != "ed25519" || node.KeyFingerprint != fingerprint || node.IdentityEpoch < 1 {
		return "blocked", "identity_or_ownership_mismatch"
	}
	if node.Status != "active" {
		return "blocked", "node_not_active"
	}
	if node.RuntimeID == "" || node.RuntimeEpoch < 1 || node.RuntimeIdentityDigest == "" {
		return "awaiting_runtime", "signed_runtime_not_observed"
	}
	if node.LastHeartbeatAt.IsZero() || node.RuntimeLastSeenAt.IsZero() ||
		node.LastHeartbeatAt.Before(now.Add(-90*time.Second)) || node.LastHeartbeatAt.After(now.Add(30*time.Second)) ||
		node.RuntimeLastSeenAt.Before(now.Add(-90*time.Second)) || node.RuntimeLastSeenAt.After(now.Add(30*time.Second)) ||
		node.LastHeartbeatAt.Before(node.IdentityRotatedAt) {
		return "awaiting_runtime", "signed_runtime_heartbeat_stale"
	}
	return "online", "signed_runtime_heartbeat_fresh"
}

func (s Server) migrationModulesBridgeStatus0446(w http.ResponseWriter, r *http.Request) {
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
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "project:read", run.ProjectID, "project", run.ProjectID) {
		return
	}
	path := r.URL.Query().Get("wrapperPath")
	if len(path) == 0 || len(path) > 2048 {
		writeError(w, 422, "Требуется wrapperPath")
		return
	}
	report, err := store.GetMigrationModules0338(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	valid := false
	for _, wrapper := range report.Wrappers {
		if wrapper.Path == path && wrapper.Status == "manual" {
			valid = true
			break
		}
	}
	if !valid {
		writeError(w, 422, "Оболочка отсутствует в закреплённой оценке миграции")
		return
	}
	serverID, fingerprint, err := store.GetMigrationWrapperEnrollment0338(r.Context(), run.ID, path)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	plans, ok := s.Repo.(interface {
		GetMigrationPlan0442(context.Context, string) (gp.Plan, error)
	})
	if !ok {
		writeError(w, 503, "Требуется сохранённый план миграции")
		return
	}
	plan, err := plans.GetMigrationPlan0442(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if err = s.migrationBridgeTarget0446(r.Context(), run.ID, run.ProjectID, plan.Destination.ProfileID, report); err != nil {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	state, reason := "blocked", "node_lookup_failed"
	if node, e := s.State.ServerBridge.getNode0142(serverID); e == nil {
		state, reason = migrationBridgeLive0446(node, run.ProjectID, plan.Destination.ProfileID, fingerprint, time.Now().UTC())
	} else if errors.Is(e, repository.ErrNotFound) || errors.Is(e, os.ErrNotExist) {
		state, reason = "awaiting_registration", "node_not_registered"
	} else {
		writeError(w, 503, "Поиск ServerBridge недоступен")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"serverId": serverID, "wrapperPath": path, "projectId": run.ProjectID,
		"profileId": plan.Destination.ProfileID, "state": state, "reason": reason,
		"cutoverAllowed": false,
	}})
}

// Запрещаем второй JSON-документ после тела запроса. Регистрация должна содержать
// ровно один однозначный объект, без игнорируемых дополнительных данных.
func decodeMigrationEnrollment0446(r io.Reader, req *moduleEnrollmentRequest0338) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		return err
	}
	if req.WrapperPath == "" || req.ID == "" || req.ProfileID == "" || req.PublicKey == "" || req.Kind == "" {
		return errors.New("Отсутствует: «поля регистрации»")
	}
	var other any
	if err := dec.Decode(&other); err != io.EOF {
		return errors.New("Лишние данные после JSON регистрации")
	}
	return nil
}
