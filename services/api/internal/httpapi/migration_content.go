package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gp "gitflic.ru/skif4er/launcher/services/api/internal/gravitplan"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type migrationContentStore0337 interface {
	EnsureMigrationContent0337(context.Context, string, string, string, string, gc.Plan, ...string) (repository.BuildWorkspace, error)
	GetMigrationContent0337(context.Context, string, string) (gc.Plan, repository.BuildWorkspace, error)
}

func (s Server) registerMigrationContentRoutes0337(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/content", s.requirePermission("settings:manage", s.migrationContentStatus0337))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/content/preview", s.requirePermission("settings:manage", s.migrationContentPreview0337))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/content/import", s.requirePermission("settings:manage", s.migrationContentImport0337))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/content/apply-optionals", s.requirePermission("settings:manage", s.migrationContentApplyOptionals0337))
}
func migrationContentHeaders0337(r *http.Request) (profilePath, id, name, loader, channel, version string) {
	return strings.TrimSpace(r.Header.Get("X-Gravit-Profile-Path")), strings.TrimSpace(r.Header.Get("X-Profile-ID")), strings.TrimSpace(r.Header.Get("X-Profile-Name")), strings.TrimSpace(r.Header.Get("X-Loader")), strings.TrimSpace(r.Header.Get("X-Channel")), strings.TrimSpace(r.Header.Get("X-Version"))
}
func (s Server) migrationContentStore0337(w http.ResponseWriter) (migrationContentStore0337, bool) {
	store, ok := s.Repo.(migrationContentStore0337)
	if !ok {
		writeError(w, 503, "Для импорта содержимого необходим PostgreSQL")
		return nil, false
	}
	return store, true
}
func (s Server) migrationContentStatus0337(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationContentStore0337(w)
	if !ok {
		return
	}
	pp := r.URL.Query().Get("profilePath")
	if pp == "" {
		writeError(w, 400, "Необходимо указать параметр запроса profilePath")
		return
	}
	plan, ws, e := store.GetMigrationContent0337(r.Context(), r.PathValue("runId"), pp)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	validation, err := s.workspaceValidate0226(ws)
	valid := err == nil
	if err != nil {
		validation = err.Error()
	}
	writeJSON(w, 200, map[string]any{"data": migrationContentResponse0337(plan, ws, validation, valid)})
}
func migrationContentResponse0337(plan gc.Plan, ws repository.BuildWorkspace, validation string, valid bool) map[string]any {
	staged := 0
	expected := map[string]gc.File{}
	for _, f := range plan.Files {
		expected[f.TargetPath] = f
	}
	for _, f := range ws.Files {
		if v, ok := expected[f.Path]; ok && f.SHA256 == v.SHA256 && f.Size == v.Size && f.Ownership == v.Ownership {
			staged++
		}
	}
	return map[string]any{"plan": plan, "workspaceId": ws.ID, "workspaceRevision": ws.Revision, "state": ws.State, "stagedFiles": staged, "totalFiles": len(plan.Files), "complete": staged == len(plan.Files) && len(ws.Files) == len(plan.Files) && (ws.State == "staged" || ws.State == "built") && valid, "validation": validation, "buildWorkspaceUrl": "/api/v1/build-workspaces/" + ws.ID}
}
func (s Server) migrationContentPreview0337(w http.ResponseWriter, r *http.Request) {
	s.migrationContentApply0337(w, r, false)
}
func (s Server) migrationContentImport0337(w http.ResponseWriter, r *http.Request) {
	s.migrationContentApply0337(w, r, true)
}
func (s Server) migrationContentApply0337(w http.ResponseWriter, r *http.Request, commit bool) {
	store, ok := s.migrationContentStore0337(w)
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
	workspaceStore, ok := s.workspaceStore0226(w)
	if !ok {
		return
	}
	run, e := flow.GetMigration0331(r.Context(), r.PathValue("runId"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if run.SourceKind != "gravit" || run.Status != "prepared" || run.Step != "source_assessment" {
		migrationHTTPError0331(w, mw.ErrBusy)
		return
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if commit && !s.authorizeProjectAction(w, r, claims, "file:write", run.ProjectID, "project", run.ProjectID) {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/zip") {
		writeError(w, 415, "Ожидается источник с типом application/zip")
		return
	}
	profilePath, profileID, name, loader, channel, version := migrationContentHeaders0337(r)
	if len(profilePath) > 1024 || len(profileID) > 128 || len(name) > 120 || len(loader) > 24 || len(channel) > 128 || len(version) > 128 || profileID == "" || profilePath == "" || loader == "" || channel == "" || version == "" {
		writeError(w, 400, "Необходимо указать путь профиля, ID, загрузчик, канал и заголовки версии")
		return
	}
	if commit && r.Header.Get("X-Migration-Content-Confirm") != run.ID {
		writeError(w, 400, "Необходимо явно подтвердить идентификатор запуска")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "Превышена ёмкость для загрузки исходников")
		return
	}
	snapshot, e := invStore.GetMigrationInventory0333(r.Context(), run.ID)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if r.ContentLength > inv.MaxSourceBytes || (r.ContentLength >= 0 && r.ContentLength != snapshot.SourceBytes) {
		writeError(w, 413, "Размер исходника не соответствует инвентаризации")
		return
	}
	src, n, digest, e := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if e != nil {
		writeError(w, 413, "Не удалось сохранить проверенный исходный ZIP во временное хранилище")
		return
	}
	defer func() { _ = src.Close(); _ = os.Remove(src.Name()) }()
	if digest != snapshot.SourceSHA256 || n != snapshot.SourceBytes {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	plan, e := gc.Prepare(r.Context(), src, n, snapshot, profilePath, run.ProjectID, profileID, name, loader)
	if e != nil {
		writeError(w, 422, "Не удалось выполнить анализ содержимого: "+e.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !commit {
		writeJSON(w, 200, map[string]any{"data": plan})
		return
	}
	if err := s.migrationCheckContentPlan0442(r.Context(), run.ID, r.Header.Get("X-Migration-Plan-SHA256"), gp.Destination{ProfilePath: profilePath, ProfileID: profileID, ProfileName: name, Loader: loader, LoaderVersion: strings.TrimSpace(r.Header.Get("X-Loader-Version")), Channel: channel, Version: version}, plan); err != nil {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	if !plan.Ready {
		writeJSON(w, 422, map[string]any{"data": plan, "error": map[string]any{"message": "resolve content blockers before import", "code": "content-blocked"}})
		return
	}
	// Конвейер релиза использует отдельную детерминированную блокировку рабочего
	// пространства. Удержание её в течение всего запроса предотвращает параллельное
	// изменение списка подготовленных файлов.
	key := gc.WorkspaceID(run.ID, profilePath)
	unlock, e := s.lockPackageMutation(r.Context(), "build-workspace:"+key)
	if e != nil {
		writeError(w, 409, e.Error())
		return
	}
	defer unlock()
	ws, e := store.EnsureMigrationContent0337(r.Context(), run.ID, claims.Sub, channel, version, plan, r.Header.Get("X-Migration-Plan-SHA256"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if ws.State == "built" && ws.PackageID != "" {
		digest, err := s.workspaceValidate0226(ws)
		if err != nil {
			writeError(w, 409, "Не удалось проверить собранную рабочую область: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"data": migrationContentResponse0337(plan, ws, "verified built workspace: "+digest, true)})
		return
	}
	if ws.PackageID != "" {
		writeError(w, 409, "Сборка пакета выполняется; повторите после её завершения")
		return
	}
	reader, e := gc.NewReader(src, n)
	if e != nil {
		writeError(w, 422, "Некорректный исходный ZIP")
		return
	}
	existing := map[string]repository.BuildFile{}
	for _, f := range ws.Files {
		existing[f.Path] = f
	}
	for _, f := range plan.Files {
		if old, ok := existing[f.TargetPath]; ok {
			if old.SHA256 != f.SHA256 || old.Size != f.Size || old.Ownership != f.Ownership || !old.Selected {
				migrationHTTPError0331(w, mw.ErrConflict)
				return
			}
			// Повторно прочитайте и аутентифицируйте подготовленный зашифрованный объект, в
			// том числе при повторной попытке: индексированный файл с отсутствующим или
			// повреждённым объектом не считается импортированным.
			if e = s.workspaceVerifyFile0226(ws, old); e == nil {
				continue
			}
		}
		b, readErr := reader.ReadVerified(r.Context(), f)
		if readErr != nil {
			writeError(w, 422, "Проверка исходного содержимого завершилась ошибкой: "+readErr.Error())
			return
		}
		file := repository.BuildFile{Path: f.TargetPath, Size: f.Size, SHA256: f.SHA256, Ownership: f.Ownership, Selected: true}
		if e = normalizeBuildFile0226(file); e != nil {
			writeError(w, 422, "Неподдерживаемый целевой файл: "+e.Error())
			return
		}
		encrypted, encryptErr := s.encryptWorkspace0226(ws, file, b)
		if encryptErr != nil {
			writeError(w, 503, "Не удалось зашифровать рабочую область")
			return
		}
		if _, _, e = s.Storage.Save(ws.ProjectID, ws.ID, workspaceObjectPath0226(file), bytes.NewReader(encrypted)); e != nil {
			writeError(w, 503, "Объектное хранилище недоступно: "+e.Error())
			return
		}
		if _, ok := existing[file.Path]; !ok {
			ws.Files = append(ws.Files, file)
		}
		ws.State = "importing"
		ws.BuildDigest = ""
		ws, e = workspaceStore.SaveBuildWorkspace(r.Context(), ws)
		if e != nil {
			migrationHTTPError0331(w, e)
			return
		}
		existing[file.Path] = file
	}
	if len(ws.Files) != len(plan.Files) {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	// Запускайте существующий валидатор манифеста и подготовки; он проверяет хеши,
	// classpath, совместимость Runtime и закреплённый снимок профиля. При неуспешной
	// проверке запрещено подписывать или публиковать. Материализация и подпись
	// остаются частью обычной процедуры явно утверждённого выпуска Build Workspace.
	ws.State = "staged"
	ws.BuildDigest = ""
	ws, e = workspaceStore.SaveBuildWorkspace(r.Context(), ws)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	digest, validationErr := s.workspaceValidate0226(ws)
	validation := "valid build inputs: " + digest
	valid := validationErr == nil
	if validationErr != nil {
		validation = "build validation blocked: " + validationErr.Error()
	}
	s.audit(r, claims.Sub, "migration:gravit-content-stage", run.ProjectID+"/"+ws.ID)
	response := migrationContentResponse0337(plan, ws, validation, valid)
	if !valid {
		writeJSON(w, 422, map[string]any{"data": response, "error": map[string]any{"code": "content-validation-blocked", "message": validation}})
		return
	}
	writeJSON(w, 200, map[string]any{"data": response})
}

// Применяет поддерживаемый каталог необязательных модов к реальному черновику v3,
// сформированному штатным сборщиком рабочего пространства. После этого оператор
// должен запустить обычную проверку и надёжную подпись Ed25519; непроверенный
// архив не может создать подписанный релиз через данный маршрут.
func (s Server) migrationContentApplyOptionals0337(w http.ResponseWriter, r *http.Request) {
	store, ok := s.migrationContentStore0337(w)
	if !ok {
		return
	}
	if r.ContentLength > 0 {
		writeError(w, 400, "Тело запроса не допускается")
		return
	}
	runID := r.PathValue("runId")
	if r.Header.Get("X-Migration-Content-Confirm") != runID {
		writeError(w, 400, "Требуется явное подтверждение идентификатора миграции")
		return
	}
	pp := r.URL.Query().Get("profilePath")
	plan, ws, e := store.GetMigrationContent0337(r.Context(), runID, pp)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	if plan.Optional == nil || !plan.Optional.Ready {
		writeError(w, 409, "Для этого профиля отсутствуют поддерживаемые дополнительные компоненты")
		return
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if claims.Sub != ws.OwnerID || !s.authorizeProjectAction(w, r, claims, "release:prepare", ws.ProjectID, "project", ws.ProjectID) {
		return
	}
	if ws.State != "built" || ws.PackageID == "" {
		writeError(w, 409, "Сначала соберите и проверьте рабочую область, затем применяйте дополнительные компоненты")
		return
	}
	lookup, unlock, e := s.lockPackageLookupMutation(r.Context(), ws.PackageID)
	if e != nil {
		writeError(w, 409, "Черновик пакета недоступен или занят")
		return
	}
	defer unlock()
	if lookup.Release.Status != "draft" || lookup.Release.ProjectID != ws.ProjectID || lookup.Release.ProfileID != ws.ProfileID || lookup.Release.ID != ws.PackageID || lookup.Release.Manifest.SchemaVersion != model.ManifestSchemaV3 || lookup.Release.Manifest.ComponentCatalog == nil {
		writeError(w, 409, "Пакет должен быть неподписанным черновиком v3, принадлежащим перенесённому профилю")
		return
	}
	// Отклоняйте любые расхождения файлов пакета после подготовки. Необязательный
	// каталог должен быть привязан к тем же проверенным байтам, которые выбраны
	// при исходном импорте.
	expected := map[string]gc.File{}
	for _, f := range plan.Files {
		expected[f.TargetPath] = f
	}
	if len(lookup.Files) != len(expected) {
		writeError(w, 409, "Количество файлов пакета изменилось")
		return
	}
	for _, f := range lookup.Files {
		old, exists := expected[f.Path]
		if !exists || old.SHA256 != f.SHA256 || old.Size != f.Size || old.Ownership != f.Ownership {
			writeError(w, 409, "Файлы пакета отличаются от проверенного содержимого")
			return
		}
	}
	original := plan.Optional.Catalog
	existing := lookup.Release.Manifest.ComponentCatalog
	if reflect.DeepEqual(existing.Components, original.Components) && reflect.DeepEqual(existing.Categories, original.Categories) && reflect.DeepEqual(existing.Groups, original.Groups) && reflect.DeepEqual(existing.Presets, original.Presets) {
		writeJSON(w, 200, map[string]any{"data": existing, "alreadyApplied": true})
		return
	}
	if len(existing.Components) != 0 {
		writeError(w, 409, "Каталог компонентов черновика изменён вручную; перезапись отклонена")
		return
	}
	req := componentEditorRequest0248{ExpectedRevision: existing.Revision, Catalog: original}
	cat, report := previewCatalog0248(lookup.Release, req)
	if !report.Valid {
		writeJSON(w, 422, map[string]any{"data": report, "error": map[string]any{"message": "optional catalog validation blocked", "code": "optional-invalid"}})
		return
	}
	writer, ok := s.Repo.(interface {
		UpdateDraftComponentCatalog0248(string, string, uint64, model.ComponentCatalog0241) (model.ReleaseVersion, error)
	})
	if !ok {
		writeError(w, 503, "Сохранение каталога недоступно")
		return
	}
	result, e := writer.UpdateDraftComponentCatalog0248(ws.ProjectID, ws.PackageID, existing.Revision, cat)
	if e != nil {
		writeError(w, 409, "Не удалось сохранить каталог дополнительных компонентов: "+e.Error())
		return
	}
	s.audit(r, claims.Sub, "migration:gravit-optionals", ws.PackageID)
	writeJSON(w, 200, map[string]any{"data": result.Manifest.ComponentCatalog, "alreadyApplied": false})
}
