package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"

	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	gp "gitflic.ru/skif4er/launcher/services/api/internal/gravitplan"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// Пакетный предпросмотр намеренно не перезаписывает существующий устойчивый план
// миграции одного профиля. Каждый подготовленный импорт всё равно должен пройти
// обычную последовательность планирования и CAS для одного профиля до подписи и
// публикации клиента.
func (s Server) migrationBatch0492(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Repo.(migrationPlanStore0442); !ok {
		writeError(w, 503, "Для миграции требуется PostgreSQL")
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
	compatibilityStore, ok := s.migrationCompatibilityStore0332(w)
	if !ok {
		return
	}
	run, err := runs.GetMigration0331(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if run.SourceKind != "gravit" || run.Step != "source_assessment" || run.Status != "prepared" {
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
	encoded := r.Header.Get("X-Gravit-Profiles")
	if len(encoded) < 2 || len(encoded) > 16384 {
		writeError(w, 400, "Требуется сопоставление X-Gravit-Profiles допустимого размера")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > 12288 {
		writeError(w, 400, "Некорректная кодировка сопоставления профилей")
		return
	}
	var destinations []gp.Destination
	if json.Unmarshal(raw, &destinations) != nil || len(destinations) == 0 || len(destinations) > gp.MaxProfiles0492 {
		writeError(w, 400, "Некорректное сопоставление профилей")
		return
	}
	// Отклоняйте также неизвестные поля: опечатка не должна незаметно изменить целевые
	// настройки.
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&destinations) != nil {
		writeError(w, 400, "Неизвестное поле сопоставления профилей")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		writeError(w, 400, "Лишние данные после сопоставления профилей")
		return
	}
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "Достигнут предел загрузки перечня файлов")
		return
	}
	saved, err := inventoryStore.GetMigrationInventory0333(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	previous, err := compatibilityStore.GetMigrationCompatibility0332(r.Context(), run.ID)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if r.ContentLength > inv.MaxSourceBytes || (r.ContentLength >= 0 && r.ContentLength != saved.SourceBytes) {
		writeError(w, 413, "Источник отличается от зафиксированной инвентаризации")
		return
	}
	f, n, sha, err := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, inv.MaxSourceBytes))
	if err != nil {
		writeError(w, 413, "Не удалось подготовить исходные данные")
		return
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if sha != saved.SourceSHA256 || n != saved.SourceBytes || previous.SourceSHA256 != sha {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	actual, err := inv.Inspect(r.Context(), f, n, sha)
	if err != nil {
		writeError(w, 422, "Некорректный исходный ZIP: "+err.Error())
		return
	}
	if actual.ManifestSHA256 != saved.ManifestSHA256 {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	compatibility, err := gd.AssessReader(r.Context(), f, n, sha, previous.ClaimedVersion)
	if err != nil {
		writeError(w, 422, "Проверка совместимости завершилась ошибкой: "+err.Error())
		return
	}
	if compatibility.FilesSHA256 != previous.FilesSHA256 || compatibility.VersionStatus != previous.VersionStatus || compatibility.DetectedVersion != previous.DetectedVersion {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	modules, err := gm.Analyze(r.Context(), f, n, saved)
	if err != nil {
		writeError(w, 422, "Не удалось проверить модуль: "+err.Error())
		return
	}
	identities := gp.IdentityPreview{State: "blocked", Reason: "Не найден поддерживаемый снимок учётных записей"}
	accounts, err := gi.Extract(r.Context(), f, n, saved)
	if err != nil {
		identities.Reason = err.Error()
	} else {
		_, summary := gi.Reconcile(accounts, nil)
		identities.SourceAccounts = len(accounts)
		identities.DuplicateOrConflicting = summary["blocked"]
		if identities.DuplicateOrConflicting != 0 {
			identities.Reason = "Повторяющиеся учётные записи источника"
		} else {
			identities.State = "review_required"
			identities.Reason = "UUID and password verifiers need target reconciliation"
		}
	}
	target, existing, err := s.migrationTargetSnapshot0442(run.ProjectID)
	if err != nil {
		writeError(w, 503, "Целевой снимок недоступен")
		return
	}
	report, err := gp.BuildBatch0492(r.Context(), f, n, run.ID, run.ProjectID, target, existing, saved, compatibility, modules, identities, destinations)
	if err != nil {
		writeError(w, 422, "Пробная миграция нескольких профилей отклонена: "+err.Error())
		return
	}
	latest, _, err := s.migrationTargetSnapshot0442(run.ProjectID)
	if err != nil || latest != target {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	newest, err := runs.GetMigration0331(r.Context(), run.ID)
	if err != nil || newest.Revision != run.Revision || newest.Fence != run.Fence || newest.Status != run.Status || newest.Step != run.Step || !reflect.DeepEqual(newest.Result, run.Result) {
		migrationHTTPError0331(w, mw.ErrConflict)
		return
	}
	s.audit(r, s.adminActor(r), "migration:dry-run-all", run.ID+":"+report.BatchSHA256)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
