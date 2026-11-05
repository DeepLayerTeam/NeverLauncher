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
		writeError(w, 503, "Для проверки совместимости Gravit требуется PostgreSQL")
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
	// Двоичный запрос application/zip, а не путь на хосте Backend; исключает
	// произвольное чтение и распаковку файлов. Загруженные байты не сохраняются.
	if t := r.Header.Get("Content-Type"); !strings.EqualFold(strings.TrimSpace(strings.Split(t, ";")[0]), "application/zip") {
		writeError(w, 415, "Загрузите ZIP-архив с типом application/zip")
		return
	}
	// Те же ограниченные двумя слотами подготовка и проверка ZIP, что и для
	// инвентаризации. Не загружайте весь модпак объёмом 512 МиБ в память процесса
	// API.
	select {
	case gravitinventorySlots0333 <- struct{}{}:
		defer func() { <-gravitinventorySlots0333 }()
	default:
		writeError(w, 429, "Сервис проверки источника занят; повторите после завершения другой загрузки")
		return
	}
	if r.ContentLength > gd.MaxArchiveBytes {
		writeError(w, 413, "Размер исходного ZIP Gravit превышает 512 МиБ")
		return
	}
	src, size, digest, err := inv.Spool(r.Context(), http.MaxBytesReader(w, r.Body, gd.MaxArchiveBytes))
	if err != nil {
		writeError(w, 413, "Не удалось подготовить ZIP Gravit с ограничением размера: "+err.Error())
		return
	}
	defer func() { src.Close(); _ = os.Remove(src.Name()) }()
	report, err := gd.AssessReader(r.Context(), src, size, digest, r.Header.Get("X-Gravit-Version"))
	if err != nil {
		writeError(w, 422, "Некорректный исходный архив Gravit: "+err.Error())
		return
	}
	saved, err := store.SaveMigrationCompatibility0332(r.Context(), id, report)
	if err != nil {
		if errors.Is(err, mw.ErrBusy) || errors.Is(err, mw.ErrConflict) || errors.Is(err, mw.ErrNotFound) {
			migrationHTTPError0331(w, err)
		} else {
			writeError(w, 503, "Не удалось сохранить отчёт о совместимости")
		}
		return
	}
	s.audit(r, s.adminActor(r), "migration:gravit-compatibility", run.ProjectID)
	writeJSON(w, 200, map[string]any{"data": saved})
}
