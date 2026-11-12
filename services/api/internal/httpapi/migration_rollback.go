package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	co "gitflic.ru/skif4er/launcher/services/api/internal/gravitcutover"
	rb "gitflic.ru/skif4er/launcher/services/api/internal/gravitrollback"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"io"
	"net/http"
	"time"
)

type rollbackStore03312 interface {
	PlanMigrationRollback03312(context.Context, string, rb.PlanInput) (rb.Result, error)
	CommitMigrationRollback03312(context.Context, string, rb.CommitInput, ed25519.PublicKey) (rb.Result, error)
	MigrationRollback03312(context.Context, string, string, string) (rb.Result, error)
}

// MIG12 передаёт до двух полных снимков по 20 тысяч игроков; декодер управляющих
// сообщений MIG01 с лимитом 16 КиБ заведомо слишком мал. Сохраняйте явное
// ограничение.
func migrationReadRollback03312[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 18<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		writeError(w, 400, "Некорректные или слишком большие доказательства отката")
		return v, false
	}
	var trailing any
	if e := d.Decode(&trailing); !errors.Is(e, io.EOF) {
		writeError(w, 400, "Доказательства отката содержат лишние данные или превышают допустимый размер")
		return v, false
	}
	return v, true
}

func (s Server) registerMigrationRollbackRoutes03312(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/rollbacks/{profile}/{channel}", s.requirePermission("settings:manage", s.migrationRollbackGet03312))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/rollbacks/plan", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationRollbackPlan03312))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/rollbacks/commit", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationRollbackCommit03312))
}
func (s Server) rollbackAccess03312(w http.ResponseWriter, r *http.Request) (rollbackStore03312, string, bool) {
	store, ok := s.Repo.(rollbackStore03312)
	if !ok {
		writeError(w, 503, "Для отката требуется PostgreSQL")
		return nil, "", false
	}
	run, e := s.migrationStoreRead03310(w, r)
	if e != nil {
		return nil, "", false
	}
	claims, e := s.adminClaims(r)
	if e != nil {
		writeError(w, 401, "Требуется авторизация")
		return nil, "", false
	}
	if !s.authorizeProjectAction(w, r, claims, "settings:manage", run.ProjectID, "project", run.ProjectID) {
		return nil, "", false
	}
	return store, run.ID, true
}
func (s Server) migrationRollbackGet03312(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.rollbackAccess03312(w, r)
	if !ok {
		return
	}
	result, e := store.MigrationRollback03312(r.Context(), id, r.PathValue("profile"), r.PathValue("channel"))
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": result})
}
func (s Server) migrationRollbackPlan03312(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.rollbackAccess03312(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-Rollback-Confirm") != id || r.Header.Get("X-Writer-Fenced") != "true" {
		writeError(w, 400, "Требуется точный идентификатор запуска и подтверждение независимой блокировки записи Launcher")
		return
	}
	input, ok := migrationReadRollback03312[rb.PlanInput](w, r)
	if !ok {
		return
	}
	result, e := store.PlanMigrationRollback03312(r.Context(), id, input)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:rollback-planned", id+":"+result.ProfileID+":"+result.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": result})
}
func (s Server) migrationRollbackCommit03312(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.rollbackAccess03312(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-Rollback-Confirm") != id || r.Header.Get("X-Writer-Fenced") != "true" || r.Header.Get("X-Migration-Source-Fenced") != "true" {
		writeError(w, 400, "Требуется точный идентификатор запуска и внешняя блокировка записи ОБОИХ источников")
		return
	}
	input, ok := migrationReadRollback03312[rb.CommitInput](w, r)
	if !ok {
		return
	}
	key, ok := s.cutoverKey03311(w)
	if !ok {
		return
	}
	ctx := r.Context()
	if repository.IsStableChannel0341(input.Channel) {
		read, ok := s.Repo.(interface {
			MigrationCutover03311(context.Context, string, string, string) (co.Route, error)
		})
		if !ok {
			writeError(w, 503, "Хранилище маршрута отката стабильной версии недоступно")
			return
		}
		route, routeErr := read.MigrationCutover03311(ctx, id, input.ProfileID, input.Channel)
		if routeErr != nil || route.BaselineReleaseID == "" {
			writeError(w, 409, "Для отката стабильной версии требуется сертифицированный предыдущий релиз (удалять текущий стабильный релиз запрещено)")
			return
		}
		lookup, loadErr := s.lookupPackage(route.BaselineReleaseID)
		if loadErr != nil {
			writeError(w, 409, "Целевая версия для стабильного отката недоступна")
			return
		}
		token, coverage, gateErr := s.issueStablePermit03411(ctx, lookup)
		if gateErr != nil {
			writeError(w, 409, "Стабильный откат заблокирован: "+fmt.Sprint(coverage.TargetBlockers)+": "+gateErr.Error())
			return
		}
		ctx = repository.WithStablePermit03411(ctx, token)
	}
	result, e := store.CommitMigrationRollback03312(ctx, id, input, key)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:rollback-committed", id+":"+result.ProfileID+":"+result.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": result})
}
