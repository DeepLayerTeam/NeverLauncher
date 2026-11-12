package httpapi

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"net/http"
	"time"

	co "gitflic.ru/skif4er/launcher/services/api/internal/gravitcutover"
)

type migrationCutoverStore03311 interface {
	MigrationCutovers03311(context.Context, string) ([]co.Route, error)
	StageMigrationCutover03311(context.Context, string, co.Stage, ed25519.PublicKey) (co.Route, error)
	ActivateMigrationCutover03311(context.Context, string, co.Activate, ed25519.PublicKey) (co.Route, error)
	CancelMigrationCutover03311(context.Context, string, string, string, int64) (co.Route, error)
}

func (s Server) registerMigrationCutoverRoutes03311(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/cutovers", s.requirePermission("settings:manage", s.migrationCutoverList03311))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/cutovers/stage", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationCutoverStage03311))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/cutovers/activate", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationCutoverActivate03311))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/cutovers/cancel", s.requireFreshSession117("mfa", 5*time.Minute, s.migrationCutoverCancel03311))
}
func (s Server) cutoverAccess03311(w http.ResponseWriter, r *http.Request) (migrationCutoverStore03311, string, bool) {
	store, ok := s.Repo.(migrationCutoverStore03311)
	if !ok {
		writeError(w, 503, "Для подготовленного переключения требуется PostgreSQL")
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
func (s Server) cutoverKey03311(w http.ResponseWriter) (ed25519.PublicKey, bool) {
	private, e := s.manifestSigningPrivateKey()
	if e != nil {
		writeError(w, 503, "Ключ подписи релиза Launcher не настроен")
		return nil, false
	}
	return private.Public().(ed25519.PublicKey), true
}
func (s Server) migrationCutoverList03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	items, e := store.MigrationCutovers03311(r.Context(), id)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": items})
}
func (s Server) migrationCutoverStage03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-Cutover-Confirm") != id {
		writeError(w, 400, "Требуется подтверждение точного запуска миграции")
		return
	}
	input, ok := migrationRead0331[co.Stage](w, r)
	if !ok {
		return
	}
	key, ok := s.cutoverKey03311(w)
	if !ok {
		return
	}
	v, e := store.StageMigrationCutover03311(r.Context(), id, input, key)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:cutover-staged", v.ProjectID+":"+v.ProfileID+":"+v.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
func (s Server) migrationCutoverActivate03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	// Ограждение источника выполняется вне основного канала и должно быть завершено и
	// проверено оператором. Подтверждение сохраняется, но не является
	// криптографическим доказательством.
	if r.Header.Get("X-Migration-Cutover-Confirm") != id || r.Header.Get("X-Migration-Source-Fenced") != "true" {
		writeError(w, 400, "Необходимо подтвердить запуск миграции и независимую блокировку записи источника")
		return
	}
	input, ok := migrationRead0331[co.Activate](w, r)
	if !ok {
		return
	}
	key, ok := s.cutoverKey03311(w)
	if !ok {
		return
	}
	ctx := r.Context()
	if repository.IsStableChannel0341(input.Channel) {
		routes, routeErr := store.MigrationCutovers03311(ctx, id)
		if routeErr != nil {
			writeError(w, 409, "Не удалось прочитать цель миграции: "+routeErr.Error())
			return
		}
		var targetID string
		for _, route := range routes {
			if route.ProfileID == input.ProfileID && repository.IsStableChannel0341(route.Channel) {
				targetID = route.ReleaseID
				break
			}
		}
		if targetID == "" {
			writeError(w, 409, "Для стабильного переключения не подготовлен целевой релиз")
			return
		}
		lookup, loadErr := s.lookupPackage(targetID)
		if loadErr != nil {
			writeError(w, 409, "Целевая версия для стабильного переключения недоступна")
			return
		}
		token, coverage, gateErr := s.issueStablePermit03411(ctx, lookup)
		if gateErr != nil {
			writeError(w, 409, "Стабильное переключение заблокировано: "+fmt.Sprint(coverage.TargetBlockers)+": "+gateErr.Error())
			return
		}
		ctx = repository.WithStablePermit03411(ctx, token)
	}
	v, e := store.ActivateMigrationCutover03311(ctx, id, input, key)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:cutover-activated", v.ProjectID+":"+v.ProfileID+":"+v.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
func (s Server) migrationCutoverCancel03311(w http.ResponseWriter, r *http.Request) {
	store, id, ok := s.cutoverAccess03311(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Migration-Cutover-Confirm") != id {
		writeError(w, 400, "Требуется подтверждение точного запуска миграции")
		return
	}
	input, ok := migrationRead0331[struct {
		ProfileID        string `json:"profileId"`
		Channel          string `json:"channel"`
		ExpectedRevision int64  `json:"expectedRevision"`
	}](w, r)
	if !ok {
		return
	}
	v, e := store.CancelMigrationCutover03311(r.Context(), id, input.ProfileID, input.Channel, input.ExpectedRevision)
	if e != nil {
		migrationHTTPError0331(w, e)
		return
	}
	s.audit(r, s.adminActor(r), "migration:cutover-cancelled", v.ProjectID+":"+v.ProfileID+":"+v.Channel)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": v})
}
