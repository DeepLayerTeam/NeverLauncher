package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionresolver"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type extensionLifecycleWrite0204 struct {
	Version string `json:"version,omitempty"`
	Channel string `json:"channel,omitempty"`
	Scope   string `json:"scope,omitempty"`
	ScopeID string `json:"scopeId,omitempty"`
}

func (s Server) lifecycleManager0204() *extensionlifecycle.Manager {
	return extensionlifecycle.New(s.Config.ExtensionRoot, s.Config.ExtensionBackupRetention, s.Repo, s.Storage)
}

func lifecycleScopeFromRequest0204(scope, scopeID string) extensionlifecycle.Scope {
	if strings.TrimSpace(scope) == "" {
		scope = "global"
	}
	return extensionlifecycle.Scope{Scope: scope, ScopeID: scopeID}
}

func decodeLifecycleWrite0204(r *http.Request) (extensionLifecycleWrite0204, error) {
	var req extensionLifecycleWrite0204
	if r.ContentLength == 0 {
		return req, nil
	}
	if err := decodeSingleJSON0203(r, &req); err != nil {
		return extensionLifecycleWrite0204{}, err
	}
	return req, nil
}

func (s Server) extensionInstallList0204(w http.ResponseWriter, r *http.Request) {
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	scopeID := strings.TrimSpace(r.URL.Query().Get("scopeId"))
	items, err := s.Repo.ListExtensionInstallStates(r.Context(), scope, scopeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "1.0", "count": len(items), "items": items}})
}

func (s Server) extensionInstallDetail0204(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	scopeID := r.URL.Query().Get("scopeId")
	item, err := s.Repo.GetExtensionInstallState(r.Context(), r.PathValue("extensionId"), scope, scopeID)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "extension installation not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("historyLimit"))
	revisions, err := s.Repo.ListExtensionInstallRevisions(r.Context(), item.ExtensionID, item.Scope, item.ScopeID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	lockStatus := "ok"
	if err := s.lifecycleManager0204().VerifyLockfile(r.Context(), item.ExtensionID, lifecycleScopeFromRequest0204(item.Scope, item.ScopeID)); err != nil {
		lockStatus = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"install": item, "revisions": revisions, "lockfile": lockStatus}})
}

func (s Server) resolveLifecycleRegistryVersion0204(r *http.Request, id, versionValue, channel string) (model.ExtensionRegistryVersion, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	versionValue = strings.TrimSpace(versionValue)
	channel = strings.ToLower(strings.TrimSpace(channel))
	if versionValue != "" {
		item, err := s.Repo.GetExtensionRegistryVersion(r.Context(), id, versionValue)
		if err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
		if item.YankedAt != nil {
			return model.ExtensionRegistryVersion{}, repository.ErrConflict
		}
		return item, nil
	}
	if channel == "" {
		channel = "stable"
	}
	items, err := s.Repo.SearchExtensionRegistry(r.Context(), model.ExtensionRegistrySearch{Query: id, Channel: channel, LauncherVersion: s.Version, OS: runtime.GOOS, Architecture: runtime.GOARCH})
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	for _, item := range items {
		if item.ExtensionID == id && item.YankedAt == nil {
			return item, nil
		}
	}
	return model.ExtensionRegistryVersion{}, repository.ErrNotFound
}

func writeLifecycleError0204(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, repository.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already") || strings.Contains(msg, "locked") || strings.Contains(msg, "not activated") || strings.Contains(msg, "not installed") || strings.Contains(msg, "no restorable") || strings.Contains(msg, "yanked") {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
	}
}

func hostKeyForInstall0205(item model.ExtensionInstall) extensionhost.Key {
	return extensionhost.Key{ExtensionID: item.ExtensionID, Scope: item.Scope, ScopeID: item.ScopeID}
}

func (s Server) stopExtensionHostForLifecycle0205(r *http.Request, id string, scope extensionlifecycle.Scope) (model.ExtensionInstall, bool, error) {
	before, err := s.Repo.GetExtensionInstallState(r.Context(), id, scope.Scope, scope.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, false, err
	}
	wasRunningDesired := before.CurrentState == model.ExtensionInstallStateEnabled && before.Enabled
	if wasRunningDesired && s.ExtensionHost != nil {
		if err := s.ExtensionHost.Stop(r.Context(), hostKeyForInstall0205(before)); err != nil {
			return before, true, err
		}
	}
	return before, wasRunningDesired, nil
}

func (s Server) restoreExtensionHostAfterLifecycleFailure0205(before model.ExtensionInstall, shouldRun bool) {
	if !shouldRun || s.ExtensionHost == nil {
		return
	}
	if err := s.ExtensionHost.StartInstallation(context.Background(), before); err != nil && !errors.Is(err, extensionhost.ErrNoBackendTarget) {
		log.Printf("extension host compensation restart failed %s/%s/%s: %v", before.Scope, before.ScopeID, before.ExtensionID, err)
	}
}

func (s Server) startEnabledExtensionHost0205(ctx context.Context, install model.ExtensionInstall) error {
	if s.ExtensionHost == nil || install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled {
		return nil
	}
	err := s.ExtensionHost.StartInstallation(ctx, install)
	if errors.Is(err, extensionhost.ErrNoBackendTarget) {
		return nil
	}
	return err
}

func (s Server) extensionInstall0204(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLifecycleWrite0204(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid install payload: "+err.Error())
		return
	}
	item, err := s.resolveLifecycleRegistryVersion0204(r, r.PathValue("extensionId"), req.Version, req.Channel)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	scope := lifecycleScopeFromRequest0204(req.Scope, req.ScopeID)
	var permissionDiff any
	if s.ExtensionSecurity != nil {
		if d, diffErr := s.ExtensionSecurity.PermissionDiff(r.Context(), item.ExtensionID, "", item.Version, scope.Scope, scope.ScopeID); diffErr == nil {
			permissionDiff = d
		}
	}
	install, err := s.lifecycleManager0204().Install(r.Context(), item, scope)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:install", install.ExtensionID+"@"+install.CurrentVersion+":"+install.Scope+":"+install.ScopeID)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "installed", "verified": true, "install": install, "permissionDiff": permissionDiff}})
}
func (s Server) extensionEnable0204(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions Safe Mode is active (--no-extensions)")
		return
	}
	req, err := decodeLifecycleWrite0204(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := lifecycleScopeFromRequest0204(req.Scope, req.ScopeID)
	install, err := s.lifecycleManager0204().Enable(r.Context(), r.PathValue("extensionId"), scope)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	if err := s.startEnabledExtensionHost0205(r.Context(), install); err != nil {
		compensated, compErr := s.lifecycleManager0204().Disable(context.Background(), install.ExtensionID, lifecycleScopeFromRequest0204(install.Scope, install.ScopeID))
		if compErr != nil {
			writeError(w, http.StatusInternalServerError, "extension host start failed and disable compensation failed: "+err.Error()+"; "+compErr.Error())
			return
		}
		writeError(w, http.StatusConflict, "extension host start failed; enable was compensated to disabled: "+err.Error()+" generation="+strconv.FormatInt(compensated.Generation, 10))
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:enable", install.ExtensionID+":"+install.Scope+":"+install.ScopeID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "enabled", "install": install}})
}
func (s Server) extensionDisable0204(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLifecycleWrite0204(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := lifecycleScopeFromRequest0204(req.Scope, req.ScopeID)
	before, wasRunning, err := s.stopExtensionHostForLifecycle0205(r, r.PathValue("extensionId"), scope)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	install, err := s.lifecycleManager0204().Disable(r.Context(), r.PathValue("extensionId"), scope)
	if err != nil {
		s.restoreExtensionHostAfterLifecycleFailure0205(before, wasRunning)
		writeLifecycleError0204(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:disable", install.ExtensionID+":"+install.Scope+":"+install.ScopeID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "disabled", "install": install}})
}
func (s Server) extensionUninstall0204(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLifecycleWrite0204(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := lifecycleScopeFromRequest0204(req.Scope, req.ScopeID)
	before, wasRunning, err := s.stopExtensionHostForLifecycle0205(r, r.PathValue("extensionId"), scope)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	install, err := s.lifecycleManager0204().Uninstall(r.Context(), r.PathValue("extensionId"), scope)
	if err != nil {
		s.restoreExtensionHostAfterLifecycleFailure0205(before, wasRunning)
		writeLifecycleError0204(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:uninstall", install.ExtensionID+":"+install.Scope+":"+install.ScopeID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "uninstalled", "install": install}})
}
func (s Server) extensionUpdate0204(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLifecycleWrite0204(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	channel := strings.TrimSpace(req.Channel)
	if channel == "" && strings.TrimSpace(req.Version) == "" {
		channel = "stable"
	}
	root := model.ExtensionUpdateRoot{ExtensionID: r.PathValue("extensionId"), Version: strings.TrimSpace(req.Version), Channel: channel}
	plan, err := s.resolver02011(channel).Resolve(r.Context(), extensionresolver.Scope{Scope: req.Scope, ScopeID: req.ScopeID}, []model.ExtensionUpdateRoot{root})
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	tx, err := s.updateManager02011().Apply(r.Context(), plan)
	if err != nil {
		s.audit(r, s.adminActor(r), "extension:lifecycle:update-failed", tx.ID+":"+tx.Status)
		writeJSON(w, http.StatusConflict, map[string]any{"apiVersion": apiContractVersion, "error": err.Error(), "data": map[string]any{"transaction": tx, "plan": plan}})
		return
	}
	install, getErr := s.Repo.GetExtensionInstallState(r.Context(), root.ExtensionID, plan.Scope, plan.ScopeID)
	if getErr != nil {
		writeError(w, http.StatusInternalServerError, "update committed but final install state could not be loaded: "+getErr.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:update", install.ExtensionID+"@"+install.CurrentVersion+":"+install.Scope+":"+install.ScopeID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "updated", "verified": true, "install": install, "transaction": tx, "plan": plan}})
}

func (s Server) extensionRollback0204(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLifecycleWrite0204(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := lifecycleScopeFromRequest0204(req.Scope, req.ScopeID)
	before, wasRunning, err := s.stopExtensionHostForLifecycle0205(r, r.PathValue("extensionId"), scope)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	install, err := s.lifecycleManager0204().Rollback(r.Context(), r.PathValue("extensionId"), scope)
	if err != nil {
		s.restoreExtensionHostAfterLifecycleFailure0205(before, wasRunning)
		writeLifecycleError0204(w, err)
		return
	}
	if err := s.startEnabledExtensionHost0205(r.Context(), install); err != nil {
		if install.CurrentState == model.ExtensionInstallStateEnabled {
			_, _ = s.lifecycleManager0204().Disable(context.Background(), install.ExtensionID, lifecycleScopeFromRequest0204(install.Scope, install.ScopeID))
		}
		writeError(w, http.StatusConflict, "rollback payload restored but backend host failed to start; installation was disabled: "+err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:rollback", install.ExtensionID+"@"+install.CurrentVersion+":"+install.Scope+":"+install.ScopeID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "rolled-back", "install": install}})
}
