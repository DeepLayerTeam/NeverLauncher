package httpapi

import (
	"errors"
	"net/http"
	"runtime"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionresolver"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionupdates"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type extensionUpdateRequest02011 struct {
	Scope   string                      `json:"scope,omitempty"`
	ScopeID string                      `json:"scopeId,omitempty"`
	Channel string                      `json:"channel,omitempty"`
	Roots   []model.ExtensionUpdateRoot `json:"roots,omitempty"`
}
type extensionPinWrite02011 struct {
	Scope   string `json:"scope,omitempty"`
	ScopeID string `json:"scopeId,omitempty"`
	Version string `json:"version"`
}

func (s Server) resolver02011(channel string) *extensionresolver.Resolver {
	if strings.TrimSpace(channel) == "" {
		channel = "stable"
	}
	return extensionresolver.New(s.Repo, extensionresolver.Environment{LauncherVersion: s.Version, APIVersion: "3.7", OS: runtime.GOOS, Architecture: runtime.GOARCH, DefaultChannel: channel})
}
func (s Server) resolveUpdatePlan02011(r *http.Request, req extensionUpdateRequest02011) (model.ExtensionUpdatePlan, error) {
	return s.resolver02011(req.Channel).Resolve(r.Context(), extensionresolver.Scope{Scope: req.Scope, ScopeID: req.ScopeID}, req.Roots)
}
func (s Server) updateManager02011() *extensionupdates.Manager {
	return &extensionupdates.Manager{Repo: s.Repo, Lifecycle: extensionlifecycle.New(s.Config.ExtensionRoot, s.Config.ExtensionBackupRetention, s.Repo, s.Storage), Host: s.ExtensionHost, Security: s.ExtensionSecurity, Config: extensionupdates.Config{HealthTimeout: 20 * time.Second, LeaseTTL: 30 * time.Minute}}
}
func (s Server) extensionUpdatePlan02011(w http.ResponseWriter, r *http.Request) {
	var req extensionUpdateRequest02011
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, "invalid update request: "+err.Error())
		return
	}
	plan, err := s.resolveUpdatePlan02011(r, req)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"plan": plan}})
}
func (s Server) extensionUpdateApply02011(w http.ResponseWriter, r *http.Request) {
	var req extensionUpdateRequest02011
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, "invalid update request: "+err.Error())
		return
	}
	plan, err := s.resolveUpdatePlan02011(r, req)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	tx, err := s.updateManager02011().Apply(r.Context(), plan)
	if err != nil {
		s.audit(r, s.adminActor(r), "extension:update-transaction:failed", tx.ID+":"+tx.Status)
		writeJSON(w, http.StatusConflict, map[string]any{"apiVersion": apiContractVersion, "error": err.Error(), "data": map[string]any{"transaction": tx}})
		return
	}
	s.audit(r, s.adminActor(r), "extension:update-transaction:succeeded", tx.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"transaction": tx}})
}
func (s Server) extensionUpdateTransaction02011(w http.ResponseWriter, r *http.Request) {
	tx, err := s.Repo.GetExtensionUpdateTransaction(r.Context(), r.PathValue("transactionId"))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "update transaction not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"transaction": tx}})
}
func (s Server) extensionUpdatePins02011(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	scopeID := r.URL.Query().Get("scopeId")
	items, err := s.Repo.ListExtensionUpdatePins(r.Context(), scope, scopeID)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items}})
}
func (s Server) extensionUpdatePinPut02011(w http.ResponseWriter, r *http.Request) {
	var req extensionPinWrite02011
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	p, err := s.Repo.SetExtensionUpdatePin(r.Context(), model.ExtensionUpdatePin{ExtensionID: r.PathValue("extensionId"), Scope: req.Scope, ScopeID: req.ScopeID, Version: req.Version})
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "extension:update-pin:set", p.ExtensionID+"@"+p.Version+":"+p.Scope+":"+p.ScopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"pin": p}})
}
func (s Server) extensionUpdatePinDelete02011(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	scopeID := r.URL.Query().Get("scopeId")
	err := s.Repo.DeleteExtensionUpdatePin(r.Context(), r.PathValue("extensionId"), scope, scopeID)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "pin not found")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:update-pin:delete", r.PathValue("extensionId")+":"+scope+":"+scopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "unpinned"}})
}
