package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func extensionHostKey0205(r *http.Request) extensionhost.Key {
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "global"
	}
	return extensionhost.Key{ExtensionID: r.PathValue("extensionId"), Scope: scope, ScopeID: strings.TrimSpace(r.URL.Query().Get("scopeId"))}
}

func (s Server) extensionHosts0205(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil {
		writeError(w, http.StatusServiceUnavailable, "extension host is disabled")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocolVersion": extensionhost.ProtocolVersion, "resourceIsolation": s.ExtensionHost.ResourceIsolation(), "limits": s.ExtensionHost.Limits(), "items": s.ExtensionHost.List()}})
}
func (s Server) extensionHostDetail0205(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil {
		writeError(w, http.StatusServiceUnavailable, "extension host is disabled")
		return
	}
	item, err := s.ExtensionHost.Get(extensionHostKey0205(r))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "extension host runtime not found")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"host": item}})
}
func (s Server) extensionHostLogs0205(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil {
		writeError(w, http.StatusServiceUnavailable, "extension host is disabled")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.ExtensionHost.Logs(extensionHostKey0205(r), limit)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "extension host runtime not found")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items}})
}
func (s Server) extensionHostStart0205(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil {
		writeError(w, http.StatusServiceUnavailable, "extension host is disabled")
		return
	}
	key := extensionHostKey0205(r)
	install, err := s.Repo.GetExtensionInstallState(r.Context(), key.ExtensionID, key.Scope, key.ScopeID)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	if err := s.ExtensionHost.StartInstallation(r.Context(), install); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	item, _ := s.ExtensionHost.Get(key)
	s.audit(r, s.adminActor(r), "extension:host:start", key.ExtensionID+":"+key.Scope+":"+key.ScopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"host": item}})
}
func (s Server) extensionHostStop0205(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil {
		writeError(w, http.StatusServiceUnavailable, "extension host is disabled")
		return
	}
	key := extensionHostKey0205(r)
	if err := s.ExtensionHost.Stop(r.Context(), key); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	item, _ := s.ExtensionHost.Get(key)
	s.audit(r, s.adminActor(r), "extension:host:stop", key.ExtensionID+":"+key.Scope+":"+key.ScopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"host": item}})
}
func (s Server) extensionHostRestart0205(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil {
		writeError(w, http.StatusServiceUnavailable, "extension host is disabled")
		return
	}
	key := extensionHostKey0205(r)
	if err := s.ExtensionHost.Restart(r.Context(), key); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	item, _ := s.ExtensionHost.Get(key)
	s.audit(r, s.adminActor(r), "extension:host:restart", key.ExtensionID+":"+key.Scope+":"+key.ScopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"host": item}})
}
