package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
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
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocolVersion": extensionhost.ProtocolVersion, "executionTrust": "legacy-unisolated", "isolationStatus": "unsupported", "isolationReasonCodes": []string{"extension-os-sandbox-not-enforced"}, "isolationDiagnostics": s.ExtensionHost.IsolationDiagnostics0311(), "resourceIsolation": s.ExtensionHost.ResourceIsolation(), "osSandbox": "none", "networkSandbox": "none", "filesystemSandbox": "none", "limits": s.ExtensionHost.Limits(), "items": s.ExtensionHost.List()}})
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
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "Extensions Safe Mode is active (--no-extensions)")
		return
	}
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
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "Extensions Safe Mode is active (--no-extensions)")
		return
	}
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

// extensionHostProbe0491 executes an actual authenticated health RPC inside the
// installed Java Host, not merely an in-memory supervisor heartbeat check.
// The extension:manage permission is enforced by the route; Java trust and
// revocation are rechecked by CallJavaRPC0304 before returning a result.
func (s Server) extensionHostProbe0491(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionHost == nil || s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "extension host unavailable")
		return
	}
	key := extensionHostKey0205(r)
	before, err := s.ExtensionHost.Get(key)
	if err != nil {
		writeError(w, http.StatusConflict, "extension host not running")
		return
	}
	if before.Runtime != "java-jvm" || before.State != "running" || !before.Healthy || before.InstanceID == "" {
		writeError(w, http.StatusConflict, "Java extension host not healthy")
		return
	}
	payload, err := s.ExtensionHost.CallJavaRPC0304(r.Context(), key, "health", json.RawMessage(`{}`))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Java extension host RPC failed")
		return
	}
	var result struct {
		State      string `json:"state"`
		Responsive bool   `json:"responsive"`
	}
	if err := json.Unmarshal(payload, &result); err != nil || result.State != "RUNNING" || !result.Responsive {
		writeError(w, http.StatusServiceUnavailable, "Java extension host did not acknowledge RUNNING")
		return
	}
	after, err := s.ExtensionHost.Get(key)
	if err != nil || after.Runtime != "java-jvm" || after.State != "running" || !after.Healthy ||
		before.Generation != after.Generation || before.InstanceID != after.InstanceID ||
		before.Version != after.Version || after.InstanceID == "" {
		writeError(w, http.StatusConflict, "Java host changed during live probe")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"host": after, "java": result,
	}})
}
