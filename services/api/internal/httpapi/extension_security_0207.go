package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type extensionPermissionGrantRequest0207 struct {
	Version    string `json:"version,omitempty"`
	Scope      string `json:"scope,omitempty"`
	ScopeID    string `json:"scopeId,omitempty"`
	Permission string `json:"permission"`
	Reason     string `json:"reason,omitempty"`
}
type extensionSecretWrite0207 struct {
	Scope       string `json:"scope,omitempty"`
	ScopeID     string `json:"scopeId,omitempty"`
	ValueBase64 string `json:"valueBase64"`
}

func securityScope0207(r *http.Request) (string, string) {
	scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	if scope == "" {
		scope = "global"
	}
	scopeID := strings.TrimSpace(r.URL.Query().Get("scopeId"))
	if scope == "global" {
		scopeID = ""
	}
	return scope, scopeID
}
func (s Server) extensionSecurityReady0207(w http.ResponseWriter) bool {
	if s.ExtensionSecurity == nil {
		writeError(w, http.StatusServiceUnavailable, "extension capability security unavailable")
		return false
	}
	return true
}
func (s Server) extensionPermissionVersion0207(r *http.Request, extensionID, requested, scope, scopeID string) (string, error) {
	if v := strings.TrimSpace(requested); v != "" {
		_, err := s.Repo.GetExtensionVersion(r.Context(), extensionID, v)
		return v, err
	}
	if strings.TrimSpace(scope) == "" {
		scope, scopeID = securityScope0207(r)
	}
	install, err := s.Repo.GetExtensionInstallState(r.Context(), extensionID, scope, scopeID)
	if err != nil {
		return "", err
	}
	if install.CurrentVersion != "" {
		return install.CurrentVersion, nil
	}
	return install.DesiredVersion, nil
}
func (s Server) extensionCapabilityCatalog0207(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"denyByDefault": true, "catalog": extensionsecurity.Catalog()}})
}
func (s Server) extensionPermissionState0207(w http.ResponseWriter, r *http.Request) {
	if !s.extensionSecurityReady0207(w) {
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	scope, scopeID := securityScope0207(r)
	toVersion := strings.TrimSpace(r.URL.Query().Get("version"))
	fromVersion := strings.TrimSpace(r.URL.Query().Get("fromVersion"))
	if toVersion == "" {
		install, err := s.Repo.GetExtensionInstallState(r.Context(), id, scope, scopeID)
		if err != nil {
			writeLifecycleError0204(w, err)
			return
		}
		toVersion = install.CurrentVersion
		if toVersion == "" {
			toVersion = install.DesiredVersion
		}
		if fromVersion == "" {
			fromVersion = install.CurrentVersion
		}
	}
	diff, err := s.ExtensionSecurity.PermissionDiff(r.Context(), id, fromVersion, toVersion, scope, scopeID)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	grants, err := s.ExtensionSecurity.Grants(r.Context(), id, "", "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"diff": diff, "grants": grants}})
}
func (s Server) extensionPermissionGrant0207(w http.ResponseWriter, r *http.Request) {
	if !s.extensionSecurityReady0207(w) {
		return
	}
	var req extensionPermissionGrantRequest0207
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	if req.Scope == "" {
		req.Scope = "global"
	}
	version, err := s.extensionPermissionVersion0207(r, id, req.Version, req.Scope, req.ScopeID)
	if err != nil {
		writeLifecycleError0204(w, err)
		return
	}
	g, err := s.ExtensionSecurity.Grant(r.Context(), id, version, req.Scope, req.ScopeID, req.Permission, s.adminActor(r), req.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:permission:grant", id+"@"+version+":"+g.Scope+":"+g.ScopeID+":"+g.Permission)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": g})
}
func (s Server) extensionPermissionRevoke0207(w http.ResponseWriter, r *http.Request) {
	if !s.extensionSecurityReady0207(w) {
		return
	}
	scope, scopeID := securityScope0207(r)
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	permission := strings.ToLower(strings.TrimSpace(r.PathValue("permission")))
	if err := s.ExtensionSecurity.Revoke(r.Context(), id, scope, scopeID, permission); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, 404, "permission grant not found")
		} else {
			writeError(w, 400, err.Error())
		}
		return
	}
	s.audit(r, s.adminActor(r), "extension:permission:revoke", id+":"+scope+":"+scopeID+":"+permission)
	w.WriteHeader(http.StatusNoContent)
}
func (s Server) extensionSecretsList0207(w http.ResponseWriter, r *http.Request) {
	if !s.extensionSecurityReady0207(w) {
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	scopeID := strings.TrimSpace(r.URL.Query().Get("scopeId"))
	items, err := s.ExtensionSecurity.ListSecrets(r.Context(), r.PathValue("extensionId"), scope, scopeID)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items, "count": len(items)}})
}
func (s Server) extensionSecretPut0207(w http.ResponseWriter, r *http.Request) {
	if !s.extensionSecurityReady0207(w) {
		return
	}
	var req extensionSecretWrite0207
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.Scope == "" {
		req.Scope = "global"
	}
	value, err := base64.StdEncoding.DecodeString(req.ValueBase64)
	if err != nil {
		writeError(w, 400, "valueBase64 is invalid")
		return
	}
	meta, err := s.ExtensionSecurity.SetSecret(r.Context(), r.PathValue("extensionId"), req.Scope, req.ScopeID, r.PathValue("secretName"), value, s.adminActor(r))
	for i := range value {
		value[i] = 0
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:secret:set", meta.ExtensionID+":"+meta.Scope+":"+meta.ScopeID+":"+meta.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": meta})
}
func (s Server) extensionSecretDelete0207(w http.ResponseWriter, r *http.Request) {
	if !s.extensionSecurityReady0207(w) {
		return
	}
	scope, scopeID := securityScope0207(r)
	id := r.PathValue("extensionId")
	name := r.PathValue("secretName")
	if err := s.ExtensionSecurity.DeleteSecret(r.Context(), id, scope, scopeID, name); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, 404, "secret not found")
		} else {
			writeError(w, 400, err.Error())
		}
		return
	}
	s.audit(r, s.adminActor(r), "extension:secret:delete", id+":"+scope+":"+scopeID+":"+name)
	w.WriteHeader(http.StatusNoContent)
}
