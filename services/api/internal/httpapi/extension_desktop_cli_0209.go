package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const desktopBridgeProtocol0209 = "neverextensions.desktop-rpc.v1"
const cliProtocol0209 = "neverextensions.cli.v1"

type desktopExtensionCatalogItem0209 struct {
	ExtensionID   string                              `json:"extensionId"`
	Name          string                              `json:"name"`
	Version       string                              `json:"version"`
	Scope         string                              `json:"scope"`
	ScopeID       string                              `json:"scopeId,omitempty"`
	Generation    int64                               `json:"generation"`
	BridgeAllowed bool                                `json:"bridgeAllowed"`
	Desktop       model.ExtensionDesktopContributions `json:"desktop"`
}

type desktopExtensionRPCRequest0209 struct {
	Protocol string          `json:"protocol"`
	ID       string          `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params,omitempty"`
}
type desktopExtensionRPCResponse0209 struct {
	Protocol string `json:"protocol"`
	ID       string `json:"id"`
	Result   any    `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
}

type cliCatalogItem0209 struct {
	ExtensionID string                          `json:"extensionId"`
	Name        string                          `json:"name"`
	Version     string                          `json:"version"`
	Scope       string                          `json:"scope"`
	ScopeID     string                          `json:"scopeId,omitempty"`
	CLI         model.ExtensionCLIContributions `json:"cli"`
}
type cliInvokeRequest0209 struct {
	Scope   string   `json:"scope"`
	ScopeID string   `json:"scopeId,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

func desktopTarget0209(m model.ExtensionManifest) (model.ExtensionTarget, bool) {
	for _, t := range m.Targets {
		if strings.EqualFold(strings.TrimSpace(t.Kind), "desktop") {
			return t, true
		}
	}
	return model.ExtensionTarget{}, false
}
func cliTargetHTTP0209(m model.ExtensionManifest) (model.ExtensionTarget, bool) {
	for _, t := range m.Targets {
		if strings.EqualFold(strings.TrimSpace(t.Kind), "cli") {
			return t, true
		}
	}
	return model.ExtensionTarget{}, false
}

func (s Server) requireDesktopExtensionAuth0209(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.verifyAdminTokenFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Desktop Bearer-токен")
			return
		}
		session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
		if !ok || strings.TrimSpace(session.TrustedDeviceID) == "" || session.DeviceTrustState != "verified" {
			writeError(w, http.StatusPreconditionRequired, "Desktop Extensions требуют verified device binding")
			return
		}
		next(w, r)
	})
}

func (s Server) desktopInstallManifest0209(r *http.Request, id, scope, scopeID string) (model.ExtensionInstall, model.ExtensionManifest, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "global"
	}
	if scope == "global" {
		scopeID = ""
	}
	install, err := s.Repo.GetExtensionInstallState(r.Context(), id, scope, strings.TrimSpace(scopeID))
	if err != nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, err
	}
	if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled || install.CurrentVersion == "" {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, errors.New("extension is not enabled")
	}
	ver, err := s.Repo.GetExtensionVersion(r.Context(), id, install.CurrentVersion)
	if err != nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, err
	}
	if ver.Manifest.Desktop == nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, errors.New("extension does not declare desktop contributions")
	}
	if _, ok := desktopTarget0209(ver.Manifest); !ok {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, errors.New("extension does not declare desktop target")
	}
	if s.ExtensionSecurity == nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, errors.New("extension security unavailable")
	}
	projectID := ""
	if install.Scope == "project" {
		projectID = install.ScopeID
	}
	allowed, err := s.ExtensionSecurity.Allowed(r.Context(), id, install.CurrentVersion, install.Scope, install.ScopeID, "desktop:contribute", projectID)
	if err != nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, err
	}
	if !allowed {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, errors.New("desktop:contribute is not granted")
	}
	return install, ver.Manifest, nil
}

func (s Server) desktopExtensionCatalog0209(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"safeMode": true, "protocol": desktopBridgeProtocol0209, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "items": []any{}}})
		return
	}
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, 401, "invalid session")
		return
	}
	installs, err := s.Repo.ListExtensionInstallStates(r.Context(), "", "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	items := make([]desktopExtensionCatalogItem0209, 0)
	for _, install := range installs {
		if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled || install.CurrentVersion == "" {
			continue
		}
		if install.Scope == "project" && !s.canAccessProject(claims, install.ScopeID) {
			continue
		}
		ver, e := s.Repo.GetExtensionVersion(r.Context(), install.ExtensionID, install.CurrentVersion)
		if e != nil || ver.Manifest.Desktop == nil {
			continue
		}
		if _, ok := desktopTarget0209(ver.Manifest); !ok {
			continue
		}
		projectID := ""
		if install.Scope == "project" {
			projectID = install.ScopeID
		}
		allowed, e := s.ExtensionSecurity.Allowed(r.Context(), install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, "desktop:contribute", projectID)
		if e != nil || !allowed {
			continue
		}
		bridgeAllowed, bridgeErr := s.ExtensionSecurity.Allowed(r.Context(), install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, "desktop:bridge", projectID)
		if bridgeErr != nil {
			bridgeAllowed = false
		}
		items = append(items, desktopExtensionCatalogItem0209{ExtensionID: install.ExtensionID, Name: ver.Manifest.Name, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, Generation: install.Generation, BridgeAllowed: bridgeAllowed, Desktop: *ver.Manifest.Desktop})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Scope == items[j].Scope && items[i].ScopeID == items[j].ScopeID {
			return items[i].ExtensionID < items[j].ExtensionID
		}
		if items[i].Scope == items[j].Scope {
			return items[i].ScopeID < items[j].ScopeID
		}
		return items[i].Scope < items[j].Scope
	})
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocol": desktopBridgeProtocol0209, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "sandbox": "allow-scripts", "items": items}})
}

func (s Server) desktopExtensionEntrypoint0209(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions Safe Mode is active (--no-extensions)")
		return
	}
	scope, scopeID := securityScope0207(r)
	install, manifest, err := s.desktopInstallManifest0209(r, r.PathValue("extensionId"), scope, scopeID)
	if err != nil {
		writeError(w, 403, err.Error())
		return
	}
	claims, _ := s.verifyAdminTokenFromRequest(r)
	if install.Scope == "project" && !s.canAccessProject(claims, install.ScopeID) {
		writeError(w, 403, "project access denied")
		return
	}
	target, _ := desktopTarget0209(manifest)
	payload, err := extensionlifecycle.CurrentPayloadDir(s.Config.ExtensionRoot, install.Scope, install.ScopeID, install.ExtensionID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	path, err := safeAdminEntrypoint0208(payload, target.Entrypoint)
	if err != nil {
		writeError(w, 409, strings.ReplaceAll(err.Error(), "admin", "desktop"))
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, 404, "desktop entrypoint not found")
		} else {
			writeError(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocol": desktopBridgeProtocol0209, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "extensionId": install.ExtensionID, "version": install.CurrentVersion, "generation": install.Generation, "html": hardenAdminHTML0208(string(data))}})
}

func (s Server) desktopExtensionRPC0209(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions Safe Mode is active (--no-extensions)")
		return
	}
	scope, scopeID := securityScope0207(r)
	install, _, err := s.desktopInstallManifest0209(r, r.PathValue("extensionId"), scope, scopeID)
	if err != nil {
		writeError(w, 403, err.Error())
		return
	}
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, 401, "invalid session")
		return
	}
	if install.Scope == "project" && !s.canAccessProject(claims, install.ScopeID) {
		writeError(w, 403, "project access denied")
		return
	}
	var req desktopExtensionRPCRequest0209
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Method = strings.ToLower(strings.TrimSpace(req.Method))
	if req.Protocol != desktopBridgeProtocol0209 || req.ID == "" || len(req.ID) > 160 || req.Method == "" || len(req.Method) > 64 || len(req.Params) > 128<<10 {
		writeError(w, 400, "invalid Desktop RPC envelope")
		return
	}
	respond := func(result any, e error) {
		out := desktopExtensionRPCResponse0209{Protocol: desktopBridgeProtocol0209, ID: req.ID, Result: result}
		if e != nil {
			out.Result = nil
			out.Error = e.Error()
		}
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": out})
	}
	allow := func(permission, projectID string) error {
		ok, e := s.ExtensionSecurity.Allowed(r.Context(), install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, permission, projectID)
		if e != nil {
			return fmt.Errorf("policy unavailable: %w", e)
		}
		if !ok {
			return fmt.Errorf("extension capability %s denied", permission)
		}
		return nil
	}
	projectAllowed := func(projectID string) bool {
		return projectID != "" && (install.Scope != "project" || install.ScopeID == projectID) && s.canAccessProject(claims, projectID)
	}
	audit := func() {
		s.audit(r, claims.Email, "extension:desktop-rpc:"+req.Method, install.ExtensionID+":"+install.Scope+":"+install.ScopeID)
	}
	switch req.Method {
	case "context.get":
		respond(map[string]any{"extensionId": install.ExtensionID, "version": install.CurrentVersion, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "scope": install.Scope, "scopeId": install.ScopeID, "generation": install.Generation, "actor": map[string]any{"id": claims.Sub, "email": claims.Email}, "deviceVerified": true}, nil)
	case "project.get":
		var p struct {
			ProjectID string `json:"projectId"`
		}
		if json.Unmarshal(req.Params, &p) != nil || !projectAllowed(strings.TrimSpace(p.ProjectID)) {
			respond(nil, errors.New("project access denied"))
			return
		}
		if e := allow("project:read", p.ProjectID); e != nil {
			respond(nil, e)
			return
		}
		project, e := s.Repo.GetProject(p.ProjectID)
		if e == nil {
			audit()
		}
		respond(project, e)
	case "releases.list":
		var p struct {
			ProjectID string `json:"projectId"`
		}
		if json.Unmarshal(req.Params, &p) != nil || !projectAllowed(strings.TrimSpace(p.ProjectID)) {
			respond(nil, errors.New("project access denied"))
			return
		}
		if e := allow("release:read", p.ProjectID); e != nil {
			respond(nil, e)
			return
		}
		items, e := s.Repo.ListVersions(p.ProjectID)
		if e == nil {
			audit()
		}
		respond(items, e)
	default:
		respond(nil, errors.New("unsupported Desktop RPC method"))
	}
}

func (s Server) extensionCLICatalog0209(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"safeMode": true, "protocol": cliProtocol0209, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "items": []any{}}})
		return
	}
	installs, err := s.Repo.ListExtensionInstallStates(r.Context(), "", "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	items := make([]cliCatalogItem0209, 0)
	for _, install := range installs {
		if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled || install.CurrentVersion == "" {
			continue
		}
		ver, e := s.Repo.GetExtensionVersion(r.Context(), install.ExtensionID, install.CurrentVersion)
		if e != nil || ver.Manifest.CLI == nil {
			continue
		}
		if _, ok := cliTargetHTTP0209(ver.Manifest); !ok {
			continue
		}
		projectID := ""
		if install.Scope == "project" {
			projectID = install.ScopeID
		}
		allowed, e := s.ExtensionSecurity.Allowed(r.Context(), install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, "cli:contribute", projectID)
		if e != nil || !allowed {
			continue
		}
		items = append(items, cliCatalogItem0209{ExtensionID: install.ExtensionID, Name: ver.Manifest.Name, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, CLI: *ver.Manifest.CLI})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CLI.Namespace == items[j].CLI.Namespace {
			return items[i].ExtensionID < items[j].ExtensionID
		}
		return items[i].CLI.Namespace < items[j].CLI.Namespace
	})
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocol": cliProtocol0209, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "items": items}})
}

func (s Server) extensionCLIInvoke0209(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions Safe Mode is active (--no-extensions)")
		return
	}
	if s.ExtensionHost == nil {
		writeError(w, 503, "extension host unavailable")
		return
	}
	var req cliInvokeRequest0209
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	req.Scope = strings.ToLower(strings.TrimSpace(req.Scope))
	if req.Scope == "" {
		req.Scope = "global"
	}
	if req.Scope != "global" && req.Scope != "project" {
		writeError(w, 400, "scope must be global or project")
		return
	}
	if req.Scope == "global" {
		req.ScopeID = ""
	} else if strings.TrimSpace(req.ScopeID) == "" {
		writeError(w, 400, "project scope requires scopeId")
		return
	}
	req.Command = strings.ToLower(strings.TrimSpace(req.Command))
	if req.Command == "" || len(req.Command) > 64 || len(req.Args) > 127 {
		writeError(w, 400, "invalid cli command")
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	install, err := s.Repo.GetExtensionInstallState(r.Context(), id, req.Scope, strings.TrimSpace(req.ScopeID))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	ver, err := s.Repo.GetExtensionVersion(r.Context(), id, install.CurrentVersion)
	if err != nil || ver.Manifest.CLI == nil {
		writeError(w, 409, "cli target unavailable")
		return
	}
	declared := false
	for _, cmd := range ver.Manifest.CLI.Commands {
		if cmd.Name == req.Command {
			declared = true
			break
		}
	}
	if !declared {
		writeError(w, 404, "cli command is not declared by extension")
		return
	}
	argv := append([]string{req.Command}, req.Args...)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, runErr := s.ExtensionHost.RunCLI0209(ctx, install, argv)
	claims, _ := s.adminClaims(r)
	actor := claims.Email
	if actor == "" {
		actor = "unknown"
	}
	s.audit(r, actor, "extension:cli:invoke", id+":"+req.Command+":"+req.Scope+":"+req.ScopeID)
	if runErr != nil {
		writeJSON(w, 422, map[string]any{"apiVersion": apiContractVersion, "data": result, "error": map[string]any{"code": 422, "message": runErr.Error()}})
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": result})
}
