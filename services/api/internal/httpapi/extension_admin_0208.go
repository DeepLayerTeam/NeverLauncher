package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const adminBridgeProtocol0208 = "neverextensions.admin-rpc.v1"
const maxAdminEntrypointBytes0208 = int64(2 << 20)

type adminExtensionCatalogItem0208 struct {
	ExtensionID string                            `json:"extensionId"`
	Name        string                            `json:"name"`
	Version     string                            `json:"version"`
	Scope       string                            `json:"scope"`
	ScopeID     string                            `json:"scopeId,omitempty"`
	Generation  int64                             `json:"generation"`
	PackageID   string                            `json:"packageIdentity,omitempty"`
	Admin       model.ExtensionAdminContributions `json:"admin"`
	Runtime     *extensionhost.Status             `json:"runtime,omitempty"`
	LastError   string                            `json:"lastError,omitempty"`
}

type adminExtensionRPCRequest0208 struct {
	Protocol string          `json:"protocol"`
	ID       string          `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type adminExtensionRPCResponse0208 struct {
	Protocol string `json:"protocol"`
	ID       string `json:"id"`
	Result   any    `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (s Server) requireAdminAuthenticated0208(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.verifyAdminTokenFromRequest(r); err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		next(w, r)
	})
}

func (s Server) adminUserCanProject0208(claims authClaims, projectID string) bool {
	return s.canAccessProject(claims, projectID)
}

func adminExtensionProjectAllowed0208(install model.ExtensionInstall, projectID string) bool {
	projectID = strings.TrimSpace(projectID)
	if install.Scope != "project" {
		return projectID != ""
	}
	return projectID != "" && projectID == strings.TrimSpace(install.ScopeID)
}

func adminTarget0208(m model.ExtensionManifest) (model.ExtensionTarget, bool) {
	for _, t := range m.Targets {
		if strings.EqualFold(strings.TrimSpace(t.Kind), "admin") {
			return t, true
		}
	}
	return model.ExtensionTarget{}, false
}

func (s Server) adminInstallManifest0208(r *http.Request, id, scope, scopeID string) (model.ExtensionInstall, model.ExtensionManifest, error) {
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
		return model.ExtensionInstall{}, model.ExtensionManifest{}, fmt.Errorf("extension is not enabled")
	}
	ver, err := s.Repo.GetExtensionVersion(r.Context(), id, install.CurrentVersion)
	if err != nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, err
	}
	if ver.Manifest.Admin == nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, fmt.Errorf("extension does not declare admin contributions")
	}
	if _, ok := adminTarget0208(ver.Manifest); !ok {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, fmt.Errorf("extension does not declare admin target")
	}
	if s.ExtensionSecurity == nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, fmt.Errorf("extension security unavailable")
	}
	allowed, err := s.ExtensionSecurity.Allowed(r.Context(), id, install.CurrentVersion, install.Scope, install.ScopeID, "ui:contribute", install.ScopeID)
	if err != nil {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, err
	}
	if !allowed {
		return model.ExtensionInstall{}, model.ExtensionManifest{}, fmt.Errorf("ui:contribute is not granted")
	}
	return install, ver.Manifest, nil
}

func (s Server) adminExtensionCatalog0208(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"safeMode": true, "protocol": adminBridgeProtocol0208, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "items": []any{}}})
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid admin session")
		return
	}
	installs, err := s.Repo.ListExtensionInstallStates(r.Context(), "", "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	items := make([]adminExtensionCatalogItem0208, 0)
	for _, install := range installs {
		if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled || install.CurrentVersion == "" {
			continue
		}
		if install.Scope == "project" && !s.adminUserCanProject0208(claims, install.ScopeID) {
			continue
		}
		ver, err := s.Repo.GetExtensionVersion(r.Context(), install.ExtensionID, install.CurrentVersion)
		if err != nil || ver.Manifest.Admin == nil {
			continue
		}
		if _, ok := adminTarget0208(ver.Manifest); !ok {
			continue
		}
		if s.ExtensionSecurity == nil {
			continue
		}
		allowed, err := s.ExtensionSecurity.Allowed(r.Context(), install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, "ui:contribute", install.ScopeID)
		if err != nil || !allowed {
			continue
		}
		item := adminExtensionCatalogItem0208{ExtensionID: install.ExtensionID, Name: ver.Manifest.Name, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, Generation: install.Generation, PackageID: install.CurrentPackageIdentity, Admin: *ver.Manifest.Admin, LastError: install.LastError}
		if s.ExtensionHost != nil {
			if st, e := s.ExtensionHost.Get(extensionhost.Key{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID}); e == nil {
				item.Runtime = &st
			}
		}
		items = append(items, item)
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
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocol": adminBridgeProtocol0208, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "sandbox": "allow-scripts", "items": items}})
}

func safeAdminEntrypoint0208(root, entry string) (string, error) {
	entry = filepath.Clean(filepath.FromSlash(strings.TrimSpace(entry)))
	if entry == "." || filepath.IsAbs(entry) || entry == ".." || strings.HasPrefix(entry, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid admin entrypoint")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	pathAbs, err := filepath.Abs(filepath.Join(rootAbs, entry))
	if err != nil {
		return "", err
	}
	if pathAbs != rootAbs && !strings.HasPrefix(pathAbs, rootAbs+string(filepath.Separator)) {
		return "", errors.New("admin entrypoint escapes payload")
	}
	info, err := os.Lstat(pathAbs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("admin entrypoint must be a regular non-symlink file")
	}
	if info.Size() > maxAdminEntrypointBytes0208 {
		return "", errors.New("admin entrypoint exceeds 2 MiB")
	}
	return pathAbs, nil
}

func hardenAdminHTML0208(raw string) string {
	csp := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; media-src data: blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'">`
	lower := strings.ToLower(raw)
	if idx := strings.Index(lower, "<head>"); idx >= 0 {
		return raw[:idx+6] + csp + raw[idx+6:]
	}
	return "<!doctype html><html><head>" + csp + "</head><body>" + raw + "</body></html>"
}

func (s Server) adminExtensionEntrypoint0208(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions Safe Mode is active (--no-extensions)")
		return
	}
	id := r.PathValue("extensionId")
	scope, scopeID := securityScope0207(r)
	install, manifest, err := s.adminInstallManifest0208(r, id, scope, scopeID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	claims, _ := s.adminClaims(r)
	if install.Scope == "project" && !s.adminUserCanProject0208(claims, install.ScopeID) {
		writeError(w, http.StatusForbidden, "project access denied")
		return
	}
	target, _ := adminTarget0208(manifest)
	payload, err := extensionlifecycle.CurrentPayloadDir(s.Config.ExtensionRoot, install.Scope, install.ScopeID, install.ExtensionID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	path, err := safeAdminEntrypoint0208(payload, target.Entrypoint)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, 404, "admin entrypoint not found")
		} else {
			writeError(w, 500, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"protocol": adminBridgeProtocol0208, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "extensionId": install.ExtensionID, "version": install.CurrentVersion, "generation": install.Generation, "html": hardenAdminHTML0208(string(data))}})
}

func (s Server) adminExtensionRPC0208(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionSafeMode {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions Safe Mode is active (--no-extensions)")
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.PathValue("extensionId")))
	scope, scopeID := securityScope0207(r)
	install, _, err := s.adminInstallManifest0208(r, id, scope, scopeID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "invalid admin session")
		return
	}
	if install.Scope == "project" && !s.adminUserCanProject0208(claims, install.ScopeID) {
		writeError(w, 403, "project access denied")
		return
	}
	var req adminExtensionRPCRequest0208
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Method = strings.TrimSpace(req.Method)
	if req.Protocol != adminBridgeProtocol0208 || req.ID == "" || len(req.ID) > 160 || req.Method == "" || len(req.Method) > 64 || len(req.Params) > 256<<10 {
		writeError(w, 400, "invalid Admin RPC envelope")
		return
	}
	method := strings.ToLower(req.Method)
	respond := func(result any, callErr error) {
		out := adminExtensionRPCResponse0208{Protocol: adminBridgeProtocol0208, ID: req.ID, Result: result}
		if callErr != nil {
			out.Result = nil
			out.Error = callErr.Error()
		}
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": out})
	}
	allow := func(permission, projectID string) error {
		if s.ExtensionSecurity == nil {
			return errors.New("extension security unavailable")
		}
		ok, e := s.ExtensionSecurity.Allowed(r.Context(), install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, permission, projectID)
		if e != nil {
			return fmt.Errorf("policy unavailable: %w", e)
		}
		if !ok {
			return fmt.Errorf("extension capability %s denied", permission)
		}
		return nil
	}
	audit := func() {
		s.audit(r, claims.Email, "extension:admin-rpc:"+method, install.ExtensionID+":"+install.Scope+":"+install.ScopeID)
	}
	switch method {
	case "context.get":
		respond(map[string]any{"extensionId": install.ExtensionID, "version": install.CurrentVersion, "extensionApiVersion": extensioncontract.ExtensionAPIVersion, "scope": install.Scope, "scopeId": install.ScopeID, "generation": install.Generation, "actor": map[string]any{"id": claims.Sub, "email": claims.Email}}, nil)
	case "projects.list":
		if err := allow("project:read", ""); err != nil {
			respond(nil, err)
			return
		}
		projects := s.Repo.ListProjects()
		out := make([]model.Project, 0, len(projects))
		for _, p := range projects {
			if install.Scope == "project" && p.ID != install.ScopeID {
				continue
			}
			if s.adminUserCanProject0208(claims, p.ID) {
				out = append(out, p)
			}
		}
		audit()
		respond(out, nil)
	case "releases.list":
		var p struct {
			ProjectID string `json:"projectId"`
		}
		if json.Unmarshal(req.Params, &p) != nil || strings.TrimSpace(p.ProjectID) == "" {
			respond(nil, errors.New("projectId required"))
			return
		}
		if !adminExtensionProjectAllowed0208(install, p.ProjectID) {
			respond(nil, errors.New("extension project scope denied"))
			return
		}
		if !s.adminUserCanProject0208(claims, p.ProjectID) {
			respond(nil, errors.New("user project access denied"))
			return
		}
		if err := allow("release:read", p.ProjectID); err != nil {
			respond(nil, err)
			return
		}
		items, e := s.Repo.ListVersions(p.ProjectID)
		if e == nil {
			audit()
		}
		respond(items, e)
	case "audit.list":
		if install.Scope == "project" {
			respond(nil, errors.New("global audit data is unavailable to project-scoped extensions"))
			return
		}
		if !s.authorizeClaims(r, claims, "audit:read", "", "audit", "").Allowed {
			respond(nil, errors.New("user audit:read denied"))
			return
		}
		if err := allow("audit:read", ""); err != nil {
			respond(nil, err)
			return
		}
		items := s.Repo.ListAuditEvents()
		if len(items) > 200 {
			items = items[len(items)-200:]
		}
		audit()
		respond(items, nil)
	case "storage.info":
		if !s.hasAnyProjectPermission(r, claims, "project:read") {
			respond(nil, errors.New("user project:read denied"))
			return
		}
		if err := allow("storage:read", ""); err != nil {
			respond(nil, err)
			return
		}
		audit()
		respond(map[string]any{"driver": s.Storage.Driver()}, nil)
	case "telemetry.emit":
		var p struct {
			ProjectID string `json:"projectId"`
			Event     string `json:"event"`
			Status    string `json:"status"`
		}
		if json.Unmarshal(req.Params, &p) != nil || strings.TrimSpace(p.ProjectID) == "" || strings.TrimSpace(p.Event) == "" {
			respond(nil, errors.New("projectId and event required"))
			return
		}
		if !adminExtensionProjectAllowed0208(install, p.ProjectID) {
			respond(nil, errors.New("extension project scope denied"))
			return
		}
		if !s.adminUserCanProject0208(claims, p.ProjectID) {
			respond(nil, errors.New("user project access denied"))
			return
		}
		if err := allow("telemetry:write", p.ProjectID); err != nil {
			respond(nil, err)
			return
		}
		s.Repo.AddTelemetryEvent(model.TelemetryEvent{ID: "extui-" + time.Now().UTC().Format("20060102150405.000000000"), ProjectID: p.ProjectID, LauncherVersion: s.Version, Event: "extension.ui." + strings.TrimSpace(p.Event), Status: strings.TrimSpace(p.Status), CreatedAt: time.Now().UTC()})
		audit()
		respond(map[string]any{"accepted": true}, nil)
	default:
		respond(nil, fmt.Errorf("unsupported Admin RPC method %q", method))
	}
}

func (s Server) adminExtensionManager0208(w http.ResponseWriter, r *http.Request) {
	installs, err := s.Repo.ListExtensionInstallStates(r.Context(), "", "")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(installs))
	for _, install := range installs {
		row := map[string]any{"install": install}
		if install.CurrentVersion != "" {
			if ver, e := s.Repo.GetExtensionVersion(r.Context(), install.ExtensionID, install.CurrentVersion); e == nil {
				row["manifest"] = ver.Manifest
				if s.ExtensionSecurity != nil {
					if diff, de := s.ExtensionSecurity.PermissionDiff(r.Context(), install.ExtensionID, install.CurrentVersion, install.CurrentVersion, install.Scope, install.ScopeID); de == nil {
						row["permissions"] = diff
					}
				}
			}
		}
		if s.ExtensionHost != nil {
			key := extensionhost.Key{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID}
			if st, e := s.ExtensionHost.Get(key); e == nil {
				row["runtime"] = st
				if logs, le := s.ExtensionHost.Logs(key, 100); le == nil {
					row["logs"] = logs
				}
			}
		}
		items = append(items, row)
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items, "count": len(items)}})
}
