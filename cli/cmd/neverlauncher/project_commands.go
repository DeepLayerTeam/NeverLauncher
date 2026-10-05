package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func handleProject(args []string) error {
	if len(args) >= 2 && args[0] == "template" && args[1] == "list" {
		printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "version": version, "templates": projectTemplates()})
		return nil
	}
	if len(args) >= 1 && args[0] == "create" {
		templateID := flagValue(args, "--template", "vanilla")
		out := flagValue(args, "--output", "project."+templateID+".json")
		project := map[string]any{"schemaVersion": cliSchemaVersion, "template": templateID, "projectId": "demo-" + templateID, "name": "Demo " + templateID, "version": version}
		return writeJSONFile(out, project)
	}
	if len(args) >= 1 && args[0] == "publish" {
		projectID := flagValue(args, "--project", "demo-project")
		channel := flagValue(args, "--channel", "stable")
		out := flagValue(args, "--output", "")
		plan := publishTransactionPlan("project", projectID, channel, flagValue(args, "--version", version))
		if out != "" && out != "-" {
			return writeJSONFile(out, plan)
		}
		printJSON(plan)
		return nil
	}
	if len(args) < 1 || args[0] != "validate" {
		return errors.New("использование: neverlauncher project validate --target 1.0 project.json | neverlauncher project publish --project demo --channel stable")
	}
	if len(args) < 2 {
		return errors.New("project validate требует путь к project.json")
	}
	target := flagValue(args, "--target", "1.0")
	path := args[len(args)-1]
	if strings.HasPrefix(path, "--") {
		return errors.New("project validate требует путь к project.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var project map[string]any
	if err := json.Unmarshal(data, &project); err != nil {
		return err
	}
	var warnings []string
	var errs []string
	for _, field := range []string{"id", "name"} {
		if strings.TrimSpace(fmt.Sprint(project[field])) == "" || fmt.Sprint(project[field]) == "<nil>" {
			errs = append(errs, "отсутствует обязательное поле "+field)
		}
	}
	if _, ok := project["profiles"]; !ok {
		warnings = append(warnings, "для canonical project contract желательно явно описать profiles")
	}
	report := compatibilityReport("project", target, path, warnings, errs)
	printJSON(report)
	if len(errs) > 0 {
		return errors.New("проект не прошёл проверку совместимости")
	}
	return nil
}

type canonicalOpenAPIDocument struct {
	OpenAPI string                     `json:"openapi"`
	Paths   map[string]json.RawMessage `json:"paths"`
}

func canonicalOpenAPIErrors(data []byte) []string {
	var document canonicalOpenAPIDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return []string{"canonical OpenAPI должен быть валидным JSON/YAML-совместимым документом: " + err.Error()}
	}
	errs := make([]string, 0)
	if document.OpenAPI != "3.1.1" {
		errs = append(errs, "ожидается OpenAPI 3.1.1")
	}
	for _, path := range []string{"/health", "/ready", "/api/v1/status"} {
		if _, ok := document.Paths[path]; !ok {
			errs = append(errs, "в canonical OpenAPI отсутствует путь "+path)
		}
	}
	for path := range document.Paths {
		for _, legacy := range []string{"/api/v2", "/api/v3", "/api/v4", "/api/v5"} {
			if path == legacy || strings.HasPrefix(path, legacy+"/") {
				errs = append(errs, "canonical OpenAPI содержит удалённый historical path "+path)
			}
		}
	}
	return errs
}

func handleAPI(args []string) error {
	if len(args) < 1 || args[0] != "compatibility-check" {
		return errors.New("использование: neverlauncher api compatibility-check --openapi schemas/openapi.yaml --target 1.0.0")
	}
	openapiPath := flagValue(args, "--openapi", "schemas/openapi.yaml")
	target := flagValue(args, "--target", "1.0.0")
	data, err := os.ReadFile(openapiPath)
	if err != nil {
		return err
	}
	errs := canonicalOpenAPIErrors(data)
	report := compatibilityReport("api", target, openapiPath, nil, errs)
	printJSON(report)
	if len(errs) > 0 {
		return errors.New("API-контракт не прошёл canonical compatibility-check")
	}
	return nil
}

func handleTenant(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные tenant-подкоманды: template, validate, plan")
	}
	switch args[0] {
	case "template":
		out := flagValue(args, "--output", "tenant.json")
		profile := defaultTenantProfile()
		if out == "-" {
			printJSON(profile)
			return nil
		}
		return writeJSONFile(out, profile)
	case "validate":
		if len(args) < 2 {
			return errors.New("tenant validate требует путь к tenant.json")
		}
		profile, err := readTenantProfile(args[1])
		if err != nil {
			return err
		}
		errs := validateTenantProfile(profile)
		if len(errs) > 0 {
			printJSON(map[string]any{"valid": false, "errors": errs})
			return errors.New("tenant-профиль не прошёл проверку")
		}
		printJSON(map[string]any{"valid": true, "tenantId": profile.TenantID, "projects": profile.Projects, "storagePrefix": profile.Storage.Prefix})
		return nil
	case "plan":
		profilePath := flagValue(args, "--tenant", "tenant.json")
		profile, err := readTenantProfile(profilePath)
		if err != nil {
			return err
		}
		printJSON(map[string]any{
			"schemaVersion": "1.0",
			"tenantId":      profile.TenantID,
			"checks":        []string{"изолировать проекты по tenantId", "использовать отдельный storage prefix", "проверить RBAC-права проекта", "проверить audit log по tenantId"},
			"storage":       profile.Storage,
			"limits":        profile.Limits,
		})
		return nil
	case "audit":
		return handleTenantAudit(args)
	default:
		return fmt.Errorf("неизвестная tenant-подкоманда: %s", args[0])
	}
}

func defaultTenantProfile() TenantProfile {
	return TenantProfile{
		SchemaVersion: "1.0",
		TenantID:      "demo-tenant",
		Name:          "Демо-проект NeverLauncher",
		OwnerEmail:    "admin@example.ru",
		Projects:      []string{"demo-project"},
		Storage:       TenantStorage{Driver: "local", Prefix: "tenants/demo-tenant"},
		Branding:      "branding/demo-tenant.json",
		Limits:        map[string]int{"projects": 10, "profiles": 50, "versions": 200, "storageGb": 50},
		Metadata:      map[string]string{"environment": "production"},
	}
}

func readTenantProfile(path string) (TenantProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TenantProfile{}, err
	}
	var profile TenantProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return TenantProfile{}, err
	}
	return profile, nil
}

func validateTenantProfile(profile TenantProfile) []string {
	var errs []string
	if strings.TrimSpace(profile.SchemaVersion) == "" {
		errs = append(errs, "отсутствует schemaVersion")
	}
	if strings.TrimSpace(profile.TenantID) == "" {
		errs = append(errs, "отсутствует tenantId")
	}
	if strings.TrimSpace(profile.Name) == "" {
		errs = append(errs, "отсутствует name")
	}
	if strings.TrimSpace(profile.OwnerEmail) == "" {
		errs = append(errs, "отсутствует ownerEmail")
	}
	if len(profile.Projects) == 0 {
		errs = append(errs, "tenant должен содержать хотя бы один projectId")
	}
	if !containsString([]string{"local", "s3"}, profile.Storage.Driver) {
		errs = append(errs, "storage.driver должен быть local или s3")
	}
	if strings.TrimSpace(profile.Storage.Prefix) == "" {
		errs = append(errs, "storage.prefix обязателен для изоляции файлов")
	}
	if strings.Contains(profile.Storage.Prefix, "..") {
		errs = append(errs, "storage.prefix не должен содержать ..")
	}
	return errs
}

func handleBranding(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные branding-подкоманды: template, validate, preview")
	}
	switch args[0] {
	case "template":
		out := flagValue(args, "--output", "branding.json")
		profile := defaultBrandingProfile()
		if out == "-" {
			printJSON(profile)
			return nil
		}
		return writeJSONFile(out, profile)
	case "validate":
		if len(args) < 2 {
			return errors.New("branding validate требует путь к branding.json")
		}
		profile, err := readBrandingProfile(args[1])
		if err != nil {
			return err
		}
		errs := validateBrandingProfile(profile)
		if len(errs) > 0 {
			printJSON(map[string]any{"valid": false, "errors": errs})
			return errors.New("бренд-профиль не прошёл проверку")
		}
		printJSON(map[string]any{"valid": true, "projectId": profile.ProjectID, "productName": profile.ProductName, "schemaVersion": profile.SchemaVersion})
		return nil
	case "preview":
		if len(args) < 2 {
			return errors.New("branding preview требует путь к branding.json")
		}
		profile, err := readBrandingProfile(args[1])
		if err != nil {
			return err
		}
		printJSON(map[string]any{
			"projectId":    profile.ProjectID,
			"productName":  profile.ProductName,
			"windowTitle":  profile.WindowTitle,
			"primaryColor": profile.PrimaryColor,
			"accentColor":  profile.AccentColor,
			"links":        profile.Links,
		})
		return nil
	default:
		return fmt.Errorf("неизвестная branding-подкоманда: %s", args[0])
	}
}

func defaultBrandingProfile() BrandingProfile {
	return BrandingProfile{
		SchemaVersion: "1.0",
		ProjectID:     "demo-project",
		ProductName:   "NeverLauncher",
		WindowTitle:   "NeverLauncher",
		Logo:          "assets/branding/logo.png",
		Icon:          "assets/branding/icon.png",
		PrimaryColor:  "#0f172a",
		AccentColor:   "#38bdf8",
		Background:    "#020617",
		Links: map[string]string{
			"site":    "https://example.ru",
			"support": "https://example.ru/support",
		},
		Texts: map[string]string{
			"loginTitle":   "Вход в проект",
			"playButton":   "Играть",
			"updateButton": "Обновить клиент",
		},
	}
}

func readBrandingProfile(path string) (BrandingProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BrandingProfile{}, err
	}
	var profile BrandingProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return BrandingProfile{}, err
	}
	return profile, nil
}

func validateBrandingProfile(profile BrandingProfile) []string {
	var errs []string
	if strings.TrimSpace(profile.SchemaVersion) == "" {
		errs = append(errs, "отсутствует schemaVersion")
	}
	if strings.TrimSpace(profile.ProjectID) == "" {
		errs = append(errs, "отсутствует projectId")
	}
	if strings.TrimSpace(profile.ProductName) == "" {
		errs = append(errs, "отсутствует productName")
	}
	if strings.TrimSpace(profile.WindowTitle) == "" {
		errs = append(errs, "отсутствует windowTitle")
	}
	for name, value := range map[string]string{"primaryColor": profile.PrimaryColor, "accentColor": profile.AccentColor, "background": profile.Background} {
		if !isHexColor(value) {
			errs = append(errs, name+" должен быть HEX-цветом вида #RRGGBB")
		}
	}
	return errs
}

func isHexColor(value string) bool {
	if len(value) != 7 || value[0] != '#' {
		return false
	}
	for _, ch := range value[1:] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

func handleSDK(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные sdk-подкоманды: list, init, validate")
	}
	sdks := []map[string]string{
		{"target": "backend", "language": "go", "path": "sdk/backend/go", "purpose": "серверные расширения Backend API"},
		{"target": "admin", "language": "typescript", "path": "sdk/admin/typescript", "purpose": "страницы и виджеты Admin Panel"},
		{"target": "desktop", "language": "typescript/rust", "path": "sdk/desktop", "purpose": "панели и действия Desktop Client"},
		{"target": "cli", "language": "go", "path": "sdk/cli/go", "purpose": "дополнительные CLI-команды"},
	}
	switch args[0] {
	case "list":
		printJSON(map[string]any{"version": version, "api": "3.7", "manifest": canonicalExtensionManifestName0201, "manifestSchema": "2.0", "sdks": sdks})
		return nil
	case "init":
		target := flagValue(args, "--target", "backend")
		out := flagValue(args, "--out", "neverlauncher-extension")
		if !containsString([]string{"backend", "admin", "desktop", "cli"}, target) {
			return errors.New("--target должен быть одним из: backend, admin, desktop, cli")
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			return err
		}
		manifest := CanonicalExtensionManifest0201{
			SchemaVersion: "2.0",
			ID:            "ru.example.neverlauncher." + target,
			Name:          "Пример SDK-расширения",
			Version:       "0.1.0",
			Publisher:     "Example Publisher",
			API:           "3.7",
			Targets:       []CanonicalExtensionTarget0201{{Kind: target, Entrypoint: sdkEntrypoint(target)}},
			Permissions:   []string{"release:read"},
		}
		if target == "admin" {
			manifest.Permissions = []string{"ui:contribute", "project:read"}
			manifest.Admin = &CanonicalExtensionAdminContributions0208{Pages: []CanonicalExtensionAdminPage0208{{ID: "main", Title: "Example extension"}}, Navigation: []CanonicalExtensionAdminNavigation0208{{ID: "main-nav", Label: "Example extension", PageID: "main"}}, DashboardWidgets: []CanonicalExtensionAdminWidget0208{{ID: "summary", Title: "Example extension", PageID: "main", Height: 280}}}
		}
		manifest, _, err := normalizeCanonicalExtension0201(manifest)
		if err != nil {
			return err
		}
		if err := writeJSONFile(filepath.Join(out, canonicalExtensionManifestName0201), manifest); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(sdkReadme(target)), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, sdkEntrypoint(target)), []byte(sdkTemplate(target)), 0o644)
	case "validate":
		if len(args) < 2 {
			return errors.New("sdk validate требует путь к каталогу расширения или neverlauncher-extension.json")
		}
		manifest, path, digest, err := loadCanonicalExtension0201(args[1])
		if err != nil {
			return err
		}
		printJSON(map[string]any{"valid": true, "id": manifest.ID, "targets": manifest.Targets, "api": manifest.API, "manifest": path, "sha256": digest})
		return nil
	default:
		return fmt.Errorf("неизвестная sdk-подкоманда: %s", args[0])
	}
}

func sdkEntrypoint(target string) string {
	switch target {
	case "backend", "cli":
		return "main.go"
	case "admin":
		return "index.html"
	case "desktop":
		return "index.ts"
	default:
		return "extension.txt"
	}
}

func sdkReadme(target string) string {
	return "# Расширение NeverLauncher\\n\\nЦель: " + target + "\\n\\nФайл `neverlauncher-extension.json` описывает расширение. Исходный файл entrypoint создаётся как стартовый шаблон для SDK NeverLauncher 3.7.\\n"
}

func sdkTemplate(target string) string {
	switch target {
	case "backend":
		return "package main\\n\\nimport \\\"fmt\\\"\\n\\nfunc main() {\\n\\tfmt.Println(\\\"NeverLauncher backend extension\\\")\\n}\\n"
	case "cli":
		return "package main\\n\\nimport \\\"fmt\\\"\\n\\nfunc main() {\\n\\tfmt.Println(\\\"NeverLauncher CLI extension\\\")\\n}\\n"
	case "admin":
		return `<!doctype html><html><head><meta charset="utf-8"><title>NeverLauncher extension</title><style>body{font:14px system-ui;margin:0;padding:16px;color:#111}pre{white-space:pre-wrap}</style></head><body><h2>NeverLauncher Admin extension</h2><pre id="out">Waiting for host…</pre><script>(()=>{const P='neverextensions.admin-rpc.v1';let seq=0,pending=new Map();const out=document.getElementById('out');window.addEventListener('message',e=>{if(e.source!==parent||!e.data||e.data.protocol!==P)return;const m=e.data;if(m.type==='rpc.response'){const p=pending.get(m.id);if(!p)return;pending.delete(m.id);m.error?p.reject(new Error(m.error)):p.resolve(m.result)}if(m.type==='host.context'){rpc('context.get',{}).then(async ctx=>{const projects=await rpc('projects.list',{});out.textContent=JSON.stringify({ctx,projects},null,2)}).catch(err=>out.textContent=String(err))}});function rpc(method,params){const id='rpc-'+Date.now()+'-'+(++seq);parent.postMessage({protocol:P,type:'rpc.request',id,method,params},'*');return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});setTimeout(()=>{if(pending.delete(id))reject(new Error('RPC timeout'))},10000)})}})();</script></body></html>`
	case "desktop":
		return "export const extension = { id: 'ru.example.neverlauncher.desktop', target: 'desktop', title: 'Desktop extension' };\\n"
	default:
		return ""
	}
}

func handlePlugin(args []string) error {
	if len(args) < 1 {
		return errors.New("plugin — legacy compatibility alias; используйте extension template|validate|import-legacy")
	}
	switch args[0] {
	case "list":
		printJSON(map[string]any{
			"version":           version,
			"deprecated":        true,
			"canonicalManifest": canonicalExtensionManifestName0201,
			"manifestSchema":    "2.0",
			"targets":           []string{"backend", "admin", "desktop", "cli"},
		})
		return nil
	case "template":
		return handleExtension0201(append([]string{"template"}, args[1:]...))
	case "validate":
		if len(args) < 2 {
			return errors.New("plugin validate требует путь к manifest")
		}
		if filepath.Base(canonicalExtensionManifestPath0201(args[1])) == canonicalExtensionManifestName0201 {
			return handleExtension0201([]string{"validate", args[1]})
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var manifest PluginManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}
		var errs []string
		if strings.TrimSpace(manifest.ID) == "" {
			errs = append(errs, "отсутствует id")
		}
		if strings.TrimSpace(manifest.Name) == "" {
			errs = append(errs, "отсутствует name")
		}
		if strings.TrimSpace(manifest.Version) == "" {
			errs = append(errs, "отсутствует version")
		}
		if !containsString([]string{"backend", "admin", "desktop", "cli"}, manifest.Target) {
			errs = append(errs, "target должен быть одним из: backend, admin, desktop, cli")
		}
		if strings.TrimSpace(manifest.API) == "" {
			errs = append(errs, "отсутствует api")
		}
		if len(errs) > 0 {
			printJSON(map[string]any{"valid": false, "legacy": true, "errors": errs})
			return errors.New("legacy plugin manifest не прошёл проверку")
		}
		printJSON(map[string]any{"valid": true, "legacy": true, "deprecated": true, "id": manifest.ID, "target": manifest.Target, "api": manifest.API, "migration": "nl extension import-legacy <neverlauncher-plugin.json> --publisher <publisher>"})
		return nil
	default:
		return fmt.Errorf("неизвестная plugin-подкоманда: %s", args[0])
	}
}
