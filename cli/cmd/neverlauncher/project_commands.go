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
		printJSON(map[string]any{"version": version, "api": "3.7", "sdks": sdks})
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
		manifest := PluginManifest{SchemaVersion: "1.2", ID: "ru.example.neverlauncher." + target, Name: "Пример SDK-расширения", Version: "0.1.0", Target: target, API: "3.7", Entrypoint: sdkEntrypoint(target), Permissions: []string{"release:read"}}
		if err := writeJSONFile(filepath.Join(out, "neverlauncher-plugin.json"), manifest); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(sdkReadme(target)), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, sdkEntrypoint(target)), []byte(sdkTemplate(target)), 0o644)
	case "validate":
		if len(args) < 2 {
			return errors.New("sdk validate требует путь к каталогу расширения или neverlauncher-plugin.json")
		}
		path := args[1]
		manifestPath := path
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			manifestPath = filepath.Join(path, "neverlauncher-plugin.json")
		}
		data, err := os.ReadFile(manifestPath)
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
		if manifest.API != "3.7" && manifest.API != "3.3" && manifest.API != "3.1" && manifest.API != "3.0" {
			errs = append(errs, "api должен быть совместим с 3.0, 3.1, 3.3 или 3.7")
		}
		if len(errs) > 0 {
			printJSON(map[string]any{"valid": false, "errors": errs})
			return errors.New("SDK-расширение не прошло проверку")
		}
		printJSON(map[string]any{"valid": true, "id": manifest.ID, "target": manifest.Target, "api": manifest.API, "manifest": manifestPath})
		return nil
	default:
		return fmt.Errorf("неизвестная sdk-подкоманда: %s", args[0])
	}
}

func sdkEntrypoint(target string) string {
	switch target {
	case "backend", "cli":
		return "main.go"
	case "admin", "desktop":
		return "index.ts"
	default:
		return "extension.txt"
	}
}

func sdkReadme(target string) string {
	return "# Расширение NeverLauncher\\n\\nЦель: " + target + "\\n\\nФайл `neverlauncher-plugin.json` описывает расширение. Исходный файл entrypoint создаётся как стартовый шаблон для SDK NeverLauncher 3.7.\\n"
}

func sdkTemplate(target string) string {
	switch target {
	case "backend":
		return "package main\\n\\nimport \\\"fmt\\\"\\n\\nfunc main() {\\n\\tfmt.Println(\\\"NeverLauncher backend extension\\\")\\n}\\n"
	case "cli":
		return "package main\\n\\nimport \\\"fmt\\\"\\n\\nfunc main() {\\n\\tfmt.Println(\\\"NeverLauncher CLI extension\\\")\\n}\\n"
	case "admin":
		return "export const extension = { id: 'ru.example.neverlauncher.admin', target: 'admin', title: 'Admin extension' };\\n"
	case "desktop":
		return "export const extension = { id: 'ru.example.neverlauncher.desktop', target: 'desktop', title: 'Desktop extension' };\\n"
	default:
		return ""
	}
}

func handlePlugin(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные plugin-подкоманды: list, template, validate")
	}
	switch args[0] {
	case "list":
		printJSON(map[string]any{
			"version":     version,
			"api":         "3.7",
			"targets":     []string{"backend", "admin", "desktop", "cli"},
			"permissions": []string{"storage:read", "storage:write", "release:read", "release:write", "ui:extend", "diagnostics:read"},
		})
		return nil
	case "template":
		target := flagValue(args, "--target", "backend")
		out := flagValue(args, "--output", "neverlauncher-plugin.json")
		manifest := PluginManifest{
			SchemaVersion: "1.2",
			ID:            "ru.example.neverlauncher.plugin",
			Name:          "Пример расширения NeverLauncher",
			Version:       "1.0.0",
			Target:        target,
			API:           "3.7",
			Entrypoint:    "./plugin",
			Permissions:   []string{"release:read"},
		}
		if out == "-" {
			printJSON(manifest)
			return nil
		}
		return writeJSONFile(out, manifest)
	case "validate":
		if len(args) < 2 {
			return errors.New("plugin validate требует путь к plugin manifest")
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
			printJSON(map[string]any{"valid": false, "errors": errs})
			return errors.New("plugin manifest не прошёл проверку")
		}
		printJSON(map[string]any{"valid": true, "id": manifest.ID, "target": manifest.Target, "api": manifest.API})
		return nil
	default:
		return fmt.Errorf("неизвестная plugin-подкоманда: %s", args[0])
	}
}
