package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var version = "dev"

const cliSchemaVersion = "1.0"

const helpText = `NeverLauncher CLI

Использование:
  nl <команда> [параметры]

Основные команды:
  version                         показать версию CLI
  manifest build|validate|diff    работа с client manifest
  update plan                     построить план обновления
  hashes check                    проверить SHA-256 файлов
  diagnostics collect|redact|validate|policy|bundle
  runtime vanilla-install|fabric-install|quilt-install|forge-install|neoforge-install|...  Minecraft materializers
  loader ...                      loader tooling
  project validate|publish        операции проекта
  api compatibility-check         проверить canonical OpenAPI
  tenant ...                      tenant tooling
  branding ...                    branding tooling
  sdk ...                         SDK tooling
  plugin ...                      plugin manifest tooling

Backend / production:
  auth login|capabilities|accounts|roles|sessions|revoke|logout-all|session-policy|password-policy
  admin overview|users|roles|audit|storage-health|create-project|update-project|create-profile|update-profile|create-channel|update-channel|create-user
  install profile list|wizard|env|storage-check|bootstrap-admin|first-project|first-run|readiness|verify
  operations status|readiness|diagnostics|diagnostics-bundle
  adminops status|readiness|diagnostics|backup
  backup status|create|inspect|restore-dry-run|restore|audit-export|diagnostics-bundle
  db migrations|migration-doctor|migrate|status|validate|repository
  storage ...
  migrate ...
  production deployment|first-run|e2e

Desktop / package / release:
  desktop connect|config|platforms|package|verify
  client ...
  pipeline ...
  release doctor|plan|build|package|verify|sign|publish-plan|publish-check
  delivery target|manifest|verify|verify-windows|prepare-linux|verify-linux|verify-macos|resolve
  packaging prepare|verify|sign

Для Backend-команд укажите --backend <url>. Для защищённых маршрутов используйте --token или NEVERLAUNCHER_TOKEN.
`

type Manifest struct {
	SchemaVersion string         `json:"schemaVersion"`
	ProjectID     string         `json:"projectId"`
	ProfileID     string         `json:"profileId"`
	Channel       string         `json:"channel"`
	Version       string         `json:"version"`
	CreatedAt     string         `json:"createdAt"`
	Files         []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path       string   `json:"path"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	URL        string   `json:"url"`
	Required   bool     `json:"required"`
	Executable bool     `json:"executable,omitempty"`
	TargetOS   []string `json:"targetOs,omitempty"`
}

type ManifestDiff struct {
	FromVersion       string         `json:"fromVersion"`
	ToVersion         string         `json:"toVersion"`
	Added             []ManifestFile `json:"added"`
	Changed           []ManifestFile `json:"changed"`
	Deleted           []string       `json:"deleted"`
	Unchanged         []string       `json:"unchanged"`
	TotalDownloadSize int64          `json:"totalDownloadSize"`
}

type UpdatePlan struct {
	FromVersion       string         `json:"fromVersion"`
	ToVersion         string         `json:"toVersion"`
	Download          []ManifestFile `json:"download"`
	Delete            []string       `json:"delete"`
	Keep              []string       `json:"keep"`
	Verify            []string       `json:"verify"`
	TotalDownloadSize int64          `json:"totalDownloadSize"`
	ResumeDownloads   bool           `json:"resumeDownloads"`
	MaxParallel       int            `json:"maxParallel"`
}

type CompatibilityReport struct {
	SchemaVersion string   `json:"schemaVersion"`
	GeneratedAt   string   `json:"generatedAt"`
	ToolVersion   string   `json:"toolVersion"`
	Target        string   `json:"target"`
	Subject       string   `json:"subject"`
	Status        string   `json:"status"`
	Warnings      []string `json:"warnings"`
	Errors        []string `json:"errors"`
}

type DiagnosticReport struct {
	SchemaVersion   string            `json:"schemaVersion"`
	GeneratedAt     string            `json:"generatedAt"`
	LauncherVersion string            `json:"launcherVersion"`
	OS              string            `json:"os"`
	Arch            string            `json:"arch"`
	BackendURL      string            `json:"backendUrl"`
	JavaPath        string            `json:"javaPath,omitempty"`
	ProfileID       string            `json:"profileId,omitempty"`
	ProfileVersion  string            `json:"profileVersion,omitempty"`
	Status          string            `json:"status"`
	Checks          map[string]string `json:"checks"`
	Logs            []string          `json:"logs,omitempty"`
}

type TenantProfile struct {
	SchemaVersion string            `json:"schemaVersion"`
	TenantID      string            `json:"tenantId"`
	Name          string            `json:"name"`
	OwnerEmail    string            `json:"ownerEmail"`
	Projects      []string          `json:"projects"`
	Storage       TenantStorage     `json:"storage"`
	Branding      string            `json:"branding"`
	Limits        map[string]int    `json:"limits"`
	Metadata      map[string]string `json:"metadata"`
}

type TenantStorage struct {
	Driver string `json:"driver"`
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix"`
}

type BrandingProfile struct {
	SchemaVersion string            `json:"schemaVersion"`
	ProjectID     string            `json:"projectId"`
	ProductName   string            `json:"productName"`
	WindowTitle   string            `json:"windowTitle"`
	Logo          string            `json:"logo"`
	Icon          string            `json:"icon"`
	PrimaryColor  string            `json:"primaryColor"`
	AccentColor   string            `json:"accentColor"`
	Background    string            `json:"background"`
	Links         map[string]string `json:"links"`
	Texts         map[string]string `json:"texts"`
}

type PluginManifest struct {
	SchemaVersion string            `json:"schemaVersion"`
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Type          string            `json:"type,omitempty"`
	Target        string            `json:"target"`
	API           string            `json:"api"`
	Entrypoint    string            `json:"entrypoint"`
	Permissions   []string          `json:"permissions"`
	Hooks         []string          `json:"hooks,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type AdminUXSection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Path        string   `json:"path"`
	Permission  string   `json:"permission"`
	Description string   `json:"description"`
	Badges      []string `json:"badges,omitempty"`
}

type AdminDashboard struct {
	SchemaVersion string           `json:"schemaVersion"`
	GeneratedAt   string           `json:"generatedAt"`
	ToolVersion   string           `json:"toolVersion"`
	Mode          string           `json:"mode"`
	Sections      []AdminUXSection `json:"sections"`
	Metrics       []string         `json:"metrics"`
	Actions       []string         `json:"actions"`
}

type AdminChecklist struct {
	SchemaVersion string   `json:"schemaVersion"`
	GeneratedAt   string   `json:"generatedAt"`
	ToolVersion   string   `json:"toolVersion"`
	Status        string   `json:"status"`
	Items         []string `json:"items"`
}

type DesktopPackageManifest struct {
	SchemaVersion string                   `json:"schemaVersion"`
	GeneratedAt   string                   `json:"generatedAt"`
	ToolVersion   string                   `json:"toolVersion"`
	Version       string                   `json:"version"`
	Platforms     []DesktopPackagePlatform `json:"platforms"`
	ChecksumsFile string                   `json:"checksumsFile"`
}

type DesktopPackagePlatform struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Format   string `json:"format"`
	Artifact string `json:"artifact"`
	Status   string `json:"status"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type ExtensionRegistry struct {
	SchemaVersion string             `json:"schemaVersion"`
	ToolVersion   string             `json:"toolVersion"`
	UpdatedAt     string             `json:"updatedAt"`
	Extensions    []ExtensionInstall `json:"extensions"`
}

type ExtensionInstall struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Type        string   `json:"type,omitempty"`
	Target      string   `json:"target"`
	API         string   `json:"api"`
	Entrypoint  string   `json:"entrypoint"`
	Permissions []string `json:"permissions"`
	Hooks       []string `json:"hooks,omitempty"`
	Enabled     bool     `json:"enabled"`
	Source      string   `json:"source"`
	Signature   string   `json:"signatureStatus"`
	InstalledAt string   `json:"installedAt"`
}

type MigrationPlan struct {
	SchemaVersion string   `json:"schemaVersion"`
	GeneratedAt   string   `json:"generatedAt"`
	ToolVersion   string   `json:"toolVersion"`
	From          string   `json:"from"`
	To            string   `json:"to"`
	Status        string   `json:"status"`
	Steps         []string `json:"steps"`
	Rollback      []string `json:"rollback"`
}

type EcosystemRegistry struct {
	SchemaVersion string              `json:"schemaVersion"`
	ToolVersion   string              `json:"toolVersion"`
	GeneratedAt   string              `json:"generatedAt"`
	Registries    map[string][]string `json:"registries"`
}

type ProjectTemplate struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Loaders     []string `json:"loaders"`
	UseCase     string   `json:"useCase"`
}

type InstallProfile struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Components  []string `json:"components"`
	Storage     string   `json:"storage"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(helpText)
		return nil
	}
	switch args[0] {
	case "version":
		fmt.Printf("NeverLauncher CLI %s\n", version)
		return nil
	case "manifest":
		return handleManifest(args[1:])
	case "update":
		return handleUpdate(args[1:])
	case "hashes":
		return handleHashes(args[1:])
	case "diagnostics":
		return handleDiagnostics(args[1:])
	case "runtime":
		return handleRuntime(args[1:])
	case "loader":
		return handleLoader(args[1:])
	case "project":
		return handleProject(args[1:])
	case "api":
		return handleAPI(args[1:])
	case "tenant":
		return handleTenant(args[1:])
	case "branding":
		return handleBranding(args[1:])
	case "sdk":
		return handleSDK(args[1:])
	case "plugin":
		return handlePlugin(args[1:])
	case "production":
		return handleProduction(args[1:])
	case "adminops", "operator":
		return handleAdminOps9100(args[1:])
	case "install":
		return handleInstall(args[1:])
	case "auth":
		return handleAuth(args[1:])
	case "security":
		return handleSecurity(args[1:])
	case "observability", "operations", "ops":
		return handleObservability(args[1:])
	case "backup":
		return handleBackup(args[1:])
	case "db":
		return handleDB(args[1:])
	case "storage":
		return handleStorage(args[1:])
	case "migrate":
		return handleMigrate(args[1:])
	case "admin":
		return handleAdmin(args[1:])
	case "desktop":
		return handleDesktop(args[1:])
	case "client":
		return handleClient(args[1:])
	case "pipeline":
		return handlePipeline(args[1:])
	case "release":
		return handleRelease(args[1:])
	case "delivery":
		return handleDelivery(args[1:])
	case "packaging", "package-release":
		return handlePackaging(args[1:])
	default:
		return fmt.Errorf("неизвестная команда: %s", args[0])
	}
}

func handleManifest(args []string) error {
	if len(args) < 1 {
		return errors.New("нужно указать подкоманду manifest")
	}
	switch args[0] {
	case "build":
		if len(args) < 2 {
			return errors.New("manifest build требует путь к каталогу клиента")
		}
		clientDir := args[1]
		project := flagValue(args, "--project", "demo-project")
		profile := flagValue(args, "--profile", "vanilla")
		ver := flagValue(args, "--version", version)
		out := flagValue(args, "--output", "manifest.json")
		manifest, err := buildManifest(clientDir, project, profile, ver)
		if err != nil {
			return err
		}
		return writeJSONFile(out, manifest)
	case "validate":
		if len(args) < 2 {
			return errors.New("manifest validate требует путь к manifest.json")
		}
		manifest, err := readManifest(args[1])
		if err != nil {
			return err
		}
		if target := flagValue(args, "--compat", ""); target != "" {
			var warnings []string
			if strings.TrimSpace(manifest.SchemaVersion) == "" {
				warnings = append(warnings, "поле schemaVersion должно быть явно зафиксировано для canonical manifest contract")
			}
			printJSON(compatibilityReport("manifest", target, args[1], warnings, nil))
			return nil
		}
		return nil
	case "diff":
		oldPath := flagValue(args, "--old", "")
		newPath := flagValue(args, "--new", "")
		out := flagValue(args, "--output", "")
		if oldPath == "" || newPath == "" {
			return errors.New("использование: neverlauncher manifest diff --old old.json --new new.json [--output diff.json]")
		}
		oldManifest, err := readManifest(oldPath)
		if err != nil {
			return err
		}
		newManifest, err := readManifest(newPath)
		if err != nil {
			return err
		}
		diff := buildManifestDiff(oldManifest, newManifest)
		if out != "" {
			return writeJSONFile(out, diff)
		}
		printJSON(diff)
		return nil
	default:
		return fmt.Errorf("неизвестная manifest-подкоманда: %s", args[0])
	}
}

func handleUpdate(args []string) error {
	if len(args) < 1 || args[0] != "plan" {
		return errors.New("использование: neverlauncher update plan --from old.json --to new.json [--output update-plan.json]")
	}
	fromPath := flagValue(args, "--from", "")
	toPath := flagValue(args, "--to", "")
	out := flagValue(args, "--output", "")
	if fromPath == "" || toPath == "" {
		return errors.New("update plan требует --from old.json и --to new.json")
	}
	oldManifest, err := readManifest(fromPath)
	if err != nil {
		return err
	}
	newManifest, err := readManifest(toPath)
	if err != nil {
		return err
	}
	plan := buildUpdatePlan(oldManifest, newManifest)
	if out != "" {
		return writeJSONFile(out, plan)
	}
	printJSON(plan)
	return nil
}

func handleHashes(args []string) error {
	if len(args) < 2 || args[0] != "check" {
		return errors.New("использование: neverlauncher hashes check manifest.json --root <каталог>")
	}
	manifest, err := readManifest(args[1])
	if err != nil {
		return err
	}
	root := flagValue(args, "--root", ".")
	for _, f := range manifest.Files {
		path := filepath.Join(root, filepath.FromSlash(f.Path))
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		if sum != f.SHA256 || size != f.Size {
			return fmt.Errorf("хэш или размер файла %s не совпадает", f.Path)
		}
	}
	fmt.Println("Хэши файлов корректны")
	return nil
}

func handleDiagnostics(args []string) error {
	if len(args) < 1 {
		return errors.New("нужно указать подкоманду diagnostics")
	}
	switch args[0] {
	case "collect":
		out := flagValue(args, "--output", "neverlauncher-diagnostic-report.json")
		backendURL := flagValue(args, "--backend-url", "http://localhost:8080")
		javaPath := flagValue(args, "--java-path", "")
		report := DiagnosticReport{
			SchemaVersion:   "1.0",
			GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
			LauncherVersion: version,
			OS:              runtime.GOOS,
			Arch:            runtime.GOARCH,
			BackendURL:      backendURL,
			JavaPath:        javaPath,
			ProfileID:       flagValue(args, "--profile", ""),
			ProfileVersion:  flagValue(args, "--profile-version", ""),
			Status:          "collected",
			Checks: map[string]string{
				"cli":     "ok",
				"backend": "не проверялся локально",
				"java":    diagnosticJavaStatus(javaPath),
			},
			Logs: []string{},
		}
		if err := writeJSONFile(out, report); err != nil {
			return err
		}
		fmt.Printf("Диагностический отчёт сохранён: %s\n", out)
		return nil
	case "redact":
		if len(args) < 2 {
			return errors.New("diagnostics redact требует путь к JSON-отчёту")
		}
		out := flagValue(args, "--output", args[1])
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		redacted := redactSensitiveText(string(data))
		if err := os.WriteFile(out, []byte(redacted), 0o644); err != nil {
			return err
		}
		fmt.Printf("Очищенный диагностический отчёт сохранён: %s\n", out)
		return nil
	case "validate":
		if len(args) < 2 {
			return errors.New("diagnostics validate требует путь к JSON-отчёту")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var report DiagnosticReport
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		if report.SchemaVersion == "" || report.LauncherVersion == "" || report.GeneratedAt == "" {
			return errors.New("диагностический отчёт не содержит обязательные поля schemaVersion, launcherVersion или generatedAt")
		}
		fmt.Println("Диагностический отчёт валиден")
		return nil
	case "policy":
		return writeOrPrintJSON(flagValue(args, "--output", ""), diagnosticsPrivacyPolicyModel())
	case "bundle":
		out := flagValue(args, "--output", "")
		bundle := diagnosticsBundleModel(flagValue(args, "--backend-url", "http://localhost:8080"))
		return writeOrPrintJSON(out, bundle)
	case "support":
		return writeOrPrintJSON(flagValue(args, "--output", ""), operationsSupportSummaryModel())
	default:
		return fmt.Errorf("неизвестная diagnostics-подкоманда: %s", args[0])
	}
}

func diagnosticJavaStatus(javaPath string) string {
	if strings.TrimSpace(javaPath) == "" {
		return "путь к Java не указан"
	}
	if _, err := os.Stat(javaPath); err != nil {
		return "Java не найдена по указанному пути"
	}
	return "путь к Java существует"
}

func redactSensitiveText(input string) string {
	replacements := []string{"token", "password", "secret", "authorization", "accessKey", "secretKey"}
	result := input
	lines := strings.Split(result, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, key := range replacements {
			if strings.Contains(lower, strings.ToLower(key)) && strings.Contains(line, ":") {
				prefix := line[:strings.Index(line, ":")+1]
				lines[i] = prefix + ` "***"`
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}
