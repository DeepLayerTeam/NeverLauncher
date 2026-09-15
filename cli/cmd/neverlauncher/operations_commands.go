package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func handleProduction(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные production-подкоманды: deployment, first-run, e2e")
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "deployment", "compose":
		return writeOrPrintJSON(out, productionDeployment990())
	case "first-run":
		return writeOrPrintJSON(out, productionFirstRun990())
	case "e2e":
		return writeOrPrintJSON(out, productionE2E990())
	default:
		return fmt.Errorf("неизвестная production-подкоманда: %s", args[0])
	}
}

func handleAdminOps9100(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные adminops-подкоманды: status, readiness, diagnostics, backup")
	}
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("adminops-команды требуют --backend <url>")
	}
	out := flagValue(args, "--output", "")
	var payload map[string]any
	var err error
	switch args[0] {
	case "status":
		payload, err = httpJSON("GET", backend+"/api/v1/status", nil)
	case "readiness":
		payload, err = httpJSON("GET", backend+"/ready", nil)
	case "diagnostics":
		payload, _, err = adminBackendGet(args, "/api/v1/operations/diagnostics")
	case "backup":
		payload, _, err = adminBackendGet(args, "/api/v1/operations/backup")
	default:
		return fmt.Errorf("неизвестная adminops-подкоманда: %s", args[0])
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, payload)
}

func productionDeployment990() map[string]any {
	return map[string]any{
		"schemaVersion": "0.10.0",
		"toolVersion":   version,
		"status":        "production-deployment-ready",
		"composeFile":   "deploy/production/docker-compose.yml",
		"envExample":    "deploy/production/env.production.example",
		"nginxConfig":   "deploy/production/nginx.conf",
		"services":      []string{"postgres", "redis", "api", "admin", "nginx"},
		"volumes":       []string{"neverlauncher_postgres", "neverlauncher_redis", "neverlauncher_storage", "neverlauncher_backups"},
		"commands":      []string{"cp deploy/production/env.production.example deploy/production/.env", "cd deploy/production && docker compose --env-file .env up -d", "./scripts/install/production-setup.sh"},
	}
}

func productionFirstRun990() map[string]any {
	return map[string]any{
		"schemaVersion": "0.10.0",
		"toolVersion":   version,
		"status":        "first-run-prepared",
		"script":        "scripts/install/production-setup.sh",
		"bootstrap":     []string{"validate env", "apply migrations", "create first admin", "create demo project", "create vanilla profile", "create stable channel", "issue bridge token", "write bootstrap report"},
		"outputs":       []string{".neverlauncher/production-first-run/first-run-report-0.10.0.json"},
	}
}

func productionE2E990() map[string]any {
	return map[string]any{
		"schemaVersion": "0.10.0",
		"toolVersion":   version,
		"status":        "production-e2e-ready",
		"script":        "e2e/scripts/run-minecraft-e2e.sh",
		"scenario":      "Desktop → package download → launch → server join → session revoke → deny next join",
		"checks":        []string{"compose present", "first-run bootstrap present", "desktop package gate", "launch plan gate", "server bridge allow/revoke/deny", "audit diagnostics"},
		"commands":      []string{"bash e2e/scripts/run-minecraft-e2e.sh"},
	}
}

func handleLoader(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные loader-подкоманды: list, resolve, validate, compatibility, merge, install-plan")
	}
	loader := strings.ToLower(flagValue(args, "--loader", "fabric"))
	minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
	loaderVersion := flagValue(args, "--loader-version", "")
	metadataPath := flagValue(args, "--metadata", "")
	installerProfile := flagValue(args, "--installer-profile", "")
	versionJSON := flagValue(args, "--version-json", "")
	assetIndexPath := flagValue(args, "--asset-index", "")
	out := flagValue(args, "--output", "")
	var payload map[string]any
	var err error
	switch args[0] {
	case "list":
		payload = map[string]any{
			"schemaVersion": cliSchemaVersion,
			"toolVersion":   version,
			"status":        "real-loader-installer",
			"loaders":       loaderCatalog(),
			"default":       "vanilla",
			"scope":         []string{"Vanilla", "Fabric", "Forge", "NeoForge", "Quilt"},
		}
	case "resolve", "install-plan":
		if !isSupportedLoader(loader) {
			return fmt.Errorf("неподдерживаемый loader: %s", loader)
		}
		payload, err = realLoaderInstallPlan(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON, assetIndexPath)
		if err != nil {
			return err
		}
	case "merge":
		if !isSupportedLoader(loader) {
			return fmt.Errorf("неподдерживаемый loader: %s", loader)
		}
		payload, err = realLoaderInstallPlan(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON, assetIndexPath)
		if err != nil {
			return err
		}
		payload["mode"] = "merged-runtime-profile"
	case "validate":
		payload = validateLoaderProfile(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON)
	case "compatibility":
		if !isSupportedLoader(loader) {
			return fmt.Errorf("неподдерживаемый loader: %s", loader)
		}
		payload = map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "loader": loader, "minecraftVersion": minecraftVersion, "status": "compatible", "constraints": loaderCompatibility(loader), "runtime": []string{"version-json", "loader-metadata", "installer-profile", "libraries", "natives", "launch-plan", "delivery"}}
	default:
		return fmt.Errorf("неизвестная loader-подкоманда: %s", args[0])
	}
	if out != "" && out != "-" {
		return writeJSONFile(out, payload)
	}
	printJSON(payload)
	return nil
}

func loaderCatalog() []map[string]any {
	return []map[string]any{
		{"id": "vanilla", "title": "Vanilla", "status": "stable", "installer": "mojang-version-manifest", "runtime": "builtin", "metadata": "version.json"},
		{"id": "fabric", "title": "Fabric", "status": "real-installer", "installer": "fabric-meta", "runtime": "loader-metadata", "metadata": "loader profile JSON или Fabric Meta profile"},
		{"id": "forge", "title": "Forge", "status": "real-installer", "installer": "forge-installer", "runtime": "installer-profile", "metadata": "install_profile.json"},
		{"id": "neoforge", "title": "NeoForge", "status": "real-installer", "installer": "neoforge-installer", "runtime": "installer-profile", "metadata": "install_profile.json"},
		{"id": "quilt", "title": "Quilt", "status": "real-installer", "installer": "quilt-meta", "runtime": "loader-metadata", "metadata": "loader profile JSON или Quilt Meta profile"},
	}
}

func isSupportedLoader(loader string) bool {
	switch loader {
	case "vanilla", "fabric", "forge", "neoforge", "quilt":
		return true
	default:
		return false
	}
}

func realLoaderInstallPlan(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON, assetIndexPath string) (map[string]any, error) {
	if loader == "vanilla" {
		plan, err := realRuntimePlan(minecraftVersion, "vanilla", "Player", ".neverlauncher/client", versionJSON, assetIndexPath)
		if err != nil {
			return nil, err
		}
		plan["schemaVersion"] = cliSchemaVersion
		plan["loaderInstall"] = map[string]any{"type": "vanilla", "status": "builtin", "steps": []string{"resolve-mojang-version", "resolve-assets", "resolve-libraries"}}
		return plan, nil
	}
	basePlan, err := realRuntimePlan(minecraftVersion, loader, "Player", ".neverlauncher/client", versionJSON, assetIndexPath)
	if err != nil {
		return nil, err
	}
	metadata, metadataSource, err := resolveLoaderMetadata(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile)
	if err != nil {
		return nil, err
	}
	mergedLibraries, mergedClasspath := mergeLoaderLibraries(basePlan, metadata)
	mergedGameArgs := mergeArgSlices(asStringSlice(basePlan["gameArgs"]), metadata.GameArgs, extractArgStrings(metadata.Arguments.Game))
	mergedJVMArgs := mergeArgSlices(asStringSlice(basePlan["jvmArgs"]), metadata.JVMArgs, extractArgStrings(metadata.Arguments.JVM))
	mainClass := metadata.MainClass
	if mainClass == "" {
		mainClass = defaultLoaderMainClass(loader)
	}
	if loaderVersion == "" {
		loaderVersion = metadata.LoaderVersion
	}
	if loaderVersion == "" {
		loaderVersion = "resolved-from-metadata"
	}
	return map[string]any{
		"schemaVersion":    "0.8.8",
		"toolVersion":      version,
		"loader":           loader,
		"loaderVersion":    loaderVersion,
		"minecraftVersion": minecraftVersion,
		"status":           "resolved",
		"mode":             "real-loader-installer",
		"metadataSource":   metadataSource,
		"installer":        loaderInstallerID(loader),
		"mainClass":        mainClass,
		"libraries":        mergedLibraries,
		"classpath":        mergedClasspath,
		"gameArgs":         mergedGameArgs,
		"jvmArgs":          mergedJVMArgs,
		"merge": map[string]any{
			"baseRuntime":      versionJSON,
			"assetIndex":       assetIndexPath,
			"loaderMetadata":   metadataPath,
			"installerProfile": installerProfile,
			"strategy":         loaderMergeStrategy(loader),
		},
		"steps":  []string{"resolve-minecraft-version", "load-loader-metadata", "parse-installer-profile", "merge-libraries", "merge-classpath", "merge-jvm-args", "merge-game-args", "validate-launch-plan"},
		"checks": loaderChecks(loader),
	}, nil
}

func resolveLoaderMetadata(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile string) (LoaderMetadata, string, error) {
	if installerProfile != "" {
		var profile ForgeInstallProfile
		if err := loadJSONSource(installerProfile, &profile); err != nil {
			return LoaderMetadata{}, installerProfile, err
		}
		metadata := LoaderMetadata{Loader: loader, MinecraftVersion: minecraftVersion, LoaderVersion: profile.Version, MainClass: defaultLoaderMainClass(loader), Libraries: profile.Libraries, JVMArgs: []string{"-DignoreList=", "-DmergeModules="}, GameArgs: []string{"--launchTarget", loaderLaunchTarget(loader)}}
		if profile.Minecraft != "" {
			metadata.MinecraftVersion = profile.Minecraft
		}
		if profile.Path != "" {
			metadata.Libraries = append([]MojangLibrary{{Name: profile.Path}}, metadata.Libraries...)
		}
		return metadata, installerProfile, nil
	}
	if metadataPath != "" {
		var metadata LoaderMetadata
		if err := loadJSONSource(metadataPath, &metadata); err == nil && (metadata.MainClass != "" || len(metadata.Libraries) > 0 || metadata.Loader != "") {
			if metadata.Loader == "" {
				metadata.Loader = loader
			}
			if metadata.MinecraftVersion == "" {
				metadata.MinecraftVersion = minecraftVersion
			}
			if metadata.LoaderVersion == "" {
				metadata.LoaderVersion = loaderVersion
			}
			return metadata, metadataPath, nil
		}
		var fabricProfile FabricMetaProfile
		if err := loadJSONSource(metadataPath, &fabricProfile); err != nil {
			return LoaderMetadata{}, metadataPath, err
		}
		metadata = LoaderMetadata{Loader: loader, MinecraftVersion: minecraftVersion, LoaderVersion: loaderVersion, MainClass: fabricProfile.MainClass, Libraries: fabricProfile.Libraries, Arguments: fabricProfile.Arguments}
		if metadata.MainClass == "" {
			metadata.MainClass = defaultLoaderMainClass(loader)
		}
		return metadata, metadataPath, nil
	}
	if loader == "vanilla" {
		return LoaderMetadata{Loader: "vanilla", MinecraftVersion: minecraftVersion, LoaderVersion: loaderVersion, MainClass: "net.minecraft.client.main.Main"}, "mojang-version-json", nil
	}
	return LoaderMetadata{}, "", fmt.Errorf("loader %s требует --metadata или --installer-profile; builtin fallback metadata в 0.10.2 запрещены", loader)
}

func mergeLoaderLibraries(basePlan map[string]any, metadata LoaderMetadata) ([]map[string]any, []string) {
	seen := map[string]bool{}
	var libraries []map[string]any
	var classpath []string
	for _, lib := range asMapSlice(basePlan["libraries"]) {
		key := fmt.Sprint(lib["name"]) + "|" + fmt.Sprint(lib["path"])
		if !seen[key] {
			libraries = append(libraries, lib)
			seen[key] = true
		}
	}
	for _, cp := range asStringSlice(basePlan["classpath"]) {
		if cp != "" && !containsString(classpath, cp) {
			classpath = append(classpath, cp)
		}
	}
	for _, lib := range metadata.Libraries {
		path := loaderLibraryPath(lib)
		key := lib.Name + "|" + path
		if !seen[key] {
			libraries = append(libraries, map[string]any{"name": lib.Name, "path": path, "url": lib.Downloads.Artifact.URL, "sha1": lib.Downloads.Artifact.SHA1, "size": lib.Downloads.Artifact.Size, "source": "loader"})
			seen[key] = true
		}
		if path != "" && !containsString(classpath, path) {
			classpath = append(classpath, path)
		}
	}
	return libraries, classpath
}

func loaderLibraryPath(lib MojangLibrary) string {
	path := lib.Downloads.Artifact.Path
	if path == "" {
		path = lib.Downloads.Artifact.ID
	}
	if path == "" {
		path = localMavenPath(lib.Name)
	}
	return filepath.ToSlash(filepath.Join("libraries", path))
}

func mergeArgSlices(groups ...[]string) []string {
	var out []string
	for _, group := range groups {
		for _, item := range group {
			if item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

func asStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func asMapSlice(value any) []map[string]any {
	switch v := value.(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func validateLoaderProfile(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON string) map[string]any {
	var errs []string
	var warnings []string
	if !isSupportedLoader(loader) {
		errs = append(errs, "неподдерживаемый loader")
	}
	if minecraftVersion == "" {
		errs = append(errs, "minecraftVersion обязателен")
	}
	if loader != "vanilla" && loaderVersion == "" && metadataPath == "" && installerProfile == "" {
		warnings = append(warnings, "loaderVersion не указан; будет использован дефолтный канал/метаданные")
	}
	if versionJSON == "" {
		warnings = append(warnings, "version.json не указан; будет использован fallback runtime plan")
	}
	if loader == "forge" || loader == "neoforge" {
		if installerProfile == "" {
			warnings = append(warnings, "для Forge/NeoForge желательно указать --installer-profile install_profile.json")
		}
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "valid": len(errs) == 0, "loader": loader, "minecraftVersion": minecraftVersion, "loaderVersion": loaderVersion, "metadata": metadataPath, "installerProfile": installerProfile, "errors": errs, "warnings": warnings, "checks": loaderChecks(loader)}
}

func defaultLoaderMainClass(loader string) string {
	switch loader {
	case "fabric":
		return "net.fabricmc.loader.impl.launch.knot.KnotClient"
	case "quilt":
		return "org.quiltmc.loader.impl.launch.knot.KnotClient"
	case "forge", "neoforge":
		return "cpw.mods.bootstraplauncher.BootstrapLauncher"
	default:
		return "net.minecraft.client.main.Main"
	}
}

func loaderInstallerID(loader string) string {
	switch loader {
	case "fabric":
		return "fabric-meta"
	case "quilt":
		return "quilt-meta"
	case "forge":
		return "forge-installer-profile"
	case "neoforge":
		return "neoforge-installer-profile"
	default:
		return "mojang-version-manifest"
	}
}

func loaderLaunchTarget(loader string) string {
	switch loader {
	case "forge", "neoforge":
		return "forgeclient"
	default:
		return "client"
	}
}

func loaderMergeStrategy(loader string) string {
	switch loader {
	case "forge", "neoforge":
		return "installer-profile-libraries-and-processor-aware-args"
	case "fabric", "quilt":
		return "metadata-profile-libraries-and-knot-main-class"
	default:
		return "vanilla-runtime-only"
	}
}

func loaderChecks(loader string) []string {
	base := []string{"minecraft-version-supported", "metadata-resolved", "libraries-resolved", "classpath-merged", "launch-plan-compatible", "delivery-compatible"}
	if loader != "vanilla" {
		base = append(base, "loader-version-pinned", "mod-directory-present", "loader-signature-policy", "metadata-source-recorded")
	}
	return base
}

func loaderCompatibility(loader string) map[string]any {
	return map[string]any{
		"java":                   []int{17, 21},
		"minecraftRange":         "1.13+ для Fabric/Quilt; 1.16.8+ для Forge/NeoForge при наличии installer profile",
		"requiresInstallerMerge": loader == "forge" || loader == "neoforge",
		"supportsOptionalMods":   loader != "vanilla",
		"profileFields":          []string{"loader", "loaderVersion", "minecraftVersion", "mainClass", "libraries", "classpath", "jvmArgs", "gameArgs"},
		"metadataInputs":         []string{"--version-json", "--metadata", "--installer-profile", "--asset-index"},
	}
}

func migrationDoctorReport(items []string) map[string]any {
	type migrationInfo struct {
		Number string `json:"number"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	byNumber := map[string][]migrationInfo{}
	var migrations []migrationInfo
	for _, path := range items {
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), "neverlauncher-migration-superseded: true") {
			continue
		}
		base := filepath.Base(path)
		number := "unknown"
		if len(base) >= 4 {
			number = base[:4]
		}
		sha, size, err := hashFile(path)
		if err != nil {
			sha = "error:" + err.Error()
		}
		info := migrationInfo{Number: number, Path: path, SHA256: sha, Size: size}
		migrations = append(migrations, info)
		byNumber[number] = append(byNumber[number], info)
	}
	duplicates := map[string][]migrationInfo{}
	for number, group := range byNumber {
		if len(group) > 1 {
			duplicates[number] = group
		}
	}
	status := "ok"
	if len(duplicates) > 0 {
		status = "requires-cleanup"
	}
	return map[string]any{"schemaVersion": "0.10.0", "toolVersion": version, "status": status, "count": len(migrations), "duplicates": duplicates, "migrations": migrations, "policy": []string{"новые миграции получают уникальный монотонный номер", "superseded tombstone migrations игнорируются migration-doctor и остаются no-op для overlay archives", "checksum фиксируется в release bundle и audit log"}}
}

func handleInstall(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные install-подкоманды: profile list, wizard, env, storage-check, bootstrap-admin, first-project, first-run, readiness, verify")
	}
	out := flagValue(args, "--output", "")
	if args[0] == "profile" && len(args) > 1 && args[1] == "list" {
		return writeOrPrintJSON(out, map[string]any{"schemaVersion": "1.0", "version": version, "profiles": installProfiles()})
	}
	switch args[0] {
	case "wizard":
		return writeOrPrintJSON(out, installWizardPayload(args))
	case "env":
		return writeOrPrintJSON(out, installEnvPayload(args))
	case "storage-check":
		return installStorageCheck(args)
	case "bootstrap-admin":
		backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
		if backend == "" {
			return errors.New("bootstrap-admin требует --backend")
		}
		token := flagValue(args, "--bootstrap-token", os.Getenv("NEVERLAUNCHER_BOOTSTRAP_TOKEN"))
		if strings.TrimSpace(token) == "" {
			return errors.New("bootstrap-admin требует --bootstrap-token или NEVERLAUNCHER_BOOTSTRAP_TOKEN")
		}
		email, password := flagValue(args, "--email", ""), flagValue(args, "--password", "")
		if email == "" || password == "" {
			return errors.New("bootstrap-admin требует --email и --password")
		}
		body := map[string]any{"email": email, "displayName": flagValue(args, "--display-name", "Administrator"), "password": password, "actor": "nl install bootstrap-admin"}
		payload, err := httpJSONWithHeaders("POST", backend+"/api/v1/install/bootstrap-admin", body, map[string]string{"X-NeverLauncher-Bootstrap-Token": token})
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "first-project":
		backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
		if backend == "" {
			return errors.New("first-project требует --backend")
		}
		token := backendToken(args)
		if token == "" {
			return errors.New("first-project требует --token или NEVERLAUNCHER_TOKEN")
		}
		body := map[string]any{"projectId": flagValue(args, "--project", "demo-project"), "profileId": flagValue(args, "--profile", "vanilla"), "channel": flagValue(args, "--channel", "stable"), "actor": "nl install first-project"}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/install/first-project", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "first-run":
		return installFirstRun(args)
	case "readiness":
		return installReadiness(args)
	case "verify":
		return installVerify(args)
	default:
		return fmt.Errorf("неизвестная install-подкоманда: %s", strings.Join(args, " "))
	}
}

func installWizardPayload(args []string) map[string]any {
	backend := strings.TrimRight(flagValue(args, "--backend", "http://127.0.0.1:8080"), "/")
	profile := flagValue(args, "--profile", "single-server-local")
	return map[string]any{
		"schemaVersion": "1.0.0",
		"toolVersion":   version,
		"mode":          "production",
		"backend":       backend,
		"profile":       profile,
		"status":        "ready",
		"steps": []map[string]any{
			{"id": "environment", "title": "Environment", "command": "nl install env --profile " + profile},
			{"id": "database", "title": "PostgreSQL", "checks": []string{"NEVERLAUNCHER_DATABASE_DSN", "NEVERLAUNCHER_SQL_DRIVER=pgx", "migrations"}},
			{"id": "storage", "title": "Storage", "command": "nl install storage-check --storage local"},
			{"id": "admin", "title": "Bootstrap admin", "command": "nl install bootstrap-admin --email admin@example.test"},
			{"id": "project", "title": "First project", "command": "nl install first-project --project demo-project --profile vanilla"},
			{"id": "verify", "title": "Installation verification", "command": "nl install verify --backend " + backend + " --profile " + profile},
		},
	}
}

func installEnvPayload(args []string) map[string]any {
	profile := flagValue(args, "--profile", "single-server-local")
	return map[string]any{"schemaVersion": "1.0.0", "toolVersion": version, "profile": profile, "required": []string{"NEVERLAUNCHER_HTTP_ADDR", "NEVERLAUNCHER_PUBLIC_URL", "NEVERLAUNCHER_REPOSITORY_DRIVER=postgres", "NEVERLAUNCHER_SQL_DRIVER=pgx", "NEVERLAUNCHER_DATABASE_DSN", "NEVERLAUNCHER_AUTH_TOKEN_SECRET", "NEVERLAUNCHER_STORAGE_DRIVER"}, "generatedFiles": []string{".env", "deploy/production/env.production.example"}}
}

func installStorageCheck(args []string) error {
	out := flagValue(args, "--output", "")
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	if backend != "" {
		token := backendToken(args)
		if token == "" {
			return errors.New("install storage-check --backend требует --token или NEVERLAUNCHER_TOKEN")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/admin/storage/health", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	}
	storage := strings.ToLower(strings.TrimSpace(flagValue(args, "--storage", "local")))
	if storage != "local" {
		return errors.New("S3 storage-check выполняется только через --backend, чтобы проверять реальные production credentials/bucket")
	}
	rootDir := filepath.Clean(flagValue(args, "--storage-root", "./storage"))
	if info, err := os.Lstat(rootDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("storage root не может быть symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return err
	}
	probe, err := os.CreateTemp(rootDir, ".neverlauncher-storage-check-*")
	if err != nil {
		return fmt.Errorf("storage root не writable: %w", err)
	}
	name := probe.Name()
	if _, err := probe.WriteString("neverlauncher-storage-check"); err != nil {
		probe.Close()
		_ = os.Remove(name)
		return err
	}
	if err := probe.Sync(); err != nil {
		probe.Close()
		_ = os.Remove(name)
		return err
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	abs, _ := filepath.Abs(rootDir)
	return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "storage": "local", "root": abs, "status": "ok", "checks": []string{"mkdir", "write", "fsync", "remove", "symlink-root-rejected"}})
}

func installVerify(args []string) error {
	out := flagValue(args, "--output", "")
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	if backend == "" {
		return errors.New("install verify требует --backend")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("install verify требует --token или NEVERLAUNCHER_TOKEN")
	}
	checks := map[string]any{}
	for id, endpoint := range map[string]string{"health": "/health", "ready": "/ready"} {
		payload, err := httpJSON("GET", backend+endpoint, nil)
		if err != nil {
			return fmt.Errorf("install verify %s failed: %w", id, err)
		}
		checks[id] = payload
	}
	for id, endpoint := range map[string]string{
		"admin":       "/api/v1/admin/me",
		"storage":     "/api/v1/admin/storage/health",
		"consistency": "/api/v1/operations/storage/consistency",
	} {
		payload, err := httpJSONWithAuth("GET", backend+endpoint, nil, token)
		if err != nil {
			return fmt.Errorf("install verify %s failed: %w", id, err)
		}
		checks[id] = payload
	}
	projects, err := httpJSONWithAuth("GET", backend+"/api/v1/projects", nil, token)
	if err != nil {
		return fmt.Errorf("install verify projects failed: %w", err)
	}
	checks["projects"] = projects
	return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "profile": flagValue(args, "--profile", "single-server-local"), "backend": backend, "status": "verified", "checks": checks})
}

func installFirstRun(args []string) error {
	out := flagValue(args, "--output", "")
	backend := strings.TrimRight(flagValue(args, "--backend", "https://neverlauncher.example"), "/")
	project := flagValue(args, "--project", "demo-project")
	profile := flagValue(args, "--profile", "vanilla")
	outputDir := strings.TrimSpace(flagValue(args, "--output-dir", ""))
	if outputDir == "" {
		return errors.New("install first-run требует --output-dir; небезопасный встроенный generator удалён")
	}
	apiImage := strings.TrimSpace(flagValue(args, "--api-image", os.Getenv("NEVERLAUNCHER_API_IMAGE")))
	adminImage := strings.TrimSpace(flagValue(args, "--admin-image", os.Getenv("NEVERLAUNCHER_ADMIN_IMAGE")))
	allowUnpinned := flagValue(args, "--allow-unpinned-images", "false") == "true"
	if apiImage == "" || adminImage == "" {
		return errors.New("install first-run требует --api-image <registry/image@sha256:...> и --admin-image <registry/image@sha256:...>; standalone bundle не собирает исходники")
	}
	if !allowUnpinned && (!strings.Contains(apiImage, "@sha256:") || !strings.Contains(adminImage, "@sha256:")) {
		return errors.New("standalone first-run требует digest-pinned images (@sha256:...); для dev-only допускается --allow-unpinned-images true")
	}
	files, err := writeFirstRunBundle(outputDir, backend, project, profile, apiImage, adminImage)
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, map[string]any{
		"schemaVersion":  cliSchemaVersion,
		"toolVersion":    version,
		"status":         "canonical-production-bundle-copied",
		"outputDir":      outputDir,
		"generatedFiles": files,
		"next":           []string{"заполнить env.production.example и сохранить как .env вне VCS", "настроить TLS", "docker compose up -d", "nl install verify --backend " + backend},
	})
}

func installReadiness(args []string) error {
	out := flagValue(args, "--output", "")
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	if backend == "" {
		return errors.New("install readiness требует --backend; локальная декларативная readiness удалена")
	}
	payload, err := httpJSON("GET", backend+"/api/v1/install/readiness", nil)
	if err != nil {
		return err
	}
	payload["backend"] = backend
	return writeOrPrintJSON(out, payload)
}

func writeFirstRunBundle(outputDir, backend, project, profile, apiImage, adminImage string) ([]string, error) {
	required := []string{"docker-compose.yml", "nginx.conf", "env.production.example", "README.md", "TLS.md", "production-checklist.md"}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}
	created := make([]string, 0, len(required)+1)
	templateSources := map[string]string{}
	for _, name := range required {
		data, source, err := readCanonicalProductionTemplate(name)
		if err != nil {
			return nil, err
		}
		templateSources[name] = source
		if name == "docker-compose.yml" {
			data, err = standaloneProductionCompose(data, apiImage, adminImage)
			if err != nil {
				return nil, err
			}
		}
		dst := filepath.Join(outputDir, name)
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return nil, err
		}
		created = append(created, name)
	}
	report := map[string]any{
		"schemaVersion":   cliSchemaVersion,
		"toolVersion":     version,
		"backend":         backend,
		"projectId":       project,
		"profileId":       profile,
		"generatedAt":     time.Now().UTC().Format(time.RFC3339),
		"status":          "canonical-production-bundle-copied",
		"source":          "embedded canonical deploy/production templates",
		"templateSources": templateSources,
		"security":        "секреты не генерируются и .env не создаётся; API/Admin images закреплены внешними registry refs",
		"images":          map[string]string{"api": apiImage, "admin": adminImage},
		"standalone":      true,
		"next":            []string{"cp env.production.example .env", "задать реальные secrets/TLS paths", "docker compose config", "docker compose up -d", "nl install verify --backend " + backend},
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filepath.Join(outputDir, "first-run-report.json"), data, 0o644); err != nil {
		return nil, err
	}
	created = append(created, "first-run-report.json")
	return created, nil
}

func standaloneProductionCompose(template []byte, apiImage, adminImage string) ([]byte, error) {
	lines := strings.Split(string(template), "\n")
	service := ""
	skipBuild := false
	apiSeen, adminSeen := false, false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			service = strings.TrimSuffix(strings.TrimSpace(line), ":")
		}
		if (service == "api" || service == "admin") && line == "    build:" {
			skipBuild = true
			continue
		}
		if skipBuild {
			if strings.HasPrefix(line, "      ") {
				continue
			}
			skipBuild = false
		}
		if service == "api" && strings.HasPrefix(line, "    image:") {
			line = "    image: " + apiImage
			apiSeen = true
		}
		if service == "admin" && strings.HasPrefix(line, "    image:") {
			line = "    image: " + adminImage
			adminSeen = true
		}
		out = append(out, line)
	}
	if !apiSeen || !adminSeen {
		return nil, errors.New("canonical compose не содержит api/admin image fields")
	}
	result := strings.Join(out, "\n")
	if strings.Contains(result, "context: ../..") || strings.Contains(result, "dockerfile: services/api") || strings.Contains(result, "dockerfile: apps/admin") {
		return nil, errors.New("standalone compose всё ещё содержит build.context; отказ")
	}
	return []byte(result), nil
}

func projectTemplates() []ProjectTemplate {
	return []ProjectTemplate{
		{ID: "vanilla", Title: "Vanilla server project", Description: "Базовый проект без mod loader", Loaders: []string{"vanilla"}, UseCase: "public-server"},
		{ID: "fabric", Title: "Fabric server project", Description: "Проект с Fabric loader и modpack-профилем", Loaders: []string{"fabric"}, UseCase: "modded"},
		{ID: "forge", Title: "Forge server project", Description: "Проект с Forge loader", Loaders: []string{"forge"}, UseCase: "modded"},
		{ID: "neoforge", Title: "NeoForge server project", Description: "Проект с NeoForge loader", Loaders: []string{"neoforge"}, UseCase: "modern-modded"},
		{ID: "quilt", Title: "Quilt server project", Description: "Проект с Quilt loader", Loaders: []string{"quilt"}, UseCase: "experimental-modded"},
		{ID: "modpack", Title: "Modpack project", Description: "Готовая структура для модпака", Loaders: []string{"fabric", "forge", "neoforge", "quilt"}, UseCase: "modpack"},
		{ID: "mmorpg", Title: "MMORPG project", Description: "Шаблон для RPG/MMORPG-сервера", Loaders: []string{"paper", "purpur"}, UseCase: "rpg"},
		{ID: "survival-plus", Title: "Survival+ project", Description: "Шаблон для Survival+ проекта", Loaders: []string{"paper", "purpur"}, UseCase: "survival"},
		{ID: "private-community", Title: "Private community project", Description: "Закрытый community-проект", Loaders: []string{"vanilla", "fabric"}, UseCase: "private"},
	}
}

func installProfiles() []InstallProfile {
	return []InstallProfile{
		{ID: "single-server-local", Title: "Single-server local", Description: "Один backend/admin на одном сервере с local storage", Components: []string{"api", "admin", "cli", "local-storage"}, Storage: "local"},
		{ID: "single-server-s3", Title: "Single-server S3", Description: "Один backend/admin с S3-compatible storage", Components: []string{"api", "admin", "cli", "s3-storage"}, Storage: "s3"},
		{ID: "multi-project", Title: "Multi-project backend", Description: "Один backend для нескольких проектов", Components: []string{"api", "admin", "rbac", "audit"}, Storage: "local-or-s3"},
		{ID: "multi-tenant", Title: "Multi-tenant backend", Description: "Tenant isolation для нескольких проектов и команд", Components: []string{"api", "admin", "tenants", "rbac", "audit", "s3-storage"}, Storage: "s3"},
		{ID: "development", Title: "Development mode", Description: "Локальная разработка без production-хранилища", Components: []string{"api", "admin", "desktop", "cli"}, Storage: "local"},
		{ID: "offline", Title: "Offline mode", Description: "Ограниченный режим без внешних registry sync", Components: []string{"desktop", "local-manifest", "diagnostics"}, Storage: "local"},
	}
}
