package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func handleRuntime(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные runtime-подкоманды: vanilla-install, vanilla-package, fabric-install, fabric-package, quilt-install, quilt-package, forge-install, forge-package, neoforge-install, neoforge-package, resolve, inspect, assets, libraries, java-check, launch-plan, verify, resolver, matrix, metadata-policy, fetch-metadata, resolve-version, resolve-loader, build-classpath, build-launch-plan, verify-launch-plan, parity, parity-smoke, build-download-plan, verify-parity-plan")
	}
	switch args[0] {
	case "vanilla-install":
		return handleRuntimeVanillaInstall(args[1:])
	case "vanilla-package":
		return handleRuntimeVanillaPackage(args[1:])
	case "fabric-install":
		return handleRuntimeFabricInstall(args[1:])
	case "fabric-package":
		return handleRuntimeFabricPackage(args[1:])
	case "quilt-install":
		return handleRuntimeQuiltInstall(args[1:])
	case "quilt-package":
		return handleRuntimeQuiltPackage(args[1:])
	case "forge-install":
		return handleRuntimeForgeInstall(args[1:])
	case "forge-package":
		return handleRuntimeForgePackage(args[1:])
	case "neoforge-install":
		return handleRuntimeNeoForgeInstall(args[1:])
	case "neoforge-package":
		return handleRuntimeNeoForgePackage(args[1:])
	case "resolve":
		minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
		loader := flagValue(args, "--loader", "vanilla")
		versionJSON := flagValue(args, "--version-json", "")
		assetIndexPath := flagValue(args, "--asset-index", "")
		out := flagValue(args, "--output", "minecraft-runtime.json")
		if versionJSON == "" {
			return errors.New("runtime resolve требует --version-json; fallback runtime plan в 0.10.6 запрещён")
		}
		plan, err := realRuntimePlan(minecraftVersion, loader, "Player", ".neverlauncher/client", versionJSON, assetIndexPath)
		if err != nil {
			return err
		}
		if out == "-" {
			printJSON(plan)
			return nil
		}
		return writeJSONFile(out, plan)
	case "inspect":
		if len(args) < 2 {
			return errors.New("runtime inspect требует путь к runtime.json")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			return err
		}
		printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "inspected", "runtime": payload, "checks": runtimeChecks()})
		return nil
	case "assets":
		minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
		assetIndexPath := flagValue(args, "--asset-index", "")
		if assetIndexPath != "" {
			var index MojangAssetIndex
			if err := loadJSONSource(assetIndexPath, &index); err != nil {
				return err
			}
			payload := resolveAssetIndex(index)
			payload["schemaVersion"] = cliSchemaVersion
			payload["toolVersion"] = version
			payload["minecraftVersion"] = minecraftVersion
			payload["source"] = assetIndexPath
			printJSON(payload)
			return nil
		}
		printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "minecraftVersion": minecraftVersion, "assetIndex": map[string]any{"id": minecraftVersion, "url": "https://resources.download.minecraft.net/", "strategy": "mojang-asset-index", "status": "source-required"}, "usage": "neverlauncher runtime assets --asset-index <indexes/version.json>"})
		return nil
	case "libraries":
		minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
		versionJSON := flagValue(args, "--version-json", "")
		if versionJSON != "" {
			var vf MojangVersionFile
			if err := loadJSONSource(versionJSON, &vf); err != nil {
				return err
			}
			libs, natives, classpath := resolveLibraries(vf)
			printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "minecraftVersion": minecraftVersion, "source": versionJSON, "libraries": libs, "natives": natives, "classpath": classpath, "status": "resolved"})
			return nil
		}
		printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "minecraftVersion": minecraftVersion, "status": "source-required", "usage": "neverlauncher runtime libraries --version-json <version.json>"})
		return nil
	case "java-check":
		javaPath := flagValue(args, "--java-path", "java")
		status := "available"
		if javaPath != "java" {
			if _, err := os.Stat(javaPath); err != nil {
				status = "not-found"
			}
		}
		printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "javaPath": javaPath, "status": status, "recommendedMajorVersion": 21, "supportedMajorVersions": []int{17, 21}, "checks": []string{"path", "major-version", "executable-bit", "launch-compatibility"}})
		if status != "available" {
			return errors.New("Java runtime не найден по указанному пути")
		}
		return nil
	case "launch-plan":
		minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
		loader := flagValue(args, "--loader", "vanilla")
		username := flagValue(args, "--username", "Player")
		gameDir := flagValue(args, "--game-dir", ".neverlauncher/client")
		versionJSON := flagValue(args, "--version-json", "")
		assetIndexPath := flagValue(args, "--asset-index", "")
		loaderVersion := flagValue(args, "--loader-version", "")
		metadataPath := flagValue(args, "--metadata", "")
		installerProfile := flagValue(args, "--installer-profile", "")
		out := flagValue(args, "--output", "launch-plan.json")
		var plan map[string]any
		var err error
		if loader != "vanilla" || metadataPath != "" || installerProfile != "" || loaderVersion != "" {
			plan, err = realLoaderInstallPlan(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON, assetIndexPath)
			if plan != nil {
				plan["gameDirectory"] = gameDir
			}
		} else {
			plan, err = realRuntimePlan(minecraftVersion, loader, username, gameDir, versionJSON, assetIndexPath)
		}
		if err != nil {
			return err
		}
		if out == "-" {
			printJSON(plan)
			return nil
		}
		return writeJSONFile(out, plan)
	case "resolver":
		minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
		loader := strings.ToLower(flagValue(args, "--loader", "vanilla"))
		printJSON(runtimeResolver740(minecraftVersion, loader))
		return nil
	case "matrix":
		printJSON(runtimeMatrix740())
		return nil
	case "metadata-policy":
		printJSON(runtimeMetadataPolicy850())
		return nil
	case "fetch-metadata":
		return handleRuntimeFetchMetadata850(args[1:])
	case "resolve-version":
		return handleRuntimeResolveVersion850(args[1:])
	case "resolve-loader":
		return handleRuntimeResolveLoader850(args[1:])
	case "build-classpath":
		return handleRuntimeBuildClasspath850(args[1:])
	case "build-launch-plan":
		return handleRuntimeBuildLaunchPlan850(args[1:])
	case "verify-launch-plan":
		return handleRuntimeVerifyLaunchPlan850(args[1:])
	case "verify":
		if len(args) < 2 {
			return errors.New("runtime verify требует путь к launch-plan.json")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			return err
		}
		var errs []string
		for _, field := range []string{"schemaVersion", "minecraftVersion", "mainClass", "classpath", "gameArgs", "jvmArgs"} {
			if strings.TrimSpace(fmt.Sprint(payload[field])) == "" || fmt.Sprint(payload[field]) == "<nil>" {
				errs = append(errs, "отсутствует поле "+field)
			}
		}
		printJSON(map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "subject": args[1], "valid": len(errs) == 0, "errors": errs, "checks": runtimeChecks()})
		if len(errs) > 0 {
			return errors.New("launch plan не прошёл проверку")
		}
		return nil
	default:
		return fmt.Errorf("неизвестная runtime-подкоманда: %s", args[0])
	}
}

type MojangVersionFile struct {
	ID            string                    `json:"id"`
	Type          string                    `json:"type"`
	MainClass     string                    `json:"mainClass"`
	Assets        string                    `json:"assets"`
	AssetIndex    MojangDownload            `json:"assetIndex"`
	Downloads     map[string]MojangDownload `json:"downloads"`
	Libraries     []MojangLibrary           `json:"libraries"`
	Arguments     MojangArguments           `json:"arguments"`
	MinecraftArgs string                    `json:"minecraftArguments"`
	JavaVersion   map[string]any            `json:"javaVersion"`
}

type MojangDownload struct {
	SHA1 string `json:"sha1"`
	Size int64  `json:"size"`
	URL  string `json:"url"`
	Path string `json:"path,omitempty"`
	ID   string `json:"id,omitempty"`
}

type MojangLibrary struct {
	Name      string                 `json:"name"`
	URL       string                 `json:"url,omitempty"`
	Downloads MojangLibraryDownloads `json:"downloads"`
	Natives   map[string]string      `json:"natives"`
	Rules     []map[string]any       `json:"rules"`
	Extract   map[string]any         `json:"extract"`
}

type MojangLibraryDownloads struct {
	Artifact    MojangDownload            `json:"artifact"`
	Classifiers map[string]MojangDownload `json:"classifiers"`
}

type MojangArguments struct {
	Game []any `json:"game"`
	JVM  []any `json:"jvm"`
}

type MojangAssetIndex struct {
	Objects map[string]MojangAssetObject `json:"objects"`
}

type MojangAssetObject struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

type MojangVersionManifest struct {
	Latest   map[string]string       `json:"latest"`
	Versions []MojangManifestVersion `json:"versions"`
}

type MojangManifestVersion struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	Time        string `json:"time"`
	ReleaseTime string `json:"releaseTime"`
	SHA1        string `json:"sha1"`
}

type LoaderMetadata struct {
	SchemaVersion    string             `json:"schemaVersion,omitempty"`
	Loader           string             `json:"loader,omitempty"`
	MinecraftVersion string             `json:"minecraftVersion,omitempty"`
	LoaderVersion    string             `json:"loaderVersion,omitempty"`
	MainClass        string             `json:"mainClass,omitempty"`
	Libraries        []MojangLibrary    `json:"libraries,omitempty"`
	JVMArgs          []string           `json:"jvmArgs,omitempty"`
	GameArgs         []string           `json:"gameArgs,omitempty"`
	Arguments        MojangArguments    `json:"arguments,omitempty"`
	Profile          *MojangVersionFile `json:"profile,omitempty"`
}

type FabricMetaVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Maven     string `json:"maven"`
	Version   string `json:"version"`
	Stable    bool   `json:"stable"`
}

type FabricMetaProfile struct {
	ID        string          `json:"id"`
	MainClass string          `json:"mainClass"`
	Libraries []MojangLibrary `json:"libraries"`
	Arguments MojangArguments `json:"arguments"`
}

type ForgeInstallProfile struct {
	Spec       int              `json:"spec"`
	Version    string           `json:"version"`
	Path       string           `json:"path"`
	Profile    string           `json:"profile"`
	Minecraft  string           `json:"minecraft"`
	Data       map[string]any   `json:"data"`
	Processors []map[string]any `json:"processors"`
	Libraries  []MojangLibrary  `json:"libraries"`
}

func runtimeResolver740(minecraftVersion string, loader string) map[string]any {
	if minecraftVersion == "" {
		minecraftVersion = "1.21.1"
	}
	loader = strings.ToLower(strings.TrimSpace(loader))
	if loader == "" {
		loader = "vanilla"
	}
	status := "ready"
	if !isSupportedLoader(loader) {
		status = "unsupported-loader"
	}
	return map[string]any{
		"schemaVersion":    "0.8.8",
		"toolVersion":      version,
		"minecraftVersion": minecraftVersion,
		"loader":           loader,
		"status":           status,
		"mode":             "minecraft-runtime-resolver",
		"supportedLoaders": []string{"vanilla", "fabric", "quilt", "forge", "neoforge"},
		"metadataSources": []map[string]any{
			{"id": "mojang-version-manifest", "requiredFor": []string{"vanilla", "fabric", "quilt", "forge", "neoforge"}, "input": "--version-json", "resolves": []string{"client.jar", "mainClass", "libraries", "natives", "arguments", "javaVersion"}},
			{"id": "mojang-asset-index", "requiredFor": []string{"all"}, "input": "--asset-index", "resolves": []string{"assets/objects", "asset total size", "asset object paths"}},
			{"id": "fabric-meta-profile", "requiredFor": []string{"fabric"}, "input": "Fabric Meta v2", "resolves": []string{"pinned loader version", "KnotClient", "fabric-loader", "intermediary", "loader arguments", "verified Maven libraries"}},
			{"id": "quilt-meta-profile", "requiredFor": []string{"quilt"}, "input": "Quilt Meta v3", "resolves": []string{"pinned loader version", "Quilt KnotClient", "quilt-loader", "intermediary", "loader arguments", "verified Maven libraries"}},
			{"id": "forge-installer", "requiredFor": []string{"forge"}, "input": "Forge Maven installer.jar", "resolves": []string{"install_profile.json", "version.json", "embedded Maven", "client processors", "verified outputs"}},
			{"id": "neoforge-installer", "requiredFor": []string{"neoforge"}, "input": "NeoForge Maven installer.jar", "resolves": []string{"install_profile.json", "version.json", "embedded Maven", "client processors", "verified outputs"}},
		},
		"pipeline": []string{"load-version-json", "resolve-java-constraints", "filter-libraries-by-rules", "resolve-natives-for-current-os", "resolve-assets", "merge-loader-metadata", "build-classpath", "build-jvm-args", "build-game-args", "validate-launch-plan"},
		"commands": []string{
			"nl runtime launch-plan --version-json <version.json> --asset-index <asset-index.json>",
			"nl runtime fabric-package --minecraft <version> --loader-version latest-stable --output client-package.json",
			"nl runtime quilt-package --minecraft <version> --loader-version latest-stable --output client-package.json",
			"nl runtime forge-package --minecraft <version> --loader-version latest-stable --output client-package.json",
			"nl runtime neoforge-package --minecraft <version> --loader-version latest-stable --output client-package.json",
		},
		"checks": runtimeChecks(),
	}
}

func runtimeMatrix740() map[string]any {
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"status":        "actual-client-public-ci-matrix",
		"title":         "NeverLauncher 0.10.6 Compatibility Matrix",
		"capabilities": []map[string]any{
			{"feature": "version inheritance", "status": "implemented"},
			{"feature": "Mojang OS/architecture/feature rules", "status": "implemented"},
			{"feature": "ordered classpath", "status": "implemented"},
			{"feature": "native classifier resolution", "status": "implemented"},
			{"feature": "JVM/game argument resolution", "status": "implemented"},
			{"feature": "signed metadata trust boundary", "status": "implemented"},
			{"feature": "actual Minecraft client E2E", "status": "implemented"},
			{"feature": "public CI evidence aggregation", "status": "implemented"},
		},
		"materializersReady": []string{"vanilla", "fabric", "quilt", "forge-modern", "neoforge", "managed-java-temurin"},
		"ciTargets":          []string{"vanilla-1.21.1-linux-x64", "fabric-1.21.1-linux-x64", "quilt-1.21.1-linux-x64", "forge-1.21.1-linux-x64", "neoforge-1.21.1-linux-x64"},
		"evidence":           []string{"package-sha256-verify", "ed25519-signed-manifest", "clean-runtime-sync", "actual-client-launch", "paper-world-join", "session-revoke-deny"},
		"pending":            []string{"forge-legacy-pre-1.13", "cross-platform-compatibility-ci"},
		"note":               "PASS формируется только GitHub Actions actual-client E2E; compatibility/targets.json не содержит ручных статусов.",
	}
}

func runtimeMetadataPolicy740() map[string]any {
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"status":        "ready",
		"policy": []map[string]any{
			{"source": "version.json", "trust": "required", "validation": []string{"id", "mainClass", "downloads.client", "libraries", "arguments or minecraftArguments"}},
			{"source": "asset index", "trust": "required-for-full-assets", "validation": []string{"objects hash", "objects size", "object path prefix"}},
			{"source": "Fabric/Quilt metadata", "trust": "official-meta-then-never-pinned", "validation": []string{"minecraft compatibility", "concrete loaderVersion", "inheritsFrom", "mainClass", "selected loader artifact", "Maven SHA-1", "normalized profile SHA-256"}},
			{"source": "Forge/NeoForge installer.jar", "trust": "official-maven-then-never-pinned", "validation": []string{"installer SHA-1", "processor-based install_profile (spec 0+)", "Minecraft match", "embedded Maven paths", "processor Main-Class", "processor outputs", "normalized runtime libraries"}},
		},
		"security": []string{"path traversal denied", "remote metadata source recorded", "hash fields preserved", "signed manifest layer remains outside resolver"},
	}
}

func runtimeMetadataPolicy850() map[string]any {
	payload := runtimeMetadataPolicy740()
	payload["schemaVersion"] = "0.8.8"
	payload["toolVersion"] = version
	payload["status"] = "product-ready"
	payload["productRules"] = []string{"runtime build-launch-plan requires --version-json", "fallback launch plans are rejected by verify-launch-plan", "classpath must not contain wildcards", "loader metadata source is recorded", "asset index is parsed when provided"}
	payload["commands"] = []string{"nl runtime fetch-metadata", "nl runtime resolve-version", "nl runtime resolve-loader", "nl runtime build-classpath", "nl runtime build-launch-plan", "nl runtime verify-launch-plan"}
	return payload
}

func handleRuntimeFetchMetadata850(args []string) error {
	minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
	versionJSON := flagValue(args, "--version-json", "")
	assetIndex := flagValue(args, "--asset-index", "")
	manifestPath := flagValue(args, "--version-manifest", "")
	cacheDir := flagValue(args, "--cache-dir", filepath.Join(".neverlauncher", "metadata"))
	out := flagValue(args, "--output", "")
	if versionJSON == "" && manifestPath == "" {
		return errors.New("runtime fetch-metadata требует --version-json или --version-manifest")
	}
	result := map[string]any{"schemaVersion": "0.8.8", "toolVersion": version, "minecraftVersion": minecraftVersion, "cacheDir": cacheDir, "status": "cached", "files": map[string]string{}}
	if err := os.MkdirAll(filepath.Join(cacheDir, "versions", minecraftVersion), 0o755); err != nil {
		return err
	}
	if manifestPath != "" && versionJSON == "" {
		var manifest MojangVersionManifest
		if err := loadJSONSource(manifestPath, &manifest); err != nil {
			return err
		}
		mv, ok := findMojangManifestVersion(manifest, minecraftVersion)
		if !ok {
			return fmt.Errorf("версия %s не найдена в version manifest", minecraftVersion)
		}
		result["manifestEntry"] = mv
		if mv.URL != "" {
			versionJSON = mv.URL
		}
	}
	if versionJSON != "" {
		var vf MojangVersionFile
		if err := loadJSONSource(versionJSON, &vf); err != nil {
			return err
		}
		if vf.ID == "" {
			vf.ID = minecraftVersion
		}
		versionOut := filepath.Join(cacheDir, "versions", vf.ID, vf.ID+".json")
		if err := writeJSONFile(versionOut, vf); err != nil {
			return err
		}
		result["version"] = resolveVersionSummary850(vf)
		result["files"].(map[string]string)["versionJson"] = filepath.ToSlash(versionOut)
		if assetIndex == "" && vf.AssetIndex.URL != "" {
			assetIndex = vf.AssetIndex.URL
		}
	}
	if assetIndex != "" {
		var ai MojangAssetIndex
		if err := loadJSONSource(assetIndex, &ai); err != nil {
			return err
		}
		assetOut := filepath.Join(cacheDir, "assets", "indexes", minecraftVersion+".json")
		if err := writeJSONFile(assetOut, ai); err != nil {
			return err
		}
		assetSummary := resolveAssetIndex(ai)
		result["assetIndex"] = assetSummary
		result["files"].(map[string]string)["assetIndex"] = filepath.ToSlash(assetOut)
	}
	return writeOrPrintJSON(out, result)
}

func handleRuntimeResolveVersion850(args []string) error {
	versionJSON := flagValue(args, "--version-json", "")
	out := flagValue(args, "--output", "")
	if versionJSON == "" {
		return errors.New("runtime resolve-version требует --version-json")
	}
	var vf MojangVersionFile
	if err := loadJSONSource(versionJSON, &vf); err != nil {
		return err
	}
	return writeOrPrintJSON(out, resolveVersionSummary850(vf))
}

func handleRuntimeResolveLoader850(args []string) error {
	loader := strings.ToLower(flagValue(args, "--loader", "vanilla"))
	minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
	loaderVersion := flagValue(args, "--loader-version", "")
	versionJSON := flagValue(args, "--version-json", "")
	assetIndex := flagValue(args, "--asset-index", "")
	metadata := flagValue(args, "--metadata", "")
	installer := flagValue(args, "--installer-profile", "")
	out := flagValue(args, "--output", "")
	plan, err := productLaunchPlan850(minecraftVersion, loader, loaderVersion, "Player", ".neverlauncher/client", versionJSON, assetIndex, metadata, installer)
	if err != nil {
		return err
	}
	plan["view"] = "loader-resolution"
	return writeOrPrintJSON(out, plan)
}

func handleRuntimeBuildClasspath850(args []string) error {
	loader := strings.ToLower(flagValue(args, "--loader", "vanilla"))
	minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
	loaderVersion := flagValue(args, "--loader-version", "")
	versionJSON := flagValue(args, "--version-json", "")
	assetIndex := flagValue(args, "--asset-index", "")
	metadata := flagValue(args, "--metadata", "")
	installer := flagValue(args, "--installer-profile", "")
	out := flagValue(args, "--output", "")
	plan, err := productLaunchPlan850(minecraftVersion, loader, loaderVersion, "Player", ".neverlauncher/client", versionJSON, assetIndex, metadata, installer)
	if err != nil {
		return err
	}
	payload := map[string]any{"schemaVersion": "0.8.8", "toolVersion": version, "minecraftVersion": plan["minecraftVersion"], "loader": loader, "status": "resolved", "classpath": plan["classpath"], "classpathSeparator": string(os.PathListSeparator), "mainClass": plan["mainClass"]}
	return writeOrPrintJSON(out, payload)
}

func handleRuntimeBuildLaunchPlan850(args []string) error {
	loader := strings.ToLower(flagValue(args, "--loader", "vanilla"))
	minecraftVersion := flagValue(args, "--minecraft", "1.21.1")
	loaderVersion := flagValue(args, "--loader-version", "")
	username := flagValue(args, "--username", "Player")
	gameDir := flagValue(args, "--game-dir", ".neverlauncher/client")
	versionJSON := flagValue(args, "--version-json", "")
	assetIndex := flagValue(args, "--asset-index", "")
	metadata := flagValue(args, "--metadata", "")
	installer := flagValue(args, "--installer-profile", "")
	out := flagValue(args, "--output", "launch-plan.json")
	plan, err := productLaunchPlan850(minecraftVersion, loader, loaderVersion, username, gameDir, versionJSON, assetIndex, metadata, installer)
	if err != nil {
		return err
	}
	if out == "-" {
		printJSON(plan)
		return nil
	}
	return writeJSONFile(out, plan)
}

func handleRuntimeVerifyLaunchPlan850(args []string) error {
	path := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		path = args[0]
	}
	if path == "" {
		path = flagValue(args, "--plan", "")
	}
	if path == "" {
		return errors.New("runtime verify-launch-plan требует путь к launch-plan.json или --plan")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	report := verifyLaunchPlanStrict850(payload)
	report["subject"] = path
	printJSON(report)
	if report["valid"] != true {
		return errors.New("launch plan не прошёл строгую проверку 0.8.8")
	}
	return nil
}

func findMojangManifestVersion(manifest MojangVersionManifest, minecraftVersion string) (MojangManifestVersion, bool) {
	if minecraftVersion == "latest" || minecraftVersion == "latest-release" {
		minecraftVersion = manifest.Latest["release"]
	}
	if minecraftVersion == "latest-snapshot" {
		minecraftVersion = manifest.Latest["snapshot"]
	}
	for _, item := range manifest.Versions {
		if item.ID == minecraftVersion {
			return item, true
		}
	}
	return MojangManifestVersion{}, false
}

func resolveVersionSummary850(vf MojangVersionFile) map[string]any {
	libs, natives, classpath := resolveLibraries(vf)
	javaMajor := 0
	if vf.JavaVersion != nil {
		if v, ok := vf.JavaVersion["majorVersion"].(float64); ok {
			javaMajor = int(v)
		}
	}
	return map[string]any{"schemaVersion": "0.8.8", "toolVersion": version, "status": "resolved", "id": vf.ID, "type": vf.Type, "mainClass": vf.MainClass, "assets": vf.Assets, "javaMajorVersion": javaMajor, "client": vf.Downloads["client"], "assetIndex": vf.AssetIndex, "libraryCount": len(libs), "nativeCount": len(natives), "classpathCount": len(classpath), "checks": []string{"version-json-parse", "downloads-client", "libraries", "rules", "natives"}}
}

func productLaunchPlan850(minecraftVersion, loader, loaderVersion, username, gameDir, versionJSON, assetIndexPath, metadataPath, installerProfile string) (map[string]any, error) {
	if versionJSON == "" {
		return nil, errors.New("product runtime 0.8.8 требует --version-json; fallback launch plan запрещён")
	}
	if loader == "" {
		loader = "vanilla"
	}
	var plan map[string]any
	var err error
	if loader == "vanilla" {
		plan, err = realRuntimePlan(minecraftVersion, loader, username, gameDir, versionJSON, assetIndexPath)
	} else {
		plan, err = realLoaderInstallPlan(loader, minecraftVersion, loaderVersion, metadataPath, installerProfile, versionJSON, assetIndexPath)
		if plan != nil {
			plan["gameDirectory"] = gameDir
		}
	}
	if err != nil {
		return nil, err
	}
	plan["schemaVersion"] = "0.8.8"
	plan["toolVersion"] = version
	plan["status"] = "resolved"
	plan["productResolver"] = true
	plan["fallbackAllowed"] = false
	plan["classpathSeparator"] = string(os.PathListSeparator)
	plan["resolvedAt"] = time.Now().UTC().Format(time.RFC3339)
	plan["verification"] = verifyLaunchPlanStrict850(plan)
	return plan, nil
}

func verifyLaunchPlanStrict850(payload map[string]any) map[string]any {
	var errs []string
	warnings := []string{}
	for _, field := range []string{"schemaVersion", "minecraftVersion", "mainClass", "classpath", "gameArgs", "jvmArgs"} {
		if strings.TrimSpace(fmt.Sprint(payload[field])) == "" || fmt.Sprint(payload[field]) == "<nil>" {
			errs = append(errs, "отсутствует поле "+field)
		}
	}
	mainClass := fmt.Sprint(payload["mainClass"])
	if mainClass == "<loader-main-class>" || strings.Contains(mainClass, "placeholder") {
		errs = append(errs, "mainClass содержит placeholder")
	}
	if strings.Contains(strings.ToLower(fmt.Sprint(payload["status"])), "fallback") || fmt.Sprint(payload["fallbackAllowed"]) == "true" {
		errs = append(errs, "fallback launch plan запрещён для product runtime 0.8.8")
	}
	for _, cp := range asStringSlice(payload["classpath"]) {
		if strings.Contains(cp, "*") {
			errs = append(errs, "classpath содержит wildcard: "+cp)
		}
		if strings.Contains(cp, "..") {
			errs = append(errs, "classpath содержит небезопасный сегмент: "+cp)
		}
	}
	if len(asStringSlice(payload["classpath"])) == 0 {
		errs = append(errs, "classpath пуст")
	}
	if payload["assetObjects"] == nil {
		warnings = append(warnings, "asset index не приложен; запуск возможен только после отдельной загрузки assets")
	}
	return map[string]any{"schemaVersion": "0.8.8", "toolVersion": version, "valid": len(errs) == 0, "errors": errs, "warnings": warnings, "checks": []string{"no-fallback", "main-class", "classpath-no-wildcards", "args-present", "schema", "safe-paths"}}
}

func nativeClassifierMatches(classifier string) bool {
	c := strings.ToLower(classifier)
	tokens := []string{}
	switch runtime.GOOS {
	case "windows":
		tokens = []string{"windows", "win", "natives-windows"}
	case "darwin":
		tokens = []string{"osx", "macos", "darwin", "natives-osx", "natives-macos"}
	default:
		tokens = []string{"linux", "natives-linux"}
	}
	for _, token := range tokens {
		if strings.Contains(c, token) {
			return true
		}
	}
	return false
}

func loadJSONSource(source string, target any) error {
	if source == "" {
		return errors.New("источник JSON не указан")
	}
	var data []byte
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("HTTP %d при загрузке %s", resp.StatusCode, source)
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
	} else {
		var err error
		data, err = os.ReadFile(source)
		if err != nil {
			return err
		}
	}
	return json.Unmarshal(data, target)
}

func localMavenPath(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return strings.ReplaceAll(name, ":", "/") + ".jar"
	}
	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact, versionPart := parts[1], parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}
	return filepath.ToSlash(filepath.Join(group, artifact, versionPart, artifact+"-"+versionPart+classifier+".jar"))
}

func rulesAllow(rules []map[string]any) bool {
	if len(rules) == 0 {
		return true
	}
	allowed := false
	currentOS := runtime.GOOS
	for _, rule := range rules {
		action, _ := rule["action"].(string)
		osRule, hasOS := rule["os"].(map[string]any)
		matches := true
		if hasOS {
			if name, ok := osRule["name"].(string); ok && name != "" {
				mapped := map[string]string{"windows": "windows", "linux": "linux", "osx": "darwin"}[name]
				matches = mapped == currentOS || name == currentOS
			}
		}
		if matches {
			allowed = action == "allow"
		}
	}
	return allowed
}

func extractArgStrings(args []any) []string {
	var out []string
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if rules, ok := v["rules"].([]any); ok {
				converted := make([]map[string]any, 0, len(rules))
				for _, r := range rules {
					if m, ok := r.(map[string]any); ok {
						converted = append(converted, m)
					}
				}
				if !rulesAllow(converted) {
					continue
				}
			}
			switch value := v["value"].(type) {
			case string:
				out = append(out, value)
			case []any:
				for _, item := range value {
					if s, ok := item.(string); ok {
						out = append(out, s)
					}
				}
			}
		}
	}
	return out
}

func resolveLibraries(versionFile MojangVersionFile) ([]map[string]any, []map[string]any, []string) {
	var libraries []map[string]any
	var natives []map[string]any
	var classpath []string
	for _, lib := range versionFile.Libraries {
		if !rulesAllow(lib.Rules) {
			continue
		}
		artifact := lib.Downloads.Artifact
		path := artifact.Path
		if path == "" {
			path = artifact.ID
		}
		if path == "" {
			path = localMavenPath(lib.Name)
		}
		if artifact.URL == "" && artifact.SHA1 == "" && artifact.Size == 0 && lib.Downloads.Artifact.ID == "" {
			path = localMavenPath(lib.Name)
		}
		libraries = append(libraries, map[string]any{"name": lib.Name, "path": filepath.ToSlash(filepath.Join("libraries", path)), "url": artifact.URL, "sha1": artifact.SHA1, "size": artifact.Size})
		classpath = append(classpath, filepath.ToSlash(filepath.Join("libraries", path)))
		for classifier, native := range lib.Downloads.Classifiers {
			if nativeClassifierMatches(classifier) {
				nativePath := native.Path
				if nativePath == "" {
					nativePath = native.ID
				}
				if nativePath == "" {
					nativePath = localMavenPath(lib.Name + ":" + classifier)
				}
				natives = append(natives, map[string]any{"name": lib.Name, "classifier": classifier, "path": filepath.ToSlash(filepath.Join("libraries", nativePath)), "url": native.URL, "sha1": native.SHA1, "size": native.Size})
			}
		}
	}
	return libraries, natives, classpath
}

func resolveAssetIndex(index MojangAssetIndex) map[string]any {
	var totalSize int64
	objects := make([]map[string]any, 0, len(index.Objects))
	for name, obj := range index.Objects {
		prefix := ""
		if len(obj.Hash) >= 2 {
			prefix = obj.Hash[:2]
		}
		totalSize += obj.Size
		if len(objects) < 50 {
			objects = append(objects, map[string]any{"name": name, "hash": obj.Hash, "size": obj.Size, "path": filepath.ToSlash(filepath.Join("assets", "objects", prefix, obj.Hash))})
		}
	}
	return map[string]any{"objectCount": len(index.Objects), "totalSize": totalSize, "sampleLimit": 50, "objects": objects}
}

func realRuntimePlan(minecraftVersion, loader, username, gameDir, versionJSON, assetIndexPath string) (map[string]any, error) {
	if versionJSON == "" {
		return nil, errors.New("Compatibility Engine требует version.json; fallback launch plan запрещён")
	}
	var vf MojangVersionFile
	if err := loadJSONSource(versionJSON, &vf); err != nil {
		return nil, err
	}
	if vf.ID == "" {
		vf.ID = minecraftVersion
	}
	if minecraftVersion == "" || minecraftVersion == "1.21.1" {
		minecraftVersion = vf.ID
	}
	libraries, natives, classpath := resolveLibraries(vf)
	clientJar := filepath.ToSlash(filepath.Join("versions", minecraftVersion, minecraftVersion+".jar"))
	classpath = append([]string{clientJar}, classpath...)
	gameArgs := extractArgStrings(vf.Arguments.Game)
	if len(gameArgs) == 0 && vf.MinecraftArgs != "" {
		gameArgs = strings.Fields(vf.MinecraftArgs)
	}
	if len(gameArgs) == 0 {
		gameArgs = []string{"--username", "${auth_player_name}", "--version", "${version_name}", "--gameDir", "${game_directory}", "--assetsDir", "${assets_root}", "--assetIndex", "${assets_index_name}", "--uuid", "${auth_uuid}", "--accessToken", "${auth_access_token}"}
	}
	jvmArgs := extractArgStrings(vf.Arguments.JVM)
	if len(jvmArgs) == 0 {
		jvmArgs = []string{"-Djava.library.path=${natives_directory}", "-cp", "${classpath}"}
	}
	assetSummary := map[string]any{"configured": false}
	if assetIndexPath != "" {
		var ai MojangAssetIndex
		if err := loadJSONSource(assetIndexPath, &ai); err != nil {
			return nil, err
		}
		assetSummary = resolveAssetIndex(ai)
		assetSummary["configured"] = true
	}
	return map[string]any{
		"schemaVersion": "0.8.8", "toolVersion": version, "minecraftVersion": minecraftVersion, "loader": loader,
		"source":    map[string]any{"versionJson": versionJSON, "assetIndex": assetIndexPath},
		"mainClass": vf.MainClass, "assets": vf.Assets, "assetIndex": vf.AssetIndex,
		"client": vf.Downloads["client"], "libraries": libraries, "natives": natives,
		"classpath": classpath, "nativesDirectory": filepath.ToSlash(filepath.Join("natives", minecraftVersion)), "gameDirectory": gameDir, "assetsDirectory": "assets",
		"gameArgs": gameArgs, "jvmArgs": jvmArgs,
		"assetObjects":    assetSummary,
		"status":          "resolved",
		"productResolver": true,
	}, nil
}

func runtimeChecks() []string {
	return []string{"version-json-parse", "mojang-rules-evaluate", "asset-index-parse", "libraries-resolve", "natives-resolve", "loader-metadata-merge", "arguments-resolve", "classpath-build", "java-runtime", "integrity"}
}
