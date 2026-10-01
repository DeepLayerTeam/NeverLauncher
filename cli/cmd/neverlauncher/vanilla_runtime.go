package main

import (
	"archive/zip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMojangVersionManifest = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
	defaultMojangAssetBase       = "https://resources.download.minecraft.net"
	defaultMojangLibraryBase     = "https://libraries.minecraft.net"
)

// 0.17.0v1 expands the actual-client Legacy Vanilla grid rather than treating
// the old line as a handful of representative anchors. These IDs are consumed
// by the materializer/runtime/release gates, so removing one silently is not a
// supported configuration.
var legacyVanilla0170v1Releases = []string{
	"1.2.1", "1.2.2", "1.2.3", "1.2.4",
	"1.3.1",
	"1.4.2", "1.4.4", "1.4.5", "1.4.6",
	"1.5", "1.5.1",
	"1.6.1", "1.6.2",
	"1.7.2", "1.7.3", "1.7.4", "1.7.5", "1.7.6", "1.7.7", "1.7.8", "1.7.9",
	"1.8", "1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7", "1.8.8",
	"1.9", "1.9.1", "1.9.2", "1.9.3",
	"1.10", "1.10.1",
	"1.11", "1.11.1",
	"1.12", "1.12.1",
	"1.13", "1.13.1",
	"1.14", "1.14.1", "1.14.2", "1.14.3",
	"1.15", "1.15.1",
	"1.16", "1.16.1", "1.16.2", "1.16.3", "1.16.4",
}

var legacyVanilla0170v1ReleaseSet = func() map[string]struct{} {
	out := make(map[string]struct{}, len(legacyVanilla0170v1Releases))
	for _, release := range legacyVanilla0170v1Releases {
		out[release] = struct{}{}
	}
	return out
}()

// 0.17.0v2 completes the Java-transition Vanilla grid with every requested
// release that was not already certified by 0.16.6. The map is also a runtime
// policy: materialization/server installation rejects missing or conflicting
// Mojang javaVersion metadata before any client/server artifact is downloaded.
var java16_17Vanilla0170v2Releases = map[string]int{
	"1.17":   16,
	"1.18":   17,
	"1.18.1": 17,
	"1.19":   17,
	"1.19.1": 17,
	"1.19.2": 17,
	"1.19.3": 17,
	"1.20":   17,
	"1.20.3": 17,
}

// 0.17.0v3 closes the two release gaps in the modern Vanilla line. These
// releases use the same production Mojang materializer/server installer as the
// rest of the matrix, but are pinned here so missing/tampered javaVersion
// metadata fails before game artifacts are downloaded.
var java21_25Vanilla0170v3Releases = map[string]int{
	"1.21.11": 21,
	"26.2":    25,
}

type vanillaTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type vanillaInstallOptions struct {
	MinecraftVersion string
	ClientDir        string
	VersionManifest  string
	AssetBaseURL     string
	LibraryBaseURL   string
	Targets          []vanillaTarget
	Workers          int
	StrictUpstream   bool
	HTTPClient       *http.Client
}

type vanillaDownloadTask struct {
	Path          string
	URL           string
	SHA1          string
	Size          int64
	Kind          string
	TargetOS      []string
	NativeExclude []string
	NativeTarget  *vanillaTarget
}

type vanillaDownloadedFile struct {
	Path        string   `json:"path"`
	Kind        string   `json:"kind"`
	Size        int64    `json:"size"`
	SHA1        string   `json:"sha1,omitempty"`
	SHA256      string   `json:"sha256"`
	TargetOS    []string `json:"targetOs,omitempty"`
	Cached      bool     `json:"cached"`
	Resumed     bool     `json:"resumed,omitempty"`
	Quarantined bool     `json:"quarantinedPrevious,omitempty"`
}

type vanillaInstallResult struct {
	SchemaVersion     string                  `json:"schemaVersion"`
	ToolVersion       string                  `json:"toolVersion"`
	MinecraftVersion  string                  `json:"minecraftVersion"`
	ReleaseType       string                  `json:"releaseType"`
	ClientDir         string                  `json:"clientDir"`
	JavaMajorVersion  int                     `json:"javaMajorVersion"`
	MainClass         string                  `json:"mainClass"`
	AssetIndex        string                  `json:"assetIndex"`
	Targets           []vanillaTarget         `json:"targets"`
	Downloaded        int                     `json:"downloaded"`
	Cached            int                     `json:"cached"`
	TotalBytes        int64                   `json:"totalBytes"`
	Files             []vanillaDownloadedFile `json:"files"`
	MetadataPath      string                  `json:"metadataPath"`
	MetadataSource    string                  `json:"metadataSource"`
	UpstreamRecovered bool                    `json:"upstreamRecovered"`
	Status            string                  `json:"status"`
}

type vanillaServerInstallResult struct {
	SchemaVersion     string `json:"schemaVersion"`
	ToolVersion       string `json:"toolVersion"`
	MinecraftVersion  string `json:"minecraftVersion"`
	ReleaseType       string `json:"releaseType"`
	JavaMajorVersion  int    `json:"javaMajorVersion"`
	ServerDir         string `json:"serverDir"`
	ServerJar         string `json:"serverJar"`
	MetadataPath      string `json:"metadataPath"`
	Size              int64  `json:"size"`
	SHA1              string `json:"sha1"`
	SHA256            string `json:"sha256"`
	Cached            bool   `json:"cached"`
	MetadataSource    string `json:"metadataSource"`
	UpstreamRecovered bool   `json:"upstreamRecovered"`
	Status            string `json:"status"`
}

type mojangLogging struct {
	Client *mojangLoggingClient `json:"client"`
}

type mojangLoggingClient struct {
	Argument string         `json:"argument"`
	File     MojangDownload `json:"file"`
}

type vanillaVersionMetadata struct {
	MojangVersionFile
	Logging mojangLogging `json:"logging"`
}

type vanillaAssetIndex struct {
	MojangAssetIndex
	Virtual        bool `json:"virtual"`
	MapToResources bool `json:"map_to_resources"`
}

type vanillaTaskResult struct {
	File vanillaDownloadedFile
	Err  error
}

func handleRuntimeVanillaInstall(args []string) error {
	minecraftVersion := flagValue(args, "--minecraft", "latest-release")
	clientDir := flagValue(args, "--client-dir", filepath.Join(".neverlauncher", "vanilla", minecraftVersion))
	lock, err := acquireCompatibilityMaterializationLock(clientDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	workers, err := strconv.Atoi(flagValue(args, "--workers", "12"))
	if err != nil || workers < 1 || workers > 64 {
		return errors.New("--workers должен быть числом от 1 до 64")
	}
	targets, err := parseVanillaTargets(flagValue(args, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
	if err != nil {
		return err
	}
	strict := !strings.EqualFold(flagValue(args, "--strict-upstream", "true"), "false")
	result, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: minecraftVersion,
		ClientDir:        clientDir,
		VersionManifest:  flagValue(args, "--version-manifest", defaultMojangVersionManifest),
		AssetBaseURL:     flagValue(args, "--asset-base-url", defaultMojangAssetBase),
		LibraryBaseURL:   flagValue(args, "--library-base-url", defaultMojangLibraryBase),
		Targets:          targets,
		Workers:          workers,
		StrictUpstream:   strict,
	})
	if err != nil {
		return err
	}
	out := flagValue(args, "--output", "")
	return writeOrPrintJSON(out, result)
}

func handleRuntimeVanillaPackage(args []string) error {
	minecraftVersion := flagValue(args, "--minecraft", "latest-release")
	clientDir := flagValue(args, "--client-dir", filepath.Join(".neverlauncher", "vanilla", minecraftVersion))
	lock, err := acquireCompatibilityMaterializationLock(clientDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	targets, err := parseVanillaTargets(flagValue(args, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
	if err != nil {
		return err
	}
	workers, err := strconv.Atoi(flagValue(args, "--workers", "12"))
	if err != nil || workers < 1 || workers > 64 {
		return errors.New("--workers должен быть числом от 1 до 64")
	}
	result, err := installVanilla(context.Background(), vanillaInstallOptions{
		MinecraftVersion: minecraftVersion,
		ClientDir:        clientDir,
		VersionManifest:  flagValue(args, "--version-manifest", defaultMojangVersionManifest),
		AssetBaseURL:     flagValue(args, "--asset-base-url", defaultMojangAssetBase),
		LibraryBaseURL:   flagValue(args, "--library-base-url", defaultMojangLibraryBase),
		Targets:          targets,
		Workers:          workers,
		StrictUpstream:   !strings.EqualFold(flagValue(args, "--strict-upstream", "true"), "false"),
	})
	if err != nil {
		return err
	}
	releaseVersion := flagValue(args, "--version", result.MinecraftVersion)
	pkg, err := buildClientPackage(clientDir, flagValue(args, "--project", "demo-project"), flagValue(args, "--profile", "vanilla"), flagValue(args, "--channel", "stable"), releaseVersion, flagValue(args, "--base-url", ""))
	if err != nil {
		return err
	}
	pkg["status"] = "materialized-and-packaged"
	pkg["vanilla"] = result
	pkg["manifestSettings"] = map[string]any{
		"minecraft": map[string]any{"version": result.MinecraftVersion, "loader": "vanilla"},
		"runtime": map[string]any{
			"java":   map[string]any{"majorVersion": result.JavaMajorVersion, "distribution": "temurin", "allowCustomPath": true},
			"launch": map[string]any{"classpathStrategy": "compatibility", "versionMetadataPath": result.MetadataPath, "nativesDirectory": "natives", "offlineMode": true},
		},
		"directories": map[string]any{"game": ".", "assets": "assets", "libraries": "libraries", "natives": "natives"},
	}
	out := flagValue(args, "--output", "client-package.json")
	return writeOrPrintJSON(out, pkg)
}

func handleRuntimeVanillaServer(args []string) error {
	minecraftVersion := flagValue(args, "--minecraft", "latest-release")
	serverDir := flagValue(args, "--server-dir", filepath.Join(".neverlauncher", "vanilla-server", minecraftVersion))
	lock, err := acquireCompatibilityMaterializationLock(serverDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	result, err := installVanillaServer(context.Background(), minecraftVersion, serverDir, flagValue(args, "--version-manifest", defaultMojangVersionManifest), nil)
	if err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), result)
}

func installVanillaServer(ctx context.Context, requestedVersion, serverDir, versionManifest string, client *http.Client) (vanillaServerInstallResult, error) {
	if strings.TrimSpace(serverDir) == "" {
		return vanillaServerInstallResult{}, errors.New("Vanilla server install требует serverDir")
	}
	if strings.TrimSpace(versionManifest) == "" {
		versionManifest = defaultMojangVersionManifest
	}
	if client == nil {
		client = secureHTTPClient()
	}
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		return vanillaServerInstallResult{}, fmt.Errorf("не удалось создать serverDir: %w", err)
	}

	resolved, err := resolveVanillaMetadataWithRecovery(ctx, client, serverDir, versionManifest, requestedVersion)
	if err != nil {
		return vanillaServerInstallResult{}, err
	}
	selected := resolved.Selected
	selectedID := selected.ID
	versionBytes := resolved.Bytes
	var metadata vanillaVersionMetadata
	if err := json.Unmarshal(versionBytes, &metadata); err != nil {
		return vanillaServerInstallResult{}, fmt.Errorf("version.json %s повреждён: %w", selectedID, err)
	}
	if metadata.ID == "" {
		metadata.ID = selectedID
	}
	if metadata.ID != selectedID {
		return vanillaServerInstallResult{}, fmt.Errorf("version.json id mismatch: ожидался %s, получен %s", selectedID, metadata.ID)
	}
	javaMajor, err := javaMajorFromVersion(selectedID, metadata.MojangVersionFile)
	if err != nil {
		return vanillaServerInstallResult{}, err
	}
	serverDownload, ok := metadata.Downloads["server"]
	if !ok || strings.TrimSpace(serverDownload.URL) == "" || strings.TrimSpace(serverDownload.SHA1) == "" || serverDownload.Size <= 0 {
		return vanillaServerInstallResult{}, fmt.Errorf("Minecraft %s version.json не содержит проверяемый downloads.server", selectedID)
	}

	metadataPath, err := secureClientDestination(serverDir, "version.json")
	if err != nil {
		return vanillaServerInstallResult{}, err
	}
	if err := writeAtomicBytes(metadataPath, versionBytes, 0o644); err != nil {
		return vanillaServerInstallResult{}, err
	}
	serverPath, err := secureClientDestination(serverDir, "server.jar")
	if err != nil {
		return vanillaServerInstallResult{}, err
	}
	serverBytes, cached, _, err := fetchVerifiedBytesWithLocalCache(ctx, client, serverDir, "server.jar", serverDownload.URL, serverDownload.SHA1, serverDownload.Size, 512<<20)
	if err != nil {
		return vanillaServerInstallResult{}, fmt.Errorf("server.jar %s: %w", selectedID, err)
	}
	h256 := sha256.Sum256(serverBytes)
	return vanillaServerInstallResult{
		SchemaVersion: "1.0", ToolVersion: version, MinecraftVersion: selectedID, ReleaseType: selected.Type,
		JavaMajorVersion: javaMajor, ServerDir: filepath.Clean(serverDir), ServerJar: filepath.ToSlash(serverPath),
		MetadataPath: filepath.ToSlash(metadataPath), Size: int64(len(serverBytes)), SHA1: strings.ToLower(serverDownload.SHA1),
		SHA256: hex.EncodeToString(h256[:]), Cached: cached, MetadataSource: map[bool]string{true: "verified-cache", false: "upstream"}[resolved.Recovered], UpstreamRecovered: resolved.Recovered, Status: "installed-and-verified",
	}, nil
}

func installVanilla(ctx context.Context, opts vanillaInstallOptions) (vanillaInstallResult, error) {
	if strings.TrimSpace(opts.ClientDir) == "" {
		return vanillaInstallResult{}, errors.New("Vanilla install требует clientDir")
	}
	if opts.VersionManifest == "" {
		opts.VersionManifest = defaultMojangVersionManifest
	}
	if opts.AssetBaseURL == "" {
		opts.AssetBaseURL = defaultMojangAssetBase
	}
	if opts.LibraryBaseURL == "" {
		opts.LibraryBaseURL = defaultMojangLibraryBase
	}
	if len(opts.Targets) == 0 {
		opts.Targets = []vanillaTarget{currentVanillaTarget()}
	}
	if opts.Workers <= 0 {
		opts.Workers = 12
	}
	client := opts.HTTPClient
	if client == nil {
		client = secureHTTPClient()
	}
	if err := os.MkdirAll(opts.ClientDir, 0o755); err != nil {
		return vanillaInstallResult{}, fmt.Errorf("не удалось создать clientDir: %w", err)
	}

	resolved, err := resolveVanillaMetadataWithRecovery(ctx, client, opts.ClientDir, opts.VersionManifest, opts.MinecraftVersion)
	if err != nil {
		return vanillaInstallResult{}, err
	}
	selected := resolved.Selected
	selectedID := selected.ID
	versionBytes := resolved.Bytes
	var metadata vanillaVersionMetadata
	if err := json.Unmarshal(versionBytes, &metadata); err != nil {
		return vanillaInstallResult{}, fmt.Errorf("version.json %s повреждён: %w", selectedID, err)
	}
	if metadata.ID == "" {
		metadata.ID = selectedID
	}
	if metadata.ID != selectedID {
		return vanillaInstallResult{}, fmt.Errorf("version.json id mismatch: ожидался %s, получен %s", selectedID, metadata.ID)
	}
	if metadata.MainClass == "" {
		return vanillaInstallResult{}, errors.New("version.json не содержит mainClass")
	}
	javaMajor, err := javaMajorFromVersion(selectedID, metadata.MojangVersionFile)
	if err != nil {
		return vanillaInstallResult{}, err
	}
	if err := validateVanillaLaunchMetadata(metadata); err != nil {
		return vanillaInstallResult{}, err
	}
	clientDownload, ok := metadata.Downloads["client"]
	if !ok || clientDownload.URL == "" || clientDownload.SHA1 == "" || clientDownload.Size <= 0 {
		return vanillaInstallResult{}, errors.New("version.json не содержит проверяемый downloads.client")
	}

	versionRel := filepath.ToSlash(filepath.Join("versions", selectedID, selectedID+".json"))
	versionPath, err := secureClientDestination(opts.ClientDir, versionRel)
	if err != nil {
		return vanillaInstallResult{}, err
	}
	if err := writeAtomicBytes(versionPath, versionBytes, 0o644); err != nil {
		return vanillaInstallResult{}, err
	}

	tasks := map[string]vanillaDownloadTask{}
	addTask := func(task vanillaDownloadTask) error {
		task.Path = filepath.ToSlash(filepath.Clean(filepath.FromSlash(task.Path)))
		if err := validateVanillaRelativePath(task.Path); err != nil {
			return err
		}
		if task.URL == "" {
			return fmt.Errorf("%s: отсутствует URL", task.Path)
		}
		if opts.StrictUpstream && task.SHA1 == "" {
			return fmt.Errorf("%s: upstream metadata не содержит SHA-1; отключение strict возможно только явно", task.Path)
		}
		if prev, exists := tasks[task.Path]; exists {
			if prev.URL != task.URL || (!strings.EqualFold(prev.SHA1, task.SHA1) && prev.SHA1 != "" && task.SHA1 != "") || (prev.Size > 0 && task.Size > 0 && prev.Size != task.Size) {
				return fmt.Errorf("конфликт upstream artifact %s", task.Path)
			}
			prev.TargetOS = unionStrings(prev.TargetOS, task.TargetOS)
			tasks[task.Path] = prev
			return nil
		}
		tasks[task.Path] = task
		return nil
	}

	if err := addTask(vanillaDownloadTask{Path: filepath.ToSlash(filepath.Join("versions", selectedID, selectedID+".jar")), URL: clientDownload.URL, SHA1: clientDownload.SHA1, Size: clientDownload.Size, Kind: "client"}); err != nil {
		return vanillaInstallResult{}, err
	}

	targetSet := map[string]vanillaTarget{}
	for _, target := range opts.Targets {
		normalized, err := normalizeVanillaTarget(target)
		if err != nil {
			return vanillaInstallResult{}, err
		}
		targetSet[normalized.OS+"/"+normalized.Arch] = normalized
	}
	opts.Targets = opts.Targets[:0]
	for _, target := range targetSet {
		opts.Targets = append(opts.Targets, target)
	}
	sort.Slice(opts.Targets, func(i, j int) bool {
		return opts.Targets[i].OS+opts.Targets[i].Arch < opts.Targets[j].OS+opts.Targets[j].Arch
	})

	for _, lib := range metadata.Libraries {
		applicableTargets := make([]string, 0, len(opts.Targets))
		for _, target := range opts.Targets {
			if rulesAllowTarget(lib.Rules, target) && libraryArtifactAppliesToTarget(lib.Name, target) {
				applicableTargets = append(applicableTargets, target.OS)
			}
		}
		if len(applicableTargets) == 0 {
			continue
		}
		artifact := lib.Downloads.Artifact
		hasArtifact := hasMojangDownloadDescriptor(artifact)
		// Mojang legacy metadata contains classifier-only entries such as
		// lwjgl-platform/jinput-platform. They are native containers, not
		// classpath JARs. Synthesizing an artifact from the Maven coordinate
		// creates a file that does not exist upstream and breaks 1.7.x/1.8.x.
		if !hasArtifact && len(lib.Downloads.Classifiers) == 0 {
			if opts.StrictUpstream {
				return vanillaInstallResult{}, fmt.Errorf("library %s: Mojang metadata не содержит проверяемый artifact", lib.Name)
			}
			artifact.Path = strings.TrimPrefix(localMavenPath(lib.Name), "/")
			hasArtifact = true
		}
		if hasArtifact {
			artifactPath := strings.TrimSpace(artifact.Path)
			if artifactPath == "" && strings.TrimSpace(lib.Name) != "" {
				artifactPath = strings.TrimPrefix(localMavenPath(lib.Name), "/")
			}
			artifactURL := strings.TrimSpace(artifact.URL)
			if artifactURL == "" {
				base := strings.TrimSpace(lib.URL)
				if base == "" {
					base = opts.LibraryBaseURL
				}
				artifactURL = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(artifactPath, "/")
			}
			if err := addTask(vanillaDownloadTask{Path: "libraries/" + strings.TrimPrefix(filepath.ToSlash(artifactPath), "libraries/"), URL: artifactURL, SHA1: artifact.SHA1, Size: artifact.Size, Kind: "library", TargetOS: uniqueStrings(applicableTargets)}); err != nil {
				return vanillaInstallResult{}, fmt.Errorf("library %s: %w", lib.Name, err)
			}
		}
		for _, target := range opts.Targets {
			if !rulesAllowTarget(lib.Rules, target) || !libraryArtifactAppliesToTarget(lib.Name, target) {
				continue
			}
			classifierTemplate := nativeClassifierForTarget(lib.Natives, target.OS)
			if classifierTemplate == "" {
				continue
			}
			classifier := strings.ReplaceAll(classifierTemplate, "${arch}", nativeArchForTarget(target.Arch))
			native, ok := lib.Downloads.Classifiers[classifier]
			if !ok {
				return vanillaInstallResult{}, fmt.Errorf("library %s: отсутствует classifier %s", lib.Name, classifier)
			}
			nativePath := strings.TrimSpace(native.Path)
			if nativePath == "" {
				nativePath = strings.TrimPrefix(localMavenPath(lib.Name+":"+classifier), "/")
			}
			nativeURL := strings.TrimSpace(native.URL)
			if nativeURL == "" {
				base := strings.TrimSpace(lib.URL)
				if base == "" {
					base = opts.LibraryBaseURL
				}
				nativeURL = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(nativePath, "/")
			}
			t := target
			if err := addTask(vanillaDownloadTask{Path: "libraries/" + strings.TrimPrefix(filepath.ToSlash(nativePath), "libraries/"), URL: nativeURL, SHA1: native.SHA1, Size: native.Size, Kind: "native-archive", TargetOS: []string{target.OS}, NativeExclude: extractExcludes(lib.Extract), NativeTarget: &t}); err != nil {
				return vanillaInstallResult{}, fmt.Errorf("native %s: %w", lib.Name, err)
			}
		}
	}

	assetIndexID := strings.TrimSpace(metadata.AssetIndex.ID)
	if assetIndexID == "" {
		assetIndexID = strings.TrimSpace(metadata.Assets)
	}
	if assetIndexID == "" || metadata.AssetIndex.URL == "" || metadata.AssetIndex.SHA1 == "" {
		return vanillaInstallResult{}, errors.New("version.json не содержит проверяемый assetIndex")
	}
	assetIndexPath := filepath.ToSlash(filepath.Join("assets", "indexes", assetIndexID+".json"))
	assetBytes, assetIndexCached, assetIndexQuarantined, err := fetchVerifiedBytesWithLocalCache(ctx, client, opts.ClientDir, assetIndexPath, metadata.AssetIndex.URL, metadata.AssetIndex.SHA1, metadata.AssetIndex.Size, 64<<20)
	if err != nil {
		return vanillaInstallResult{}, fmt.Errorf("asset index: %w", err)
	}
	var assets vanillaAssetIndex
	if err := json.Unmarshal(assetBytes, &assets); err != nil {
		return vanillaInstallResult{}, fmt.Errorf("asset index повреждён: %w", err)
	}
	for name, object := range assets.Objects {
		if err := validateAssetLogicalPath(name); err != nil {
			return vanillaInstallResult{}, err
		}
		if err := validateSHA1Hex(object.Hash); err != nil || object.Size < 0 {
			return vanillaInstallResult{}, fmt.Errorf("asset %q содержит некорректный hash/size", name)
		}
		objectURL := strings.TrimRight(opts.AssetBaseURL, "/") + "/" + object.Hash[:2] + "/" + object.Hash
		objectPath := filepath.ToSlash(filepath.Join("assets", "objects", object.Hash[:2], object.Hash))
		if err := addTask(vanillaDownloadTask{Path: objectPath, URL: objectURL, SHA1: object.Hash, Size: object.Size, Kind: "asset"}); err != nil {
			return vanillaInstallResult{}, err
		}
	}

	if metadata.Logging.Client != nil && metadata.Logging.Client.File.ID != "" {
		logging := metadata.Logging.Client.File
		if logging.URL == "" || logging.SHA1 == "" {
			return vanillaInstallResult{}, errors.New("logging.client.file не содержит проверяемый URL/SHA1")
		}
		if err := addTask(vanillaDownloadTask{Path: filepath.ToSlash(filepath.Join("assets", "log_configs", logging.ID)), URL: logging.URL, SHA1: logging.SHA1, Size: logging.Size, Kind: "logging"}); err != nil {
			return vanillaInstallResult{}, err
		}
	}

	taskList := make([]vanillaDownloadTask, 0, len(tasks))
	for _, task := range tasks {
		taskList = append(taskList, task)
	}
	sort.Slice(taskList, func(i, j int) bool { return taskList[i].Path < taskList[j].Path })
	downloadedFiles, err := runVanillaDownloads(ctx, client, opts.ClientDir, taskList, opts.Workers)
	if err != nil {
		return vanillaInstallResult{}, err
	}

	// Metadata files are local trust inputs too; include their final SHA-256 in the report.
	metadataHash := sha256.Sum256(versionBytes)
	downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: filepath.ToSlash(filepath.Join("versions", selectedID, selectedID+".json")), Kind: "version-metadata", Size: int64(len(versionBytes)), SHA1: selected.SHA1, SHA256: hex.EncodeToString(metadataHash[:]), Cached: resolved.Recovered, Resumed: resolved.Recovered})
	assetHash := sha256.Sum256(assetBytes)
	downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: assetIndexPath, Kind: "asset-index", Size: int64(len(assetBytes)), SHA1: metadata.AssetIndex.SHA1, SHA256: hex.EncodeToString(assetHash[:]), Cached: assetIndexCached, Quarantined: assetIndexQuarantined})

	nativeTasks := make([]vanillaDownloadTask, 0)
	for _, task := range taskList {
		if task.Kind == "native-archive" && task.NativeTarget != nil {
			nativeTasks = append(nativeTasks, task)
		}
	}
	nativeByTarget := map[string][]vanillaDownloadTask{}
	for _, task := range nativeTasks {
		key := task.NativeTarget.OS + "/" + task.NativeTarget.Arch
		nativeByTarget[key] = append(nativeByTarget[key], task)
	}
	// Generated natives are published transactionally per OS/arch. A failed
	// extraction therefore leaves the previously verified directory intact
	// instead of exposing a half-written native tree to the next launch.
	for _, target := range opts.Targets {
		key := target.OS + "/" + target.Arch
		finalRel := filepath.ToSlash(filepath.Join("natives", target.OS, target.Arch))
		finalDir, err := secureClientDestination(opts.ClientDir, finalRel)
		if err != nil {
			return vanillaInstallResult{}, err
		}
		stagingRel := filepath.ToSlash(filepath.Join("natives", fmt.Sprintf(".staging-%s-%s-%d-%d", target.OS, target.Arch, os.Getpid(), time.Now().UnixNano())))
		stagingDir, err := secureClientDestination(opts.ClientDir, stagingRel)
		if err != nil {
			return vanillaInstallResult{}, err
		}
		if err := os.MkdirAll(stagingDir, 0o755); err != nil {
			return vanillaInstallResult{}, fmt.Errorf("native staging %s: %w", key, err)
		}
		publishFiles := make([]vanillaDownloadedFile, 0)
		failed := false
		for _, task := range nativeByTarget[key] {
			archivePath := filepath.Join(opts.ClientDir, filepath.FromSlash(task.Path))
			extracted, err := extractNativeJar(archivePath, stagingDir, task.NativeExclude)
			if err != nil {
				_ = os.RemoveAll(stagingDir)
				return vanillaInstallResult{}, fmt.Errorf("native extraction %s: %w", task.Path, err)
			}
			for _, rel := range extracted {
				full := filepath.Join(stagingDir, filepath.FromSlash(rel))
				sum, size, err := hashFile(full)
				if err != nil {
					failed = true
					break
				}
				publishFiles = append(publishFiles, vanillaDownloadedFile{Path: filepath.ToSlash(filepath.Join("natives", target.OS, target.Arch, rel)), Kind: "native", Size: size, SHA256: sum, TargetOS: []string{target.OS}, Cached: false})
			}
			if failed {
				break
			}
		}
		if failed {
			_ = os.RemoveAll(stagingDir)
			return vanillaInstallResult{}, fmt.Errorf("native staging %s hash verification failed", key)
		}
		if err := os.MkdirAll(filepath.Dir(finalDir), 0o755); err != nil {
			_ = os.RemoveAll(stagingDir)
			return vanillaInstallResult{}, err
		}
		if err := replaceDirectoryAtomicPortable(stagingDir, finalDir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return vanillaInstallResult{}, fmt.Errorf("native publish %s: %w", key, err)
		}
		downloadedFiles = append(downloadedFiles, publishFiles...)
	}

	virtualAssets := assets.Virtual || isLegacyVirtualAssetIndex(assetIndexID)
	if virtualAssets || assets.MapToResources {
		virtualIndexID := strings.TrimSpace(assetIndexID)
		if virtualAssets {
			if err := validateLegacyAssetIndexID(virtualIndexID); err != nil {
				return vanillaInstallResult{}, err
			}
		}

		type generatedAssetTree struct {
			enabled  bool
			finalRel string
			finalDir string
			staging  string
			kind     string
		}
		prepareTree := func(enabled bool, finalRel, kind string) (generatedAssetTree, error) {
			tree := generatedAssetTree{enabled: enabled, finalRel: filepath.ToSlash(finalRel), kind: kind}
			if !enabled {
				return tree, nil
			}
			finalDir, err := secureClientDestination(opts.ClientDir, tree.finalRel)
			if err != nil {
				return generatedAssetTree{}, err
			}
			parent := filepath.Dir(finalDir)
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return generatedAssetTree{}, err
			}
			staging, err := os.MkdirTemp(parent, "."+filepath.Base(finalDir)+".staging-")
			if err != nil {
				return generatedAssetTree{}, err
			}
			tree.finalDir = finalDir
			tree.staging = staging
			return tree, nil
		}

		virtualTree, err := prepareTree(virtualAssets, filepath.Join("assets", "virtual", virtualIndexID), "virtual-asset")
		if err != nil {
			return vanillaInstallResult{}, fmt.Errorf("virtual assets staging %s: %w", virtualIndexID, err)
		}
		resourcesTree, err := prepareTree(assets.MapToResources, "resources", "resource-asset")
		if err != nil {
			if virtualTree.staging != "" {
				_ = os.RemoveAll(virtualTree.staging)
			}
			return vanillaInstallResult{}, fmt.Errorf("resources staging: %w", err)
		}
		defer func() {
			if virtualTree.staging != "" {
				_ = os.RemoveAll(virtualTree.staging)
			}
			if resourcesTree.staging != "" {
				_ = os.RemoveAll(resourcesTree.staging)
			}
		}()

		names := make([]string, 0, len(assets.Objects))
		for name := range assets.Objects {
			names = append(names, name)
		}
		sort.Strings(names)
		generatedFiles := make([]vanillaDownloadedFile, 0, len(names)*2)
		for _, name := range names {
			object := assets.Objects[name]
			source := filepath.Join(opts.ClientDir, "assets", "objects", object.Hash[:2], object.Hash)
			for _, tree := range []generatedAssetTree{virtualTree, resourcesTree} {
				if !tree.enabled {
					continue
				}
				dest, err := secureClientDestination(tree.staging, filepath.FromSlash(name))
				if err != nil {
					return vanillaInstallResult{}, err
				}
				if err := copyFileVerified(source, dest, object.Size, object.Hash); err != nil {
					return vanillaInstallResult{}, fmt.Errorf("%s %s: %w", tree.kind, name, err)
				}
				sum, size, err := hashFile(dest)
				if err != nil {
					return vanillaInstallResult{}, fmt.Errorf("%s %s hash: %w", tree.kind, name, err)
				}
				generatedFiles = append(generatedFiles, vanillaDownloadedFile{
					Path:   filepath.ToSlash(filepath.Join(tree.finalRel, filepath.FromSlash(name))),
					Kind:   tree.kind,
					Size:   size,
					SHA1:   object.Hash,
					SHA256: sum,
				})
			}
		}
		for _, tree := range []*generatedAssetTree{&virtualTree, &resourcesTree} {
			if !tree.enabled {
				continue
			}
			if err := replaceDirectoryAtomicPortable(tree.staging, tree.finalDir); err != nil {
				return vanillaInstallResult{}, fmt.Errorf("%s publish: %w", tree.kind, err)
			}
			tree.staging = ""
		}
		downloadedFiles = append(downloadedFiles, generatedFiles...)
	}

	sort.Slice(downloadedFiles, func(i, j int) bool { return downloadedFiles[i].Path < downloadedFiles[j].Path })
	result := vanillaInstallResult{
		SchemaVersion:     cliSchemaVersion,
		ToolVersion:       version,
		MinecraftVersion:  selectedID,
		ReleaseType:       selected.Type,
		ClientDir:         opts.ClientDir,
		JavaMajorVersion:  javaMajor,
		MainClass:         metadata.MainClass,
		AssetIndex:        assetIndexID,
		Targets:           opts.Targets,
		Files:             downloadedFiles,
		MetadataPath:      filepath.ToSlash(filepath.Join("versions", selectedID, selectedID+".json")),
		MetadataSource:    map[bool]string{true: "verified-cache", false: "upstream"}[resolved.Recovered],
		UpstreamRecovered: resolved.Recovered,
		Status:            "installed-and-verified",
	}
	for _, file := range downloadedFiles {
		result.TotalBytes += file.Size
		if file.Cached {
			result.Cached++
		} else {
			result.Downloaded++
		}
	}
	statePath, err := secureClientDestination(opts.ClientDir, ".neverlauncher/vanilla-install.json")
	if err != nil {
		return vanillaInstallResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return vanillaInstallResult{}, err
	}
	if err := writeJSONFile(statePath, result); err != nil {
		return vanillaInstallResult{}, err
	}
	return result, nil
}

func runVanillaDownloads(ctx context.Context, client *http.Client, root string, tasks []vanillaDownloadTask, workers int) ([]vanillaDownloadedFile, error) {
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	jobs := make(chan vanillaDownloadTask)
	results := make(chan vanillaTaskResult, len(tasks))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range jobs {
				file, err := downloadVanillaArtifact(ctx, client, task, root)
				results <- vanillaTaskResult{File: file, Err: err}
				if err != nil {
					cancel()
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, task := range tasks {
			select {
			case <-ctx.Done():
				return
			case jobs <- task:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]vanillaDownloadedFile, 0, len(tasks))
	var firstErr error
	for result := range results {
		if result.Err != nil && firstErr == nil {
			firstErr = result.Err
		}
		if result.Err == nil {
			out = append(out, result.File)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func downloadVanillaArtifact(ctx context.Context, client *http.Client, task vanillaDownloadTask, root string) (vanillaDownloadedFile, error) {
	dest, err := secureClientDestination(root, task.Path)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	if task.Size > maxCompatibilityArtifact {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: artifact size %d превышает лимит %d", task.Path, task.Size, maxCompatibilityArtifact)
	}
	if task.SHA1 != "" {
		if err := validateSHA1Hex(task.SHA1); err != nil {
			return vanillaDownloadedFile{}, fmt.Errorf("%s: %w", task.Path, err)
		}
		if ok, sha256sum, size := existingFileMatchesSHA1(dest, task.SHA1, task.Size); ok {
			return vanillaDownloadedFile{Path: task.Path, Kind: task.Kind, Size: size, SHA1: strings.ToLower(task.SHA1), SHA256: sha256sum, TargetOS: uniqueStrings(task.TargetOS), Cached: true}, nil
		}
	}
	quarantined := false
	if _, statErr := os.Lstat(dest); statErr == nil {
		if task.SHA1 == "" {
			return vanillaDownloadedFile{}, fmt.Errorf("%s: существующий artifact нельзя безопасно переиспользовать без SHA-1", task.Path)
		}
		quarantined, err = quarantineCompatibilityArtifact(root, task.Path, "cached artifact failed Mojang SHA-1/size verification")
		if err != nil {
			return vanillaDownloadedFile{}, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return vanillaDownloadedFile{}, statErr
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return vanillaDownloadedFile{}, err
	}
	if err := validateRemoteURL(task.URL); err != nil {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: %w", task.Path, err)
	}

	tmp := dest + ".nlpart"
	resumeOffset, completedPartial, err := inspectVanillaPartial(tmp, task)
	if err != nil {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: partial recovery: %w", task.Path, err)
	}
	if completedPartial {
		ok, sha256sum, size := existingFileMatchesSHA1(tmp, task.SHA1, task.Size)
		if !ok {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				return vanillaDownloadedFile{}, fmt.Errorf("%s: удалить повреждённый completed partial: %w", task.Path, err)
			}
			resumeOffset = 0
		} else {
			if _, err := secureClientDestination(root, task.Path); err != nil {
				return vanillaDownloadedFile{}, err
			}
			if err := replaceFileAtomicPortable(tmp, dest); err != nil {
				return vanillaDownloadedFile{}, err
			}
			return vanillaDownloadedFile{Path: task.Path, Kind: task.Kind, Size: size, SHA1: strings.ToLower(task.SHA1), SHA256: sha256sum, TargetOS: uniqueStrings(task.TargetOS), Resumed: true, Quarantined: quarantined}, nil
		}
	}

	resp, resumed, err := fetchVanillaArtifactResponse(ctx, client, task, resumeOffset)
	if err != nil {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: download: %w", task.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: HTTP %d", task.Path, resp.StatusCode)
	}
	if resumed {
		if err := validateContentRange(resp.Header.Get("Content-Range"), resumeOffset, task.Size); err != nil {
			_ = os.Remove(tmp)
			return vanillaDownloadedFile{}, fmt.Errorf("%s: %w", task.Path, err)
		}
		if resp.ContentLength > 0 && task.Size > 0 && resp.ContentLength != task.Size-resumeOffset {
			_ = os.Remove(tmp)
			return vanillaDownloadedFile{}, fmt.Errorf("%s: resumed Content-Length=%d, ожидалось %d", task.Path, resp.ContentLength, task.Size-resumeOffset)
		}
	} else if task.Size > 0 && resp.ContentLength > 0 && resp.ContentLength != task.Size {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: Content-Length=%d, ожидалось %d", task.Path, resp.ContentLength, task.Size)
	}

	h1 := sha1.New()
	h256 := sha256.New()
	var out *os.File
	if resumed {
		prefix, err := os.Open(tmp)
		if err != nil {
			return vanillaDownloadedFile{}, err
		}
		hashed, hashErr := io.Copy(io.MultiWriter(h1, h256), prefix)
		closeErr := prefix.Close()
		if hashErr != nil || closeErr != nil || hashed != resumeOffset {
			return vanillaDownloadedFile{}, fmt.Errorf("%s: partial prefix hash failed", task.Path)
		}
		out, err = os.OpenFile(tmp, os.O_WRONLY|os.O_APPEND, 0o644)
	} else {
		resumeOffset = 0
		out, err = os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	}
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	limit := maxCompatibilityArtifact - resumeOffset + 1
	written, copyErr := io.Copy(io.MultiWriter(out, h1, h256), io.LimitReader(resp.Body, limit))
	syncErr := out.Sync()
	closeErr := out.Close()
	totalWritten := resumeOffset + written
	if copyErr != nil || syncErr != nil || closeErr != nil {
		// Keep a regular partial file. A later invocation can safely resume it from
		// the exact byte offset because the final Mojang SHA-1 remains mandatory.
		return vanillaDownloadedFile{}, fmt.Errorf("%s: запись не завершена: %v %v %v", task.Path, copyErr, syncErr, closeErr)
	}
	gotSHA1 := hex.EncodeToString(h1.Sum(nil))
	gotSHA256 := hex.EncodeToString(h256.Sum(nil))
	if totalWritten > maxCompatibilityArtifact {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("%s: artifact превышает лимит %d", task.Path, maxCompatibilityArtifact)
	}
	if task.Size > 0 && totalWritten != task.Size {
		// A clean early EOF is also resumable; preserve the verified-size-bounded
		// partial instead of throwing away progress.
		return vanillaDownloadedFile{}, fmt.Errorf("%s: неполная загрузка %d/%d bytes сохранена для recovery", task.Path, totalWritten, task.Size)
	}
	if task.SHA1 != "" && !strings.EqualFold(gotSHA1, task.SHA1) {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("%s: SHA-1 mismatch", task.Path)
	}
	if _, err := secureClientDestination(root, task.Path); err != nil {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, err
	}
	if err := replaceFileAtomicPortable(tmp, dest); err != nil {
		return vanillaDownloadedFile{}, err
	}
	return vanillaDownloadedFile{Path: task.Path, Kind: task.Kind, Size: totalWritten, SHA1: gotSHA1, SHA256: gotSHA256, TargetOS: uniqueStrings(task.TargetOS), Cached: false, Resumed: resumed, Quarantined: quarantined}, nil
}

func inspectVanillaPartial(tmp string, task vanillaDownloadTask) (offset int64, completed bool, err error) {
	info, err := os.Lstat(tmp)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, false, errors.New(".nlpart должен быть обычным файлом")
	}
	if task.Size <= 0 || task.SHA1 == "" || info.Size() <= 0 || info.Size() > task.Size {
		if err := os.Remove(tmp); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	if info.Size() == task.Size {
		return info.Size(), true, nil
	}
	return info.Size(), false, nil
}

func fetchVanillaArtifactResponse(ctx context.Context, client *http.Client, task vanillaDownloadTask, resumeOffset int64) (*http.Response, bool, error) {
	if resumeOffset > 0 && task.Size > resumeOffset {
		headers := make(http.Header)
		headers.Set("Range", fmt.Sprintf("bytes=%d-", resumeOffset))
		resp, err := compatibilityGETWithHeaders(ctx, client, task.URL, "NeverLauncher/"+version+" VanillaMaterializer", headers)
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode == http.StatusPartialContent {
			return resp, true, nil
		}
		// Servers are allowed to ignore Range and return a full 200 response. In
		// that case restart from zero; never append a full body to a partial file.
		if resp.StatusCode == http.StatusOK {
			return resp, false, nil
		}
		return resp, false, nil
	}
	resp, err := compatibilityGET(ctx, client, task.URL, "NeverLauncher/"+version+" VanillaMaterializer")
	return resp, false, err
}

func validateContentRange(value string, expectedStart, expectedTotal int64) error {
	value = strings.TrimSpace(value)
	var start, end, total int64
	if _, err := fmt.Sscanf(value, "bytes %d-%d/%d", &start, &end, &total); err != nil {
		return fmt.Errorf("некорректный Content-Range %q", value)
	}
	if start != expectedStart || end < start || (expectedTotal > 0 && total != expectedTotal) || (expectedTotal > 0 && end >= expectedTotal) {
		return fmt.Errorf("Content-Range mismatch: %q", value)
	}
	return nil
}

func existingFileMatchesSHA1(path, expected string, expectedSize int64) (bool, string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return false, "", 0
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() || (expectedSize > 0 && info.Size() != expectedSize) {
		return false, "", 0
	}
	h1 := sha1.New()
	h256 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h1, h256), f); err != nil {
		return false, "", 0
	}
	if !strings.EqualFold(hex.EncodeToString(h1.Sum(nil)), expected) {
		return false, "", 0
	}
	return true, hex.EncodeToString(h256.Sum(nil)), info.Size()
}

func extractNativeJar(archivePath, targetDir string, excludes []string) ([]string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if len(reader.File) > maxCompatibilityNativeEntries {
		return nil, fmt.Errorf("native archive содержит слишком много entries: %d", len(reader.File))
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return nil, err
	}
	extracted := []string{}
	var totalExtracted int64
	for _, entry := range reader.File {
		name := strings.ReplaceAll(entry.Name, "\\", "/")
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(name), "META-INF/") || isExcludedNative(name, excludes) {
			continue
		}
		clean := path.Clean(name)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean != name {
			return nil, fmt.Errorf("archive traversal entry: %s", entry.Name)
		}
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("native archive содержит symlink: %s", entry.Name)
		}
		if !mode.IsRegular() {
			return nil, fmt.Errorf("native archive содержит неподдерживаемый entry type: %s", entry.Name)
		}
		if entry.UncompressedSize64 > uint64(maxCompatibilityNativeEntry) {
			return nil, fmt.Errorf("native archive entry %s имеет небезопасный размер %d", entry.Name, entry.UncompressedSize64)
		}
		if totalExtracted > maxCompatibilityNativeExtract-int64(entry.UncompressedSize64) {
			return nil, fmt.Errorf("native archive распаковывается более чем в %d bytes", maxCompatibilityNativeExtract)
		}
		dst, err := secureClientDestination(targetDir, clean)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(targetDir, dst)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
			return nil, fmt.Errorf("native archive path escape: %s", entry.Name)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		src, err := entry.Open()
		if err != nil {
			return nil, err
		}
		tmp := dst + ".nlpart"
		if info, err := os.Lstat(tmp); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
			src.Close()
			return nil, fmt.Errorf("native temp path имеет небезопасный тип: %s", tmp)
		}
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			src.Close()
			return nil, err
		}
		copied, copyErr := io.Copy(out, io.LimitReader(src, maxCompatibilityNativeEntry+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		src.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("native %s extraction failed", entry.Name)
		}
		if copied != int64(entry.UncompressedSize64) || copied > maxCompatibilityNativeEntry {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("native %s uncompressed size mismatch: got %d expected %d", entry.Name, copied, entry.UncompressedSize64)
		}
		if err := replaceFileAtomicPortable(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return nil, err
		}
		totalExtracted += copied
		extracted = append(extracted, filepath.ToSlash(clean))
	}
	sort.Strings(extracted)
	return extracted, nil
}

func copyFileVerified(src, dst string, expectedSize int64, expectedSHA1 string) error {
	ok, _, _ := existingFileMatchesSHA1(src, expectedSHA1, expectedSize)
	if !ok {
		return errors.New("source asset не прошёл SHA-1/size verification")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".nlpart"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := replaceFileAtomicPortable(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func fetchJSONBytes(ctx context.Context, client *http.Client, source string, max int64) ([]byte, error) {
	return fetchBytesVerified(ctx, client, source, "", 0, max, false)
}

func fetchBytesVerified(ctx context.Context, client *http.Client, source, expectedSHA1 string, expectedSize, max int64, requireHash bool) ([]byte, error) {
	if requireHash && expectedSHA1 == "" {
		return nil, errors.New("upstream checksum обязателен")
	}
	if err := validateRemoteURL(source); err != nil {
		return nil, err
	}
	resp, err := compatibilityGET(ctx, client, source, "NeverLauncher/"+version+" VanillaMaterializer")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if expectedSize > 0 && resp.ContentLength > 0 && resp.ContentLength != expectedSize {
		return nil, fmt.Errorf("Content-Length=%d, ожидалось %d", resp.ContentLength, expectedSize)
	}
	if max <= 0 {
		max = 64 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("response превышает лимит %d bytes", max)
	}
	if expectedSize > 0 && int64(len(data)) != expectedSize {
		return nil, fmt.Errorf("размер %d, ожидался %d", len(data), expectedSize)
	}
	if expectedSHA1 != "" {
		sum := sha1.Sum(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), expectedSHA1) {
			return nil, errors.New("SHA-1 mismatch")
		}
	}
	return data, nil
}

func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return errors.New("слишком много HTTP redirect")
			}
			return validateRemoteURL(req.URL.String())
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func validateRemoteURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.Opaque != "" {
		return fmt.Errorf("некорректный remote URL: %q", raw)
	}
	if parsed.User != nil || parsed.Fragment != "" || strings.ContainsAny(raw, "\r\n\x00") {
		return fmt.Errorf("remote URL содержит credentials/fragment/control characters: %q", raw)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if strings.Contains(host, "%") {
		return fmt.Errorf("remote URL содержит IPv6 zone identifier: %q", raw)
	}
	if parsed.Scheme == "https" {
		if ip := net.ParseIP(host); ip != nil && isPrivateCompatibilityIP(ip) && !allowPrivateCompatibilityUpstream() {
			return fmt.Errorf("private/link-local HTTPS upstream требует NEVERLAUNCHER_ALLOW_PRIVATE_UPSTREAM=1: %s", raw)
		}
		return nil
	}
	if parsed.Scheme == "http" {
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("remote URL должен использовать HTTPS: %s", raw)
}

func allowPrivateCompatibilityUpstream() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NEVERLAUNCHER_ALLOW_PRIVATE_UPSTREAM"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func isPrivateCompatibilityIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func resolveRequestedMinecraftVersion(manifest MojangVersionManifest, requested string) string {
	normalized := strings.TrimSpace(requested)
	switch strings.ToLower(normalized) {
	case "", "latest", "latest-release":
		return manifest.Latest["release"]
	case "latest-snapshot", "snapshot":
		return manifest.Latest["snapshot"]
	case "1.0.0":
		// Mojang's canonical first release id is "1.0". Accept the common
		// semantic-version spelling without fabricating a non-existent version.
		return "1.0"
	default:
		return normalized
	}
}

func isLegacyVirtualAssetIndex(id string) bool {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "pre-1.6", "legacy":
		return true
	default:
		return false
	}
}

func validateLegacyAssetIndexID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\`) || id == "." || id == ".." || strings.ContainsRune(id, '\x00') {
		return fmt.Errorf("небезопасный legacy asset index id: %q", id)
	}
	return nil
}

func parseVanillaTargets(raw string) ([]vanillaTarget, error) {
	if strings.TrimSpace(raw) == "" {
		return []vanillaTarget{currentVanillaTarget()}, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]vanillaTarget, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), "/")
		if len(fields) != 2 {
			return nil, fmt.Errorf("некорректный --target %q, ожидается os/arch", part)
		}
		target, err := normalizeVanillaTarget(vanillaTarget{OS: fields[0], Arch: fields[1]})
		if err != nil {
			return nil, err
		}
		key := target.OS + "/" + target.Arch
		if !seen[key] {
			seen[key] = true
			out = append(out, target)
		}
	}
	return out, nil
}

func currentVanillaTarget() vanillaTarget {
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "osx"
	}
	return vanillaTarget{OS: osName, Arch: normalizeVanillaArch(runtime.GOARCH)}
}

func normalizeVanillaTarget(target vanillaTarget) (vanillaTarget, error) {
	osName := strings.ToLower(strings.TrimSpace(target.OS))
	switch osName {
	case "win", "windows":
		osName = "windows"
	case "linux":
	case "darwin", "mac", "macos", "osx":
		osName = "osx"
	default:
		return vanillaTarget{}, fmt.Errorf("неподдерживаемая target OS: %s", target.OS)
	}
	arch := normalizeVanillaArch(target.Arch)
	switch arch {
	case "x86", "x86_64", "aarch64", "arm":
	default:
		return vanillaTarget{}, fmt.Errorf("неподдерживаемая target arch: %s", target.Arch)
	}
	return vanillaTarget{OS: osName, Arch: arch}, nil
}

func normalizeVanillaArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64", "x64", "x86_64":
		return "x86_64"
	case "386", "i386", "i686", "x86":
		return "x86"
	case "arm64", "aarch64":
		return "aarch64"
	case "arm", "arm32":
		return "arm"
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

func nativeArchForTarget(arch string) string {
	if arch == "x86" || arch == "arm" {
		return "32"
	}
	return "64"
}

func hasMojangDownloadDescriptor(download MojangDownload) bool {
	return strings.TrimSpace(download.Path) != "" || strings.TrimSpace(download.URL) != "" || strings.TrimSpace(download.SHA1) != "" || download.Size > 0 || strings.TrimSpace(download.ID) != ""
}

func nativeClassifierForTarget(natives map[string]string, osName string) string {
	if natives == nil {
		return ""
	}
	if value := natives[osName]; value != "" {
		return value
	}
	if osName == "osx" {
		return natives["macos"]
	}
	return ""
}

func rulesAllowTarget(rules []map[string]any, target vanillaTarget) bool {
	if len(rules) == 0 {
		return true
	}
	allowed := false
	for _, rule := range rules {
		action, _ := rule["action"].(string)
		matches := true
		if osRule, ok := rule["os"].(map[string]any); ok {
			if name, ok := osRule["name"].(string); ok && strings.TrimSpace(name) != "" {
				matches = matches && vanillaOSRuleMatches(name, target)
			}
			if arch, ok := osRule["arch"].(string); ok && strings.TrimSpace(arch) != "" {
				re, err := regexp.Compile("^(?:" + arch + ")$")
				if err != nil {
					matches = false
				} else {
					matches = matches && (re.MatchString(target.Arch) || re.MatchString(vanillaArchAlias(target.Arch)))
				}
			}
		}
		// build-side materialization has no dynamic launcher feature state; feature-gated entries are
		// retained only if they don't require a true feature. Runtime evaluates them again at launch.
		if features, ok := rule["features"].(map[string]any); ok {
			for _, expected := range features {
				if value, ok := expected.(bool); ok && value {
					matches = false
				}
			}
		}
		if matches {
			if action == "allow" {
				allowed = true
			} else if action == "disallow" {
				allowed = false
			}
		}
	}
	return allowed
}

func vanillaArchAlias(arch string) string {
	switch normalizeVanillaArch(arch) {
	case "x86_64":
		return "x64"
	case "aarch64":
		return "arm64"
	default:
		return normalizeVanillaArch(arch)
	}
}

func vanillaOSRuleMatches(name string, target vanillaTarget) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	aliases := map[string]string{"win": "windows", "darwin": "osx", "mac": "osx", "macos": "osx"}
	if v, ok := aliases[n]; ok {
		n = v
	}
	for _, suffix := range []struct{ token, arch string }{{"-arm64", "aarch64"}, {"-aarch64", "aarch64"}, {"-x64", "x86_64"}, {"-x86_64", "x86_64"}} {
		if strings.HasSuffix(n, suffix.token) {
			base := strings.TrimSuffix(n, suffix.token)
			if base == "macos" || base == "mac" || base == "darwin" {
				base = "osx"
			}
			return base == target.OS && suffix.arch == target.Arch
		}
	}
	return n == target.OS
}

func libraryArtifactAppliesToTarget(name string, target vanillaTarget) bool {
	parts := strings.Split(strings.TrimSpace(name), ":")
	if len(parts) < 4 {
		return true
	}
	classifier := strings.ToLower(parts[3])
	if !strings.HasPrefix(classifier, "natives-") {
		return true
	}
	osToken := target.OS
	if osToken == "osx" {
		osToken = "macos"
	}
	prefix := "natives-" + osToken
	if !strings.HasPrefix(classifier, prefix) {
		return true // OS rules remain authoritative for artifacts belonging to another OS.
	}
	suffix := strings.TrimPrefix(classifier, prefix)
	switch suffix {
	case "":
		return target.Arch == "x86_64"
	case "-arm64", "-aarch64":
		return target.Arch == "aarch64"
	case "-x86", "-i386", "-i686":
		return target.Arch == "x86"
	case "-arm32":
		return target.Arch == "arm"
	default:
		return true
	}
}

func extractExcludes(extract map[string]any) []string {
	raw, ok := extract["exclude"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok && strings.TrimSpace(value) != "" {
			out = append(out, strings.ReplaceAll(value, "\\", "/"))
		}
	}
	return out
}

func isExcludedNative(name string, excludes []string) bool {
	for _, prefix := range excludes {
		prefix = strings.TrimPrefix(strings.ReplaceAll(prefix, "\\", "/"), "/")
		if prefix != "" && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func validateVanillaLaunchMetadata(v vanillaVersionMetadata) error {
	if len(v.Arguments.Game) == 0 && strings.TrimSpace(v.MinecraftArgs) == "" {
		return fmt.Errorf("Minecraft %s version.json не содержит исполняемые arguments.game или minecraftArguments", strings.TrimSpace(v.ID))
	}
	return nil
}

func isLegacyVanilla0170v1Release(version string) bool {
	_, ok := legacyVanilla0170v1ReleaseSet[strings.TrimSpace(version)]
	return ok
}

func javaMajorFromVersion(minecraftVersion string, v MojangVersionFile) (int, error) {
	metadataMajor := 0
	if raw, ok := v.JavaVersion["majorVersion"]; ok {
		switch n := raw.(type) {
		case float64:
			if n > 0 && n == float64(int(n)) {
				metadataMajor = int(n)
			}
		case int:
			if n > 0 {
				metadataMajor = n
			}
		case json.Number:
			value, err := strconv.Atoi(n.String())
			if err == nil && value > 0 {
				metadataMajor = value
			}
		}
	}
	if isLegacyVanillaJava8Release(minecraftVersion) {
		if metadataMajor != 0 && metadataMajor != 8 {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata Java mismatch: Legacy Vanilla требует Java 8, got %d", minecraftVersion, metadataMajor)
		}
		return 8, nil
	}
	if expected, enforced := expectedJavaMajorForVanilla0170v2(minecraftVersion); enforced {
		if metadataMajor == 0 {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata не содержит javaVersion.majorVersion; 0.17.0v2 требует exact Java %d", minecraftVersion, expected)
		}
		if metadataMajor != expected {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata Java mismatch: 0.17.0v2 expected %d, got %d", minecraftVersion, expected, metadataMajor)
		}
		return metadataMajor, nil
	}
	if expected, enforced := expectedJavaMajorForVanilla0170v3(minecraftVersion); enforced {
		if metadataMajor == 0 {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata не содержит javaVersion.majorVersion; 0.17.0v3 требует exact Java %d", minecraftVersion, expected)
		}
		if metadataMajor != expected {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata Java mismatch: 0.17.0v3 expected %d, got %d", minecraftVersion, expected, metadataMajor)
		}
		return metadataMajor, nil
	}
	if expected, enforced := expectedJavaMajorForVanilla0166(minecraftVersion); enforced {
		if metadataMajor == 0 {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata не содержит javaVersion.majorVersion; 0.16.6 требует exact Java %d", minecraftVersion, expected)
		}
		if metadataMajor != expected {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata Java mismatch: expected %d, got %d", minecraftVersion, expected, metadataMajor)
		}
		return metadataMajor, nil
	}
	if expected, enforced := expectedJavaMajorForVanilla0167(minecraftVersion); enforced {
		if metadataMajor == 0 {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata не содержит javaVersion.majorVersion; 0.16.7 требует exact Java %d", minecraftVersion, expected)
		}
		if metadataMajor != expected {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata Java mismatch: expected %d, got %d", minecraftVersion, expected, metadataMajor)
		}
		return metadataMajor, nil
	}
	if expected, enforced := expectedJavaMajorForVanilla0168(minecraftVersion); enforced {
		if metadataMajor == 0 {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata не содержит javaVersion.majorVersion; 0.16.8 требует exact Java %d", minecraftVersion, expected)
		}
		if metadataMajor != expected {
			return 0, fmt.Errorf("Minecraft %s: Mojang metadata Java mismatch: expected %d, got %d", minecraftVersion, expected, metadataMajor)
		}
		return metadataMajor, nil
	}
	if metadataMajor > 0 {
		return metadataMajor, nil
	}
	// Unknown historical metadata outside the certified Legacy Vanilla release
	// range keeps the old compatibility fallback, but certified 1.x releases are
	// handled above by the exact Java 8 policy.
	return 8, nil
}

func isLegacyVanillaJava8Release(version string) bool {
	major, minor, patch, ok := parseMinecraftReleaseVersion(version)
	return ok && major == 1 && (minor < 16 || (minor == 16 && patch <= 5))
}

func expectedJavaMajorForVanilla0170v2(version string) (int, bool) {
	expected, ok := java16_17Vanilla0170v2Releases[strings.TrimSpace(version)]
	return expected, ok
}

func expectedJavaMajorForVanilla0170v3(version string) (int, bool) {
	expected, ok := java21_25Vanilla0170v3Releases[strings.TrimSpace(version)]
	return expected, ok
}

func expectedJavaMajorForVanilla0166(version string) (int, bool) {
	major, minor, patch, ok := parseMinecraftReleaseVersion(version)
	if !ok || major != 1 {
		return 0, false
	}
	if minor == 17 && patch == 1 {
		return 16, true
	}
	if minor < 18 || minor > 20 {
		return 0, false
	}
	if minor == 20 && patch > 4 {
		return 0, false
	}
	return 17, true
}

func expectedJavaMajorForVanilla0167(version string) (int, bool) {
	major, minor, patch, ok := parseMinecraftReleaseVersion(version)
	if !ok || major != 1 {
		return 0, false
	}
	if minor == 20 {
		if patch == 5 || patch == 6 {
			return 21, true
		}
		return 0, false
	}
	if minor == 21 && patch >= 0 && patch <= 10 {
		return 21, true
	}
	return 0, false
}

func expectedJavaMajorForVanilla0168(version string) (int, bool) {
	major, minor, patch, ok := parseMinecraftReleaseVersion(version)
	if !ok || major != 26 {
		return 0, false
	}
	// 26.1.x and the 26.3 release require Java 25.
	if minor == 1 || (minor == 3 && patch == 0) {
		return 25, true
	}
	return 0, false
}

func parseMinecraftReleaseVersion(value string) (major, minor, patch int, ok bool) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0, 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return 0, 0, 0, false
	}
	if len(parts) == 3 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil || patch < 0 {
			return 0, 0, 0, false
		}
	}
	return major, minor, patch, true
}

func validateVanillaRelativePath(rel string) error {
	rel = strings.ReplaceAll(rel, "\\", "/")
	clean := path.Clean(rel)
	if rel == "" || clean == "." || clean == ".." || clean != rel || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || strings.ContainsRune(rel, '\x00') {
		return fmt.Errorf("небезопасный Vanilla path: %q", rel)
	}
	return nil
}

func writeAtomicBytes(dst string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".nlpart"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, mode)
	if err == nil {
		err = f.Sync()
		_ = f.Close()
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := replaceFileAtomicPortable(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func unionStrings(a, b []string) []string {
	return uniqueStrings(append(append([]string{}, a...), b...))
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
