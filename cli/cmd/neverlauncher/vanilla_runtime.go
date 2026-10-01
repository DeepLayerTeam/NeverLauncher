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
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Size     int64    `json:"size"`
	SHA1     string   `json:"sha1,omitempty"`
	SHA256   string   `json:"sha256"`
	TargetOS []string `json:"targetOs,omitempty"`
	Cached   bool     `json:"cached"`
}

type vanillaInstallResult struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	ToolVersion      string                  `json:"toolVersion"`
	MinecraftVersion string                  `json:"minecraftVersion"`
	ReleaseType      string                  `json:"releaseType"`
	ClientDir        string                  `json:"clientDir"`
	JavaMajorVersion int                     `json:"javaMajorVersion"`
	MainClass        string                  `json:"mainClass"`
	AssetIndex       string                  `json:"assetIndex"`
	Targets          []vanillaTarget         `json:"targets"`
	Downloaded       int                     `json:"downloaded"`
	Cached           int                     `json:"cached"`
	TotalBytes       int64                   `json:"totalBytes"`
	Files            []vanillaDownloadedFile `json:"files"`
	MetadataPath     string                  `json:"metadataPath"`
	Status           string                  `json:"status"`
}

type vanillaServerInstallResult struct {
	SchemaVersion    string `json:"schemaVersion"`
	ToolVersion      string `json:"toolVersion"`
	MinecraftVersion string `json:"minecraftVersion"`
	ReleaseType      string `json:"releaseType"`
	JavaMajorVersion int    `json:"javaMajorVersion"`
	ServerDir        string `json:"serverDir"`
	ServerJar        string `json:"serverJar"`
	MetadataPath     string `json:"metadataPath"`
	Size             int64  `json:"size"`
	SHA1             string `json:"sha1"`
	SHA256           string `json:"sha256"`
	Cached           bool   `json:"cached"`
	Status           string `json:"status"`
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

	manifestBytes, err := fetchJSONBytes(ctx, client, versionManifest, 16<<20)
	if err != nil {
		return vanillaServerInstallResult{}, fmt.Errorf("Mojang version manifest: %w", err)
	}
	var manifest MojangVersionManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return vanillaServerInstallResult{}, fmt.Errorf("Mojang version manifest повреждён: %w", err)
	}
	selectedID := resolveRequestedMinecraftVersion(manifest, requestedVersion)
	selected, ok := findMojangManifestVersion(manifest, selectedID)
	if !ok {
		return vanillaServerInstallResult{}, fmt.Errorf("Minecraft %s отсутствует в Mojang version manifest", selectedID)
	}
	if selected.URL == "" || selected.SHA1 == "" {
		return vanillaServerInstallResult{}, fmt.Errorf("Mojang manifest entry %s не содержит URL/SHA1", selectedID)
	}
	versionBytes, err := fetchBytesVerified(ctx, client, selected.URL, selected.SHA1, 0, 32<<20, true)
	if err != nil {
		return vanillaServerInstallResult{}, fmt.Errorf("version.json %s: %w", selectedID, err)
	}
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

	metadataPath := filepath.Join(serverDir, "version.json")
	if err := writeAtomicBytes(metadataPath, versionBytes, 0o644); err != nil {
		return vanillaServerInstallResult{}, err
	}
	serverPath := filepath.Join(serverDir, "server.jar")
	cached := false
	serverBytes, err := os.ReadFile(serverPath)
	if err == nil && int64(len(serverBytes)) == serverDownload.Size {
		h := sha1.Sum(serverBytes)
		if strings.EqualFold(hex.EncodeToString(h[:]), serverDownload.SHA1) {
			cached = true
		}
	}
	if !cached {
		serverBytes, err = fetchBytesVerified(ctx, client, serverDownload.URL, serverDownload.SHA1, serverDownload.Size, 512<<20, true)
		if err != nil {
			return vanillaServerInstallResult{}, fmt.Errorf("server.jar %s: %w", selectedID, err)
		}
		if err := writeAtomicBytes(serverPath, serverBytes, 0o644); err != nil {
			return vanillaServerInstallResult{}, err
		}
	}
	h256 := sha256.Sum256(serverBytes)
	return vanillaServerInstallResult{
		SchemaVersion: "1.0", ToolVersion: version, MinecraftVersion: selectedID, ReleaseType: selected.Type,
		JavaMajorVersion: javaMajor, ServerDir: filepath.Clean(serverDir), ServerJar: filepath.ToSlash(filepath.Join(filepath.Clean(serverDir), "server.jar")),
		MetadataPath: filepath.ToSlash(filepath.Join(filepath.Clean(serverDir), "version.json")), Size: int64(len(serverBytes)), SHA1: strings.ToLower(serverDownload.SHA1),
		SHA256: hex.EncodeToString(h256[:]), Cached: cached, Status: "installed-and-verified",
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

	var manifest MojangVersionManifest
	manifestBytes, err := fetchJSONBytes(ctx, client, opts.VersionManifest, 16<<20)
	if err != nil {
		return vanillaInstallResult{}, fmt.Errorf("Mojang version manifest: %w", err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return vanillaInstallResult{}, fmt.Errorf("Mojang version manifest повреждён: %w", err)
	}
	selectedID := resolveRequestedMinecraftVersion(manifest, opts.MinecraftVersion)
	selected, ok := findMojangManifestVersion(manifest, selectedID)
	if !ok {
		return vanillaInstallResult{}, fmt.Errorf("Minecraft %s отсутствует в Mojang version manifest", selectedID)
	}
	if selected.URL == "" || selected.SHA1 == "" {
		return vanillaInstallResult{}, fmt.Errorf("Mojang manifest entry %s не содержит URL/SHA1", selectedID)
	}
	versionBytes, err := fetchBytesVerified(ctx, client, selected.URL, selected.SHA1, 0, 32<<20, true)
	if err != nil {
		return vanillaInstallResult{}, fmt.Errorf("version.json %s: %w", selectedID, err)
	}
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
	assetBytes, err := fetchBytesVerified(ctx, client, metadata.AssetIndex.URL, metadata.AssetIndex.SHA1, metadata.AssetIndex.Size, 64<<20, true)
	if err != nil {
		return vanillaInstallResult{}, fmt.Errorf("asset index: %w", err)
	}
	assetIndexDest, err := secureClientDestination(opts.ClientDir, assetIndexPath)
	if err != nil {
		return vanillaInstallResult{}, err
	}
	if err := writeAtomicBytes(assetIndexDest, assetBytes, 0o644); err != nil {
		return vanillaInstallResult{}, err
	}
	var assets vanillaAssetIndex
	if err := json.Unmarshal(assetBytes, &assets); err != nil {
		return vanillaInstallResult{}, fmt.Errorf("asset index повреждён: %w", err)
	}
	for name, object := range assets.Objects {
		if err := validateAssetLogicalPath(name); err != nil {
			return vanillaInstallResult{}, err
		}
		if len(object.Hash) != 40 || object.Size < 0 {
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
	downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: filepath.ToSlash(filepath.Join("versions", selectedID, selectedID+".json")), Kind: "version-metadata", Size: int64(len(versionBytes)), SHA1: selected.SHA1, SHA256: hex.EncodeToString(metadataHash[:]), Cached: false})
	assetHash := sha256.Sum256(assetBytes)
	downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: assetIndexPath, Kind: "asset-index", Size: int64(len(assetBytes)), SHA1: metadata.AssetIndex.SHA1, SHA256: hex.EncodeToString(assetHash[:]), Cached: false})

	nativeTasks := make([]vanillaDownloadTask, 0)
	// Natives are generated output, not a cache. Rebuild every target directory so an
	// older Minecraft/loader materialization cannot leak stale native libraries into
	// the next signed package.
	for _, target := range opts.Targets {
		nativeRel := filepath.ToSlash(filepath.Join("natives", target.OS, target.Arch))
		nativeDir, err := secureClientDestination(opts.ClientDir, nativeRel)
		if err != nil {
			return vanillaInstallResult{}, err
		}
		if err := os.RemoveAll(nativeDir); err != nil {
			return vanillaInstallResult{}, fmt.Errorf("native cleanup %s/%s: %w", target.OS, target.Arch, err)
		}
		if err := os.MkdirAll(nativeDir, 0o755); err != nil {
			return vanillaInstallResult{}, fmt.Errorf("native directory %s/%s: %w", target.OS, target.Arch, err)
		}
	}
	for _, task := range taskList {
		if task.Kind == "native-archive" && task.NativeTarget != nil {
			nativeTasks = append(nativeTasks, task)
		}
	}
	for _, task := range nativeTasks {
		archivePath := filepath.Join(opts.ClientDir, filepath.FromSlash(task.Path))
		targetRel := filepath.ToSlash(filepath.Join("natives", task.NativeTarget.OS, task.NativeTarget.Arch))
		targetDir, err := secureClientDestination(opts.ClientDir, targetRel)
		if err != nil {
			return vanillaInstallResult{}, err
		}
		extracted, err := extractNativeJar(archivePath, targetDir, task.NativeExclude)
		if err != nil {
			return vanillaInstallResult{}, fmt.Errorf("native extraction %s: %w", task.Path, err)
		}
		for _, rel := range extracted {
			full := filepath.Join(targetDir, filepath.FromSlash(rel))
			sum, size, err := hashFile(full)
			if err != nil {
				return vanillaInstallResult{}, err
			}
			downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: filepath.ToSlash(filepath.Join("natives", task.NativeTarget.OS, task.NativeTarget.Arch, rel)), Kind: "native", Size: size, SHA256: sum, TargetOS: []string{task.NativeTarget.OS}, Cached: false})
		}
	}

	virtualAssets := assets.Virtual || isLegacyVirtualAssetIndex(assetIndexID)
	if virtualAssets || assets.MapToResources {
		virtualIndexID := strings.TrimSpace(assetIndexID)
		if virtualAssets {
			if err := validateLegacyAssetIndexID(virtualIndexID); err != nil {
				return vanillaInstallResult{}, err
			}
			virtualRootRel := filepath.ToSlash(filepath.Join("assets", "virtual", virtualIndexID))
			virtualRoot, err := secureClientDestination(opts.ClientDir, virtualRootRel)
			if err != nil {
				return vanillaInstallResult{}, err
			}
			// assets/virtual is generated launcher output. Rebuild the selected index
			// atomically from verified objects so stale files from another old client
			// cannot leak into a package or alter pre-1.7 runtime behavior.
			if err := os.RemoveAll(virtualRoot); err != nil {
				return vanillaInstallResult{}, fmt.Errorf("virtual assets cleanup %s: %w", virtualIndexID, err)
			}
			if err := os.MkdirAll(virtualRoot, 0o755); err != nil {
				return vanillaInstallResult{}, fmt.Errorf("virtual assets directory %s: %w", virtualIndexID, err)
			}
		}

		names := make([]string, 0, len(assets.Objects))
		for name := range assets.Objects {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			object := assets.Objects[name]
			source := filepath.Join(opts.ClientDir, "assets", "objects", object.Hash[:2], object.Hash)
			if virtualAssets {
				destRel := filepath.ToSlash(filepath.Join("assets", "virtual", virtualIndexID, filepath.FromSlash(name)))
				dest, err := secureClientDestination(opts.ClientDir, destRel)
				if err != nil {
					return vanillaInstallResult{}, err
				}
				if err := copyFileVerified(source, dest, object.Size, object.Hash); err != nil {
					return vanillaInstallResult{}, fmt.Errorf("virtual asset %s: %w", name, err)
				}
				sum, size, err := hashFile(dest)
				if err != nil {
					return vanillaInstallResult{}, fmt.Errorf("virtual asset %s hash: %w", name, err)
				}
				downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: destRel, Kind: "virtual-asset", Size: size, SHA1: object.Hash, SHA256: sum})
			}
			if assets.MapToResources {
				destRel := filepath.ToSlash(filepath.Join("resources", filepath.FromSlash(name)))
				dest, err := secureClientDestination(opts.ClientDir, destRel)
				if err != nil {
					return vanillaInstallResult{}, err
				}
				if err := copyFileVerified(source, dest, object.Size, object.Hash); err != nil {
					return vanillaInstallResult{}, fmt.Errorf("resource asset %s: %w", name, err)
				}
				sum, size, err := hashFile(dest)
				if err != nil {
					return vanillaInstallResult{}, fmt.Errorf("resource asset %s hash: %w", name, err)
				}
				downloadedFiles = append(downloadedFiles, vanillaDownloadedFile{Path: filepath.ToSlash(filepath.Join("resources", name)), Kind: "resource-asset", Size: size, SHA1: object.Hash, SHA256: sum})
			}
		}
	}

	sort.Slice(downloadedFiles, func(i, j int) bool { return downloadedFiles[i].Path < downloadedFiles[j].Path })
	result := vanillaInstallResult{
		SchemaVersion:    cliSchemaVersion,
		ToolVersion:      version,
		MinecraftVersion: selectedID,
		ReleaseType:      selected.Type,
		ClientDir:        opts.ClientDir,
		JavaMajorVersion: javaMajor,
		MainClass:        metadata.MainClass,
		AssetIndex:       assetIndexID,
		Targets:          opts.Targets,
		Files:            downloadedFiles,
		MetadataPath:     filepath.ToSlash(filepath.Join("versions", selectedID, selectedID+".json")),
		Status:           "installed-and-verified",
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
		if ok, sha256sum, size := existingFileMatchesSHA1(dest, task.SHA1, task.Size); ok {
			return vanillaDownloadedFile{Path: task.Path, Kind: task.Kind, Size: size, SHA1: task.SHA1, SHA256: sha256sum, TargetOS: uniqueStrings(task.TargetOS), Cached: true}, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return vanillaDownloadedFile{}, err
	}
	if err := validateRemoteURL(task.URL); err != nil {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: %w", task.Path, err)
	}
	resp, err := compatibilityGET(ctx, client, task.URL, "NeverLauncher/"+version+" VanillaMaterializer")
	if err != nil {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: download: %w", task.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: HTTP %d", task.Path, resp.StatusCode)
	}
	if task.Size > 0 && resp.ContentLength > 0 && resp.ContentLength != task.Size {
		return vanillaDownloadedFile{}, fmt.Errorf("%s: Content-Length=%d, ожидалось %d", task.Path, resp.ContentLength, task.Size)
	}
	tmp := dest + ".nlpart"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	h1 := sha1.New()
	h256 := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, h1, h256), io.LimitReader(resp.Body, maxCompatibilityArtifact+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("%s: запись не завершена: %v %v %v", task.Path, copyErr, syncErr, closeErr)
	}
	gotSHA1 := hex.EncodeToString(h1.Sum(nil))
	gotSHA256 := hex.EncodeToString(h256.Sum(nil))
	if written > maxCompatibilityArtifact {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("%s: artifact превышает лимит %d", task.Path, maxCompatibilityArtifact)
	}
	if task.Size > 0 && written != task.Size {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("%s: размер %d, ожидался %d", task.Path, written, task.Size)
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
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, err
	}
	return vanillaDownloadedFile{Path: task.Path, Kind: task.Kind, Size: written, SHA1: gotSHA1, SHA256: gotSHA256, TargetOS: uniqueStrings(task.TargetOS), Cached: false}, nil
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
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return nil, err
	}
	extracted := []string{}
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
		if entry.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("native archive содержит symlink: %s", entry.Name)
		}
		dst, err := secureClientDestination(targetDir, clean)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(targetDir, dst)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
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
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			src.Close()
			return nil, err
		}
		_, copyErr := io.Copy(out, io.LimitReader(src, 512<<20))
		syncErr := out.Sync()
		closeErr := out.Close()
		src.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("native %s extraction failed", entry.Name)
		}
		if err := replaceFileAtomicPortable(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return nil, err
		}
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
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("некорректный remote URL: %q", raw)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" {
		host := strings.ToLower(parsed.Hostname())
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("remote URL должен использовать HTTPS: %s", raw)
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
	// Old launcher metadata predates javaVersion; Java 8 is the safe compatibility default.
	return 8, nil
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
