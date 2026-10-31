package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultForgeMavenBase    = "https://maven.minecraftforge.net"
	defaultNeoForgeMavenBase = "https://maven.neoforged.net/releases"
	defaultMavenCentralBase  = "https://repo.maven.apache.org/maven2"
)

type forgeMaterializeOptions struct {
	Loader                 string
	MinecraftVersion       string
	LoaderVersion          string
	ClientDir              string
	JavaExecutable         string
	InstallerURL           string
	InstallerSHA1          string
	InstallerSourceFile    string
	InstallerSourceSHA256  string
	MavenMetadataURL       string
	VersionManifest        string
	AssetBaseURL           string
	LibraryBaseURL         string
	Targets                []vanillaTarget
	Workers                int
	StrictUpstream         bool
	SharedCacheDir         string
	ResolutionLockPath     string
	ResolutionSourceSHA256 string
	ProcessorTimeout       time.Duration
	ProcessorSandbox       string
	LoaderCacheOnly        bool
	EnforceGASupport       bool
	HTTPClient             *http.Client
}

type forgeDataValue struct {
	Client string `json:"client"`
	Server string `json:"server"`
}

type forgeProcessor struct {
	Sides     []string          `json:"sides"`
	Jar       string            `json:"jar"`
	Classpath []string          `json:"classpath"`
	Args      []string          `json:"args"`
	Outputs   map[string]string `json:"outputs"`
}

type forgeInstallerProfile struct {
	Spec       int                       `json:"spec"`
	Profile    string                    `json:"profile"`
	Version    string                    `json:"version"`
	JSON       string                    `json:"json"`
	Path       string                    `json:"path"`
	Minecraft  string                    `json:"minecraft"`
	Data       map[string]forgeDataValue `json:"data"`
	Processors []forgeProcessor          `json:"processors"`
	Libraries  []MojangLibrary           `json:"libraries"`
}

type forgeLegacyInstall struct {
	ProfileName string `json:"profileName"`
	Target      string `json:"target"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	FilePath    string `json:"filePath"`
	Minecraft   string `json:"minecraft"`
}

type forgeLegacyInstallerProfile struct {
	Install     forgeLegacyInstall `json:"install"`
	VersionInfo json.RawMessage    `json:"versionInfo"`
}

type forgeMaterializeResult struct {
	SchemaVersion           string                  `json:"schemaVersion"`
	ToolVersion             string                  `json:"toolVersion"`
	Loader                  string                  `json:"loader"`
	MinecraftVersion        string                  `json:"minecraftVersion"`
	LoaderVersion           string                  `json:"loaderVersion"`
	ArtifactVersion         string                  `json:"artifactVersion"`
	ProfileID               string                  `json:"profileId"`
	ProfilePath             string                  `json:"profilePath"`
	MainClass               string                  `json:"mainClass"`
	ClientDir               string                  `json:"clientDir"`
	JavaMajorVersion        int                     `json:"javaMajorVersion"`
	InstallerSHA1           string                  `json:"installerSha1"`
	InstallerSHA256         string                  `json:"installerSha256"`
	InstallMode             string                  `json:"installMode"`
	LegacyUniversalPath     string                  `json:"legacyUniversalPath,omitempty"`
	LegacyUniversalSHA1     string                  `json:"legacyUniversalSha1,omitempty"`
	LegacyUniversalSHA256   string                  `json:"legacyUniversalSha256,omitempty"`
	LegacyTweaker           string                  `json:"legacyTweaker,omitempty"`
	LegacyBaseVersion       string                  `json:"legacyBaseVersion,omitempty"`
	LegacyProfileNormalized bool                    `json:"legacyProfileNormalized,omitempty"`
	ProcessorCount          int                     `json:"processorCount"`
	ClientProcessorCount    int                     `json:"clientProcessorCount"`
	ProcessorRan            int                     `json:"processorRan"`
	ProcessorSkipped        int                     `json:"processorSkipped"`
	ProcessorRecovered      int                     `json:"processorRecovered"`
	ProcessorJournalPath    string                  `json:"processorJournalPath,omitempty"`
	ProcessorJournalSHA256  string                  `json:"processorJournalSha256,omitempty"`
	ProcessorJournalRebuilt bool                    `json:"processorJournalRebuilt,omitempty"`
	LibraryCount            int                     `json:"libraryCount"`
	Downloaded              int                     `json:"downloaded"`
	Cached                  int                     `json:"cached"`
	TotalBytes              int64                   `json:"totalBytes"`
	ProfileSHA256           string                  `json:"profileSha256"`
	ResolutionLockPath      string                  `json:"resolutionLockPath"`
	ResolutionLockSHA256    string                  `json:"resolutionLockSha256"`
	ResolutionSourceURL     string                  `json:"resolutionSourceUrl"`
	ResolutionSourceSHA256  string                  `json:"resolutionSourceSha256"`
	MaterializationSHA256   string                  `json:"materializationSha256"`
	ReproducibilitySHA256   string                  `json:"reproducibilitySha256"`
	ResolutionPinned        bool                    `json:"resolutionPinned"`
	LoaderCacheOnly         bool                    `json:"loaderCacheOnly"`
	InstallerCacheHit       bool                    `json:"installerCacheHit"`
	UpstreamRecoveryUsed    bool                    `json:"upstreamRecoveryUsed"`
	Vanilla                 vanillaInstallResult    `json:"vanilla"`
	Files                   []vanillaDownloadedFile `json:"files"`
	Status                  string                  `json:"status"`
}

type mavenMetadataXML struct {
	Versioning struct {
		Release  string `xml:"release"`
		Latest   string `xml:"latest"`
		Versions struct {
			Version []string `xml:"version"`
		} `xml:"versions"`
	} `xml:"versioning"`
}

type installerBundle struct {
	Profile       forgeInstallerProfile
	Version       loaderVersionProfile
	VersionRaw    []byte
	ZipPath       string
	Legacy        bool
	LegacyMode    string
	LegacyInstall forgeLegacyInstall
}

type processorStats struct {
	Ran            int
	Skipped        int
	Recovered      int
	JournalPath    string
	JournalSHA256  string
	JournalRebuilt bool
}

func handleRuntimeForgeInstall(args []string) error {
	return handleRuntimeForgeLikeInstall("forge", args)
}

func handleRuntimeNeoForgeInstall(args []string) error {
	return handleRuntimeForgeLikeInstall("neoforge", args)
}

func handleRuntimeForgePackage(args []string) error {
	return handleRuntimeForgeLikePackage("forge", args)
}

func handleRuntimeNeoForgePackage(args []string) error {
	return handleRuntimeForgeLikePackage("neoforge", args)
}

func handleRuntimeForgeLikeInstall(loader string, args []string) error {
	opts, err := parseForgeMaterializeOptions(loader, args)
	if err != nil {
		return err
	}
	lock, err := acquireCompatibilityMaterializationLock(opts.ClientDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	result, err := installForgeLike(context.Background(), opts)
	if err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), result)
}

func handleRuntimeForgeLikePackage(loader string, args []string) error {
	opts, err := parseForgeMaterializeOptions(loader, args)
	if err != nil {
		return err
	}
	lock, err := acquireCompatibilityMaterializationLock(opts.ClientDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	result, err := installForgeLike(context.Background(), opts)
	if err != nil {
		return err
	}
	releaseVersion := flagValue(args, "--version", result.MinecraftVersion+"-"+loader+"-"+result.LoaderVersion)
	pkg, err := buildClientPackage(opts.ClientDir, flagValue(args, "--project", "demo-project"), flagValue(args, "--profile", loader), flagValue(args, "--channel", "stable"), releaseVersion, flagValue(args, "--base-url", ""))
	if err != nil {
		return err
	}
	pkg["status"] = "materialized-and-packaged"
	pkg[loader] = result
	pkg["manifestSettings"] = map[string]any{
		"minecraft": map[string]any{
			"version":       result.MinecraftVersion,
			"loader":        loader,
			"loaderVersion": result.LoaderVersion,
			"mainClass":     result.MainClass,
		},
		"runtime": map[string]any{
			"java": map[string]any{
				"majorVersion":    result.JavaMajorVersion,
				"distribution":    "temurin",
				"allowCustomPath": true,
			},
			"launch": map[string]any{
				"classpathStrategy":   "compatibility",
				"versionMetadataPath": result.ProfilePath,
				"nativesDirectory":    "natives",
				"offlineMode":         true,
			},
		},
		"directories": map[string]any{"game": ".", "assets": "assets", "libraries": "libraries", "natives": "natives"},
	}
	return writeOrPrintJSON(flagValue(args, "--output", "client-package.json"), pkg)
}

func parseForgeMaterializeOptions(loader string, args []string) (forgeMaterializeOptions, error) {
	loader = strings.ToLower(strings.TrimSpace(loader))
	if loader != "forge" && loader != "neoforge" {
		return forgeMaterializeOptions{}, fmt.Errorf("installer loader %s не поддерживается", loader)
	}
	minecraftVersion := strings.TrimSpace(flagValue(args, "--minecraft", "latest-release"))
	if compatibilityLoaderGA0180Required(version) && minecraftVersion != "latest-release" {
		if _, err := enforceLoaderGASupport0180(loader, minecraftVersion, 0); err != nil {
			return forgeMaterializeOptions{}, err
		}
	}
	clientDir := flagValue(args, "--client-dir", filepath.Join(".launcher", loader, minecraftVersion))
	workers, err := strconv.Atoi(flagValue(args, "--workers", "12"))
	if err != nil || workers < 1 || workers > 64 {
		return forgeMaterializeOptions{}, errors.New("--workers должен быть числом от 1 до 64")
	}
	targets, err := parseVanillaTargets(flagValue(args, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
	if err != nil {
		return forgeMaterializeOptions{}, err
	}
	timeout, err := time.ParseDuration(flagValue(args, "--processor-timeout", "10m"))
	if err != nil || timeout < time.Second || timeout > time.Hour {
		return forgeMaterializeOptions{}, errors.New("--processor-timeout должен быть от 1s до 1h")
	}
	sandbox := strings.ToLower(strings.TrimSpace(flagValue(args, "--processor-sandbox", "process")))
	if sandbox != "process" && sandbox != "required" {
		return forgeMaterializeOptions{}, errors.New("--processor-sandbox must be process or required")
	}
	return forgeMaterializeOptions{
		Loader:             loader,
		MinecraftVersion:   minecraftVersion,
		LoaderVersion:      strings.TrimSpace(flagValue(args, "--loader-version", "latest-stable")),
		ClientDir:          clientDir,
		JavaExecutable:     strings.TrimSpace(flagValue(args, "--java", "")),
		InstallerURL:       strings.TrimSpace(flagValue(args, "--installer-url", "")),
		InstallerSHA1:      strings.TrimSpace(flagValue(args, "--installer-sha1", "")),
		MavenMetadataURL:   strings.TrimSpace(flagValue(args, "--maven-metadata-url", "")),
		VersionManifest:    flagValue(args, "--version-manifest", defaultMojangVersionManifest),
		AssetBaseURL:       flagValue(args, "--asset-base-url", defaultMojangAssetBase),
		LibraryBaseURL:     flagValue(args, "--library-base-url", defaultMojangLibraryBase),
		Targets:            targets,
		Workers:            workers,
		StrictUpstream:     !strings.EqualFold(flagValue(args, "--strict-upstream", "true"), "false"),
		SharedCacheDir:     strings.TrimSpace(flagValue(args, "--shared-cache-dir", "")),
		ResolutionLockPath: strings.TrimSpace(flagValue(args, "--resolution-lock", "")),
		ProcessorTimeout:   timeout,
		ProcessorSandbox:   strings.ToLower(strings.TrimSpace(flagValue(args, "--processor-sandbox", "process"))),
		LoaderCacheOnly:    strings.EqualFold(flagValue(args, "--loader-cache-only", "false"), "true"),
		EnforceGASupport:   true,
	}, nil
}

func installForgeLike(ctx context.Context, opts forgeMaterializeOptions) (forgeMaterializeResult, error) {
	var cacheErr error
	ctx, cacheErr = sharedArtifactsContext0277(ctx, opts.SharedCacheDir, opts.ClientDir)
	if cacheErr != nil {
		return forgeMaterializeResult{}, cacheErr
	}
	loader := strings.ToLower(strings.TrimSpace(opts.Loader))
	if loader != "forge" && loader != "neoforge" {
		return forgeMaterializeResult{}, fmt.Errorf("поддерживаются только Forge и NeoForge, получен %s", loader)
	}
	defaultInstallerClient := opts.HTTPClient == nil
	if defaultInstallerClient {
		opts.HTTPClient = secureHTTPClient()
	}
	// Медленные ответы Forge Maven могут передавать крупные установщики несколько минут.
	// Увеличивайте общий тайм-аут тела только для стандартного производственного клиента;
	// тестовые и предоставленные вызывающим кодом HTTP-клиенты сохраняют явно заданные ограничения.
	installerClient := opts.HTTPClient
	if defaultInstallerClient {
		extended := *opts.HTTPClient
		extended.Timeout = 8 * time.Minute
		installerClient = &extended
	}
	if opts.ProcessorTimeout <= 0 {
		opts.ProcessorTimeout = 10 * time.Minute
	}
	if err := os.MkdirAll(opts.ClientDir, 0o755); err != nil {
		return forgeMaterializeResult{}, err
	}

	vanilla, err := installVanilla(ctx, vanillaInstallOptions{
		MinecraftVersion: opts.MinecraftVersion,
		ClientDir:        opts.ClientDir,
		VersionManifest:  opts.VersionManifest,
		AssetBaseURL:     opts.AssetBaseURL,
		LibraryBaseURL:   opts.LibraryBaseURL,
		Targets:          opts.Targets,
		Workers:          opts.Workers,
		StrictUpstream:   opts.StrictUpstream,
		HTTPClient:       opts.HTTPClient,
	})
	if err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("%s base Vanilla: %w", loader, err)
	}
	if opts.EnforceGASupport && compatibilityLoaderGA0180Required(version) {
		if _, err := enforceLoaderGASupport0180(loader, vanilla.MinecraftVersion, vanilla.JavaMajorVersion); err != nil {
			return forgeMaterializeResult{}, err
		}
	}

	lockPath := opts.ResolutionLockPath
	if lockPath == "" {
		lockPath = defaultLoaderResolutionLockPath(opts.ClientDir, loader)
	}
	pinned, err := readLoaderResolutionLock(lockPath, loader, vanilla.MinecraftVersion, opts.LoaderVersion)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	var loaderVersion, artifactVersion, metadataURL, resolutionSourceSHA256 string
	if pinned != nil {
		loaderVersion = pinned.ResolvedVersion
		artifactVersion = pinned.ArtifactVersion
		metadataURL = pinned.ResolutionSourceURL
		resolutionSourceSHA256 = pinned.ResolutionSourceSHA256
		if artifactVersion == "" {
			return forgeMaterializeResult{}, errors.New("loader resolution lock не содержит Forge/NeoForge artifactVersion")
		}
	} else {
		loaderVersion, artifactVersion, metadataURL, resolutionSourceSHA256, err = resolveForgeLikeVersionWithEvidence(ctx, opts.HTTPClient, loader, vanilla.MinecraftVersion, opts.LoaderVersion, opts.MavenMetadataURL)
		if err != nil {
			return forgeMaterializeResult{}, err
		}
	}
	installerURL := opts.InstallerURL
	if installerURL == "" {
		installerURL = forgeInstallerURL(loader, vanilla.MinecraftVersion, artifactVersion)
	}
	if err := validateRemoteURL(installerURL); err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("installer URL: %w", err)
	}
	installerRel := filepath.ToSlash(filepath.Join(".launcher", "installers", loader, sanitizeVersionToken(artifactVersion), "installer.jar"))
	installerPath, err := secureClientDestination(opts.ClientDir, installerRel)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	installerSHA1 := strings.ToLower(strings.TrimSpace(opts.InstallerSHA1))
	// The verified local installer is a cache source, not an alternate runtime
	// identity: the canonical upstream URL remains in the resolution lock.
	// Never accept an unpinned local installer or use it to defeat a pinned lock.
	if opts.InstallerSourceFile != "" {
		if !isSHA256Hex0271(opts.InstallerSourceSHA256) {
			return forgeMaterializeResult{}, errors.New("local installer requires exact --installer-sha256")
		}
		if _, err := mirrorCheckedHash0274(opts.InstallerSourceFile, opts.InstallerSourceSHA256); err != nil {
			return forgeMaterializeResult{}, err
		}
		if pinned != nil && !strings.EqualFold(pinned.PayloadSHA256, opts.InstallerSourceSHA256) {
			return forgeMaterializeResult{}, errors.New("local installer differs from pinned installer")
		}
		sha1sum, _, _, err := hashFileSHA1SHA256(opts.InstallerSourceFile)
		if err != nil {
			return forgeMaterializeResult{}, err
		}
		if installerSHA1 != "" && !strings.EqualFold(installerSHA1, sha1sum) {
			return forgeMaterializeResult{}, errors.New("local installer SHA-1 mismatch")
		}
		installerSHA1 = sha1sum
		if _, err := os.Lstat(installerPath); errors.Is(err, os.ErrNotExist) {
			if err := copyFileAtomic(opts.InstallerSourceFile, installerPath); err != nil {
				return forgeMaterializeResult{}, err
			}
		} else if err != nil {
			return forgeMaterializeResult{}, err
		}
	}

	installerCacheHit := false
	upstreamRecoveryUsed := false
	var installerFile vanillaDownloadedFile

	if pinned != nil {
		if pinned.PayloadURL != installerURL {
			return forgeMaterializeResult{}, fmt.Errorf("loader resolution lock payload URL mismatch: pinned %s got %s", pinned.PayloadURL, installerURL)
		}
		if ok, sha256sum, size := existingFileMatchesSHA256(installerPath, pinned.PayloadSHA256); ok {
			sha1sum, _, _, hashErr := hashFileSHA1SHA256(installerPath)
			if hashErr != nil {
				return forgeMaterializeResult{}, hashErr
			}
			installerFile = vanillaDownloadedFile{Path: installerRel, Kind: loader + "-installer", Size: size, SHA1: sha1sum, SHA256: sha256sum, Cached: true}
			installerCacheHit = true
		} else {
			if _, statErr := os.Lstat(installerPath); statErr == nil {
				if _, qErr := quarantineCompatibilityArtifact(opts.ClientDir, installerRel, "pinned installer failed resolution-lock SHA-256 verification"); qErr != nil {
					return forgeMaterializeResult{}, qErr
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return forgeMaterializeResult{}, statErr
			}
			if restored, restoreErr := restorePinnedInstallerFromCache(opts.ClientDir, loader, vanilla.MinecraftVersion, installerURL, pinned.PayloadSHA256, installerPath); restoreErr == nil {
				installerFile = restored
				installerCacheHit = true
				upstreamRecoveryUsed = true
			} else {
				if opts.LoaderCacheOnly {
					return forgeMaterializeResult{}, fmt.Errorf("%s cache-only installer recovery: %w", loader, restoreErr)
				}
				downloaded, downloadErr := downloadPinnedSHA256Artifact(ctx, installerClient, opts.ClientDir, installerRel, installerURL, pinned.PayloadSHA256, loader+"-installer", maxCompatibilityArtifact)
				if downloadErr != nil {
					return forgeMaterializeResult{}, fmt.Errorf("%s pinned installer download: %w", loader, downloadErr)
				}
				if _, cacheErr := storeLoaderPayloadCacheFile(opts.ClientDir, loader, vanilla.MinecraftVersion, installerURL, installerPath, pinned.PayloadSHA256); cacheErr != nil {
					return forgeMaterializeResult{}, fmt.Errorf("%s pinned installer cache commit: %w", loader, cacheErr)
				}
				installerFile = downloaded
			}
		}
		installerSHA1 = installerFile.SHA1
	} else {
		if opts.LoaderCacheOnly {
			return forgeMaterializeResult{}, errors.New("loader cache-only mode требует существующий immutable resolution lock")
		}
		if installerSHA1 == "" {
			shaBytes, shaErr := fetchLimitedBytes(ctx, opts.HTTPClient, installerURL+".sha1", 64<<10)
			if shaErr != nil {
				if opts.StrictUpstream {
					return forgeMaterializeResult{}, fmt.Errorf("%s installer SHA-1: %w", loader, shaErr)
				}
			} else {
				installerSHA1 = parseSHA1Sidecar(string(shaBytes))
			}
		}
		if opts.StrictUpstream && !validSHA1Hex(installerSHA1) {
			return forgeMaterializeResult{}, fmt.Errorf("%s installer не имеет корректного upstream SHA-1", loader)
		}
		if installerSHA1 != "" && !validSHA1Hex(installerSHA1) {
			return forgeMaterializeResult{}, fmt.Errorf("%s installer SHA-1 некорректен", loader)
		}
		installerFile, err = downloadForgeInstallerRecoveringTransport(ctx, installerClient, vanillaDownloadTask{Path: installerRel, URL: installerURL, SHA1: installerSHA1, Kind: loader + "-installer"}, opts.ClientDir)
		if err != nil {
			return forgeMaterializeResult{}, fmt.Errorf("%s installer download: %w", loader, err)
		}
		if _, err := storeLoaderPayloadCacheFile(opts.ClientDir, loader, vanilla.MinecraftVersion, installerURL, installerPath, installerFile.SHA256); err != nil {
			return forgeMaterializeResult{}, fmt.Errorf("%s installer cache commit: %w", loader, err)
		}
	}
	if err := assertPinnedPayloadSHA256(pinned, installerURL, installerFile.SHA256); err != nil {
		return forgeMaterializeResult{}, err
	}
	bundle, err := inspectForgeInstaller(installerPath)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	if bundle.Legacy {
		if loader != "forge" {
			return forgeMaterializeResult{}, fmt.Errorf("%s legacy universal installer format не поддерживается", loader)
		}
		legacyOpts := opts
		legacyOpts.ResolutionSourceSHA256 = resolutionSourceSHA256
		return installForgeLegacy(ctx, legacyOpts, vanilla, loaderVersion, artifactVersion, metadataURL, installerURL, installerSHA1, installerFile, installerPath, bundle, installerCacheHit, upstreamRecoveryUsed)
	}
	// Forge использует spec=0 для классического формата установщика 1.13+ на основе
	// процессоров; NeoForge унаследовал этот формат и может задавать новые значения
	// spec. Реальный критерий производственной обработки — наличие version.json и
	// метаданных процессоров, а не произвольный минимальный номер spec.
	if bundle.Profile.JSON == "" && bundle.Profile.Version == "" {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer profile не содержит version/json metadata; legacy pre-1.13 installer format в текущем compatibility release не поддерживается", loader)
	}
	if bundle.Profile.Minecraft == "" {
		bundle.Profile.Minecraft = vanilla.MinecraftVersion
	}
	if bundle.Profile.Minecraft != vanilla.MinecraftVersion {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer предназначен для Minecraft %s, выбран %s", loader, bundle.Profile.Minecraft, vanilla.MinecraftVersion)
	}
	if bundle.Version.InheritsFrom == "" {
		bundle.Version.InheritsFrom = vanilla.MinecraftVersion
	}
	if bundle.Version.InheritsFrom != vanilla.MinecraftVersion {
		return forgeMaterializeResult{}, fmt.Errorf("%s version profile inheritsFrom=%s, ожидался %s", loader, bundle.Version.InheritsFrom, vanilla.MinecraftVersion)
	}
	if bundle.Version.ID == "" || bundle.Version.MainClass == "" {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer version.json не содержит id/mainClass", loader)
	}
	if err := validateLoaderProfileID(bundle.Version.ID); err != nil {
		return forgeMaterializeResult{}, err
	}
	clientProcessorCount := 0
	for _, processor := range bundle.Profile.Processors {
		if processorAppliesToClient(processor.Sides) {
			clientProcessorCount++
		}
	}
	if clientProcessorCount == 0 {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer не содержит client processors; поддерживается только processor-based modern installer format", loader)
	}

	javaPath, err := selectInstallerJava(opts.JavaExecutable, vanilla.JavaMajorVersion)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	installerDataRel := filepath.ToSlash(filepath.Join(".launcher", "installers", loader, sanitizeVersionToken(artifactVersion), "data"))
	installerDataDir, err := secureClientDestination(opts.ClientDir, installerDataRel)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	// Данные установщика — воспроизводимое временное состояние. Очищайте его при каждом запуске, чтобы
	// устаревшие входы процессора или оставшиеся символические ссылки не переживали повторную материализацию.
	if err := os.RemoveAll(installerDataDir); err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("installer data cleanup: %w", err)
	}
	if err := os.MkdirAll(installerDataDir, 0o755); err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("installer data create: %w", err)
	}
	if err := extractInstallerData(installerPath, installerDataDir, &bundle.Profile); err != nil {
		return forgeMaterializeResult{}, err
	}

	files := make([]vanillaDownloadedFile, 0)
	embeddedFiles, err := extractEmbeddedMaven(installerPath, opts.ClientDir)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	files = append(files, embeddedFiles...)

	profileFiles, err := materializeForgeLibraries(ctx, opts.HTTPClient, opts.ClientDir, &bundle.Profile.Libraries, loader, opts.Workers, opts.StrictUpstream, opts.Targets...)
	if err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer libraries: %w", loader, err)
	}
	files = append(files, profileFiles...)

	stats, err := runForgeProcessors(ctx, forgeProcessorContext{
		Loader:           loader,
		MinecraftVersion: vanilla.MinecraftVersion,
		ClientDir:        opts.ClientDir,
		InstallerPath:    installerPath,
		InstallerDataDir: installerDataDir,
		JavaExecutable:   javaPath,
		Profile:          &bundle.Profile,
		Timeout:          opts.ProcessorTimeout,
		StrictSandbox:    opts.ProcessorSandbox == "required",
	})
	if err != nil {
		return forgeMaterializeResult{}, err
	}

	versionFiles, err := materializeForgeLibraries(ctx, opts.HTTPClient, opts.ClientDir, &bundle.Version.Libraries, loader, opts.Workers, opts.StrictUpstream, opts.Targets...)
	if err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("%s runtime libraries: %w", loader, err)
	}
	files = append(files, versionFiles...)

	profileBytes, err := json.MarshalIndent(bundle.Version, "", "  ")
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	profileBytes = append(profileBytes, '\n')
	profilePath := filepath.ToSlash(filepath.Join("versions", bundle.Version.ID, bundle.Version.ID+".json"))
	profileDest, err := secureClientDestination(opts.ClientDir, profilePath)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	if err := writeAtomicBytes(profileDest, profileBytes, 0o644); err != nil {
		return forgeMaterializeResult{}, err
	}
	profileSHA := sha256.Sum256(profileBytes)
	profileSHA256 := hex.EncodeToString(profileSHA[:])
	if err := assertPinnedRuntimeProfile(pinned, profileSHA256); err != nil {
		return forgeMaterializeResult{}, err
	}
	files = append(files, vanillaDownloadedFile{Path: profilePath, Kind: loader + "-profile", Size: int64(len(profileBytes)), SHA256: profileSHA256})
	files = dedupeDownloadedFiles(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	materializationSHA256 := loaderMaterializationSHA256(files)
	if err := assertPinnedMaterialization(pinned, materializationSHA256); err != nil {
		return forgeMaterializeResult{}, err
	}
	selectorForLock := opts.LoaderVersion
	if pinned != nil {
		selectorForLock = pinned.Selector
	}
	resolution := loaderResolutionLock{
		SchemaVersion: loaderResolutionLockSchema, Loader: loader, MinecraftVersion: vanilla.MinecraftVersion, Selector: selectorForLock,
		ResolvedVersion: loaderVersion, ArtifactVersion: artifactVersion, ResolutionSourceURL: metadataURL, ResolutionSourceSHA256: resolutionSourceSHA256,
		PayloadURL: installerURL, PayloadSHA256: installerFile.SHA256, RuntimeProfileSHA256: profileSHA256, MaterializationSHA256: materializationSHA256,
	}
	resolution, resolutionLockSHA256, err := persistLoaderResolutionLock(lockPath, resolution)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	downloaded, cached := 0, 0
	var total int64
	for _, file := range files {
		if file.Cached {
			cached++
		} else {
			downloaded++
		}
		total += file.Size
	}
	state := map[string]any{
		"schemaVersion": "1.0", "toolVersion": version, "loader": loader,
		"minecraftVersion": vanilla.MinecraftVersion, "loaderVersion": loaderVersion,
		"artifactVersion": artifactVersion, "profileId": bundle.Version.ID, "profilePath": profilePath,
		"profileSha256": profileSHA256, "installerUrl": installerURL,
		"installerSha1": installerSHA1, "installerSha256": installerFile.SHA256, "installMode": "processors",
		"mavenMetadata": metadataURL, "resolutionLockPath": filepath.ToSlash(lockPath), "resolutionLockSha256": resolutionLockSHA256,
		"resolutionSourceUrl": metadataURL, "resolutionSourceSha256": resolutionSourceSHA256, "materializationSha256": materializationSHA256, "reproducibilitySha256": resolution.ReproducibilitySHA256, "resolutionPinned": pinned != nil,
		"clientProcessorCount": clientProcessorCount, "processorRan": stats.Ran, "processorSkipped": stats.Skipped,
		"processorRecovered": stats.Recovered, "processorJournalPath": stats.JournalPath, "processorJournalSha256": stats.JournalSHA256, "processorJournalRebuilt": stats.JournalRebuilt,
		"loaderCacheOnly": opts.LoaderCacheOnly, "installerCacheHit": installerCacheHit, "upstreamRecoveryUsed": upstreamRecoveryUsed,
		"status": "installed-and-verified",
	}
	stateBytes, _ := json.MarshalIndent(state, "", "  ")
	statePath, err := secureClientDestination(opts.ClientDir, filepath.ToSlash(filepath.Join(".launcher", loader+"-install.json")))
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	if err := writeAtomicBytes(statePath, append(stateBytes, '\n'), 0o600); err != nil {
		return forgeMaterializeResult{}, err
	}

	return forgeMaterializeResult{
		SchemaVersion: "1.0", ToolVersion: version, Loader: loader,
		MinecraftVersion: vanilla.MinecraftVersion, LoaderVersion: loaderVersion, ArtifactVersion: artifactVersion,
		ProfileID: bundle.Version.ID, ProfilePath: profilePath, MainClass: bundle.Version.MainClass,
		ClientDir: opts.ClientDir, JavaMajorVersion: vanilla.JavaMajorVersion,
		InstallerSHA1: installerSHA1, InstallerSHA256: installerFile.SHA256, InstallMode: "processors",
		ProcessorCount: len(bundle.Profile.Processors), ClientProcessorCount: clientProcessorCount, ProcessorRan: stats.Ran, ProcessorSkipped: stats.Skipped,
		ProcessorRecovered: stats.Recovered, ProcessorJournalPath: stats.JournalPath, ProcessorJournalSHA256: stats.JournalSHA256, ProcessorJournalRebuilt: stats.JournalRebuilt,
		LibraryCount: len(bundle.Profile.Libraries) + len(bundle.Version.Libraries), Downloaded: downloaded, Cached: cached,
		TotalBytes: total, ProfileSHA256: profileSHA256,
		ResolutionLockPath: filepath.ToSlash(lockPath), ResolutionLockSHA256: resolutionLockSHA256, ResolutionSourceURL: metadataURL, ResolutionSourceSHA256: resolutionSourceSHA256, MaterializationSHA256: materializationSHA256, ReproducibilitySHA256: resolution.ReproducibilitySHA256, ResolutionPinned: pinned != nil,
		LoaderCacheOnly: opts.LoaderCacheOnly, InstallerCacheHit: installerCacheHit, UpstreamRecoveryUsed: upstreamRecoveryUsed,
		Vanilla: vanilla, Files: files, Status: "installed-and-verified",
	}, nil
}

func installForgeLegacy(
	ctx context.Context,
	opts forgeMaterializeOptions,
	vanilla vanillaInstallResult,
	loaderVersion, artifactVersion, metadataURL, installerURL, installerSHA1 string,
	installerFile vanillaDownloadedFile,
	installerPath string,
	bundle installerBundle,
	hardening ...bool,
) (forgeMaterializeResult, error) {
	installerCacheHit := len(hardening) > 0 && hardening[0]
	upstreamRecoveryUsed := len(hardening) > 1 && hardening[1]
	lockPath := opts.ResolutionLockPath
	if lockPath == "" {
		lockPath = defaultLoaderResolutionLockPath(opts.ClientDir, "forge")
	}
	pinned, err := readLoaderResolutionLock(lockPath, "forge", vanilla.MinecraftVersion, opts.LoaderVersion)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	resolutionSourceSHA256 := strings.ToLower(strings.TrimSpace(opts.ResolutionSourceSHA256))
	if pinned != nil {
		resolutionSourceSHA256 = pinned.ResolutionSourceSHA256
	} else if resolutionSourceSHA256 == "" {
		_, resolutionSourceSHA256 = explicitResolutionSource("forge", vanilla.MinecraftVersion, opts.LoaderVersion, loaderVersion, artifactVersion)
	}
	expectedTweaker := ""
	allowedModes := map[string]bool{}
	switch vanilla.MinecraftVersion {
	case "1.7.10":
		expectedTweaker = "cpw.mods.fml.common.launcher.FMLTweaker"
		allowedModes["legacy-v1-universal"] = true
	case "1.12.2":
		expectedTweaker = "net.minecraftforge.fml.common.launcher.FMLTweaker"
		allowedModes["legacy-v1-universal"] = true
		allowedModes["legacy-v2-empty-processors"] = true
	default:
		return forgeMaterializeResult{}, fmt.Errorf("Forge legacy compatibility поддерживает Minecraft 1.7.10 и 1.12.2, получен %s", vanilla.MinecraftVersion)
	}
	if vanilla.JavaMajorVersion != 8 {
		return forgeMaterializeResult{}, fmt.Errorf("Forge legacy %s требует Java 8, materializer получил Java %d", vanilla.MinecraftVersion, vanilla.JavaMajorVersion)
	}
	if !allowedModes[bundle.LegacyMode] {
		return forgeMaterializeResult{}, fmt.Errorf("Forge legacy %s не поддерживает install mode %q", vanilla.MinecraftVersion, bundle.LegacyMode)
	}
	profileNormalized := false
	if bundle.Version.InheritsFrom == "" {
		bundle.Version.InheritsFrom = vanilla.MinecraftVersion
		profileNormalized = true
	}
	if bundle.Version.InheritsFrom != vanilla.MinecraftVersion {
		return forgeMaterializeResult{}, fmt.Errorf("Forge legacy profile inheritsFrom=%s, ожидался %s", bundle.Version.InheritsFrom, vanilla.MinecraftVersion)
	}
	if bundle.Version.ID == "" || bundle.Version.MainClass == "" {
		return forgeMaterializeResult{}, errors.New("Forge legacy runtime profile не содержит id/mainClass")
	}
	if err := validateLoaderProfileID(bundle.Version.ID); err != nil {
		return forgeMaterializeResult{}, err
	}
	if bundle.Version.MainClass != "net.minecraft.launchwrapper.Launch" {
		return forgeMaterializeResult{}, fmt.Errorf("Forge %s legacy profile mainClass=%s, ожидался net.minecraft.launchwrapper.Launch", vanilla.MinecraftVersion, bundle.Version.MainClass)
	}
	if !legacyMinecraftArgumentsContainTweaker(bundle.Version.MinecraftArgs, expectedTweaker) {
		return forgeMaterializeResult{}, fmt.Errorf("Forge %s legacy profile не содержит --tweakClass %s", vanilla.MinecraftVersion, expectedTweaker)
	}

	files := make([]vanillaDownloadedFile, 0, len(bundle.Version.Libraries)+4)
	universalCoord := strings.TrimSpace(bundle.Profile.Path)
	if bundle.LegacyMode == "legacy-v1-universal" {
		if bundle.LegacyInstall.Minecraft != vanilla.MinecraftVersion {
			return forgeMaterializeResult{}, fmt.Errorf("legacy Forge installer предназначен для Minecraft %s, выбран %s", bundle.LegacyInstall.Minecraft, vanilla.MinecraftVersion)
		}
		universalCoord = strings.TrimSpace(bundle.LegacyInstall.Path)
	}
	if universalCoord == "" {
		return forgeMaterializeResult{}, fmt.Errorf("Forge %s legacy installer не содержит Maven coordinate universal JAR", vanilla.MinecraftVersion)
	}
	universalRel, err := mavenCoordinatePath(universalCoord)
	if err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("Forge legacy universal coordinate: %w", err)
	}
	universalDestRel := "libraries/" + universalRel
	universalDest, err := secureClientDestination(opts.ClientDir, universalDestRel)
	if err != nil {
		return forgeMaterializeResult{}, err
	}

	if bundle.LegacyMode == "legacy-v1-universal" {
		entry := strings.TrimPrefix(strings.ReplaceAll(strings.TrimSpace(bundle.LegacyInstall.FilePath), "\\", "/"), "/")
		if entry == "" {
			return forgeMaterializeResult{}, errors.New("legacy Forge install.filePath пуст")
		}
		if _, err := safeArchiveRelative(entry); err != nil {
			return forgeMaterializeResult{}, fmt.Errorf("legacy Forge universal entry: %w", err)
		}
		if err := extractInstallerEntry(installerPath, entry, universalDest); err != nil {
			return forgeMaterializeResult{}, fmt.Errorf("extract Forge legacy universal JAR: %w", err)
		}
	} else if bundle.LegacyMode == "legacy-v2-empty-processors" {
		embedded, err := extractEmbeddedMaven(installerPath, opts.ClientDir)
		if err != nil {
			return forgeMaterializeResult{}, err
		}
		files = append(files, embedded...)
		if _, err := os.Stat(universalDest); err != nil {
			// Некоторые перепакованные установщики указывают универсальный
			// артефакт в профиле, но не включают его внутрь. Перед отказом
			// установки загрузите библиотеки профиля по авторитетным Maven URL.
			profileFiles, materializeErr := materializeForgeLibraries(ctx, opts.HTTPClient, opts.ClientDir, &bundle.Profile.Libraries, "forge", opts.Workers, opts.StrictUpstream)
			if materializeErr != nil {
				return forgeMaterializeResult{}, fmt.Errorf("Forge legacy profile libraries: %w", materializeErr)
			}
			files = append(files, profileFiles...)
		}
		if _, err := os.Stat(universalDest); err != nil {
			return forgeMaterializeResult{}, fmt.Errorf("Forge 1.12.2 empty-processor installer не материализовал universal JAR %s", universalDestRel)
		}
	} else {
		return forgeMaterializeResult{}, fmt.Errorf("неизвестный Forge legacy install mode %q", bundle.LegacyMode)
	}

	universalSHA1, universalSHA256, universalSize, err := hashFileSHA1SHA256(universalDest)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	if err := verifyForgeLegacyUniversal(ctx, opts.HTTPClient, universalCoord, universalRel, universalSHA1, bundle, opts.StrictUpstream, validSHA1Hex(installerSHA1) && bundle.LegacyMode == "legacy-v1-universal"); err != nil {
		return forgeMaterializeResult{}, err
	}
	files = append(files, vanillaDownloadedFile{
		Path: universalDestRel, Kind: "forge-legacy-universal", Size: universalSize,
		SHA1: universalSHA1, SHA256: universalSHA256,
	})

	versionFiles, err := materializeForgeLibraries(ctx, opts.HTTPClient, opts.ClientDir, &bundle.Version.Libraries, "forge", opts.Workers, opts.StrictUpstream)
	if err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("Forge legacy runtime libraries: %w", err)
	}
	files = append(files, versionFiles...)

	profileBytes, normalizedRaw, err := normalizeForgeLegacyRuntimeProfile(bundle.VersionRaw, bundle.Version, vanilla.MinecraftVersion)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	profileNormalized = profileNormalized || normalizedRaw
	profileBytes = append(profileBytes, '\n')
	profilePath := filepath.ToSlash(filepath.Join("versions", bundle.Version.ID, bundle.Version.ID+".json"))
	profileDest, err := secureClientDestination(opts.ClientDir, profilePath)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	if err := writeAtomicBytes(profileDest, profileBytes, 0o644); err != nil {
		return forgeMaterializeResult{}, err
	}
	profileSHA := sha256.Sum256(profileBytes)
	profileSHA256 := hex.EncodeToString(profileSHA[:])
	if err := assertPinnedRuntimeProfile(pinned, profileSHA256); err != nil {
		return forgeMaterializeResult{}, err
	}
	files = append(files, vanillaDownloadedFile{Path: profilePath, Kind: "forge-legacy-profile", Size: int64(len(profileBytes)), SHA256: profileSHA256})
	files = dedupeDownloadedFiles(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	materializationSHA256 := loaderMaterializationSHA256(files)
	if err := assertPinnedMaterialization(pinned, materializationSHA256); err != nil {
		return forgeMaterializeResult{}, err
	}
	selectorForLock := opts.LoaderVersion
	if pinned != nil {
		selectorForLock = pinned.Selector
	}
	resolution := loaderResolutionLock{
		SchemaVersion: loaderResolutionLockSchema, Loader: "forge", MinecraftVersion: vanilla.MinecraftVersion, Selector: selectorForLock,
		ResolvedVersion: loaderVersion, ArtifactVersion: artifactVersion, ResolutionSourceURL: metadataURL, ResolutionSourceSHA256: resolutionSourceSHA256,
		PayloadURL: installerURL, PayloadSHA256: installerFile.SHA256, RuntimeProfileSHA256: profileSHA256, MaterializationSHA256: materializationSHA256,
	}
	resolution, resolutionLockSHA256, err := persistLoaderResolutionLock(lockPath, resolution)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	downloaded, cached := 0, 0
	var total int64
	for _, file := range files {
		if file.Cached {
			cached++
		} else {
			downloaded++
		}
		total += file.Size
	}
	state := map[string]any{
		"schemaVersion": "1.0", "toolVersion": version, "loader": "forge",
		"minecraftVersion": vanilla.MinecraftVersion, "loaderVersion": loaderVersion,
		"artifactVersion": artifactVersion, "profileId": bundle.Version.ID, "profilePath": profilePath,
		"profileSha256": profileSHA256, "installerUrl": installerURL,
		"installerSha1": installerSHA1, "installerSha256": installerFile.SHA256,
		"mavenMetadata": metadataURL, "resolutionLockPath": filepath.ToSlash(lockPath), "resolutionLockSha256": resolutionLockSHA256,
		"resolutionSourceUrl": metadataURL, "resolutionSourceSha256": resolutionSourceSHA256, "materializationSha256": materializationSHA256, "reproducibilitySha256": resolution.ReproducibilitySHA256, "resolutionPinned": pinned != nil,
		"installMode":         bundle.LegacyMode,
		"legacyUniversalPath": universalDestRel, "legacyUniversalSha1": universalSHA1, "legacyUniversalSha256": universalSHA256,
		"legacyTweaker": expectedTweaker, "legacyBaseVersion": vanilla.MinecraftVersion, "legacyProfileNormalized": profileNormalized,
		"clientProcessorCount": 0, "processorRan": 0, "processorSkipped": 0,
		"loaderCacheOnly": opts.LoaderCacheOnly, "installerCacheHit": installerCacheHit, "upstreamRecoveryUsed": upstreamRecoveryUsed,
		"status": "installed-and-verified",
	}
	stateBytes, _ := json.MarshalIndent(state, "", "  ")
	statePath, err := secureClientDestination(opts.ClientDir, filepath.ToSlash(filepath.Join(".launcher", "forge-install.json")))
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	if err := writeAtomicBytes(statePath, append(stateBytes, '\n'), 0o600); err != nil {
		return forgeMaterializeResult{}, err
	}

	return forgeMaterializeResult{
		SchemaVersion: "1.0", ToolVersion: version, Loader: "forge",
		MinecraftVersion: vanilla.MinecraftVersion, LoaderVersion: loaderVersion, ArtifactVersion: artifactVersion,
		ProfileID: bundle.Version.ID, ProfilePath: profilePath, MainClass: bundle.Version.MainClass,
		ClientDir: opts.ClientDir, JavaMajorVersion: vanilla.JavaMajorVersion,
		InstallerSHA1: installerSHA1, InstallerSHA256: installerFile.SHA256, InstallMode: bundle.LegacyMode,
		LegacyUniversalPath: universalDestRel, LegacyUniversalSHA1: universalSHA1, LegacyUniversalSHA256: universalSHA256,
		LegacyTweaker: expectedTweaker, LegacyBaseVersion: vanilla.MinecraftVersion, LegacyProfileNormalized: profileNormalized,
		ProcessorCount: 0, ClientProcessorCount: 0, ProcessorRan: 0, ProcessorSkipped: 0,
		LibraryCount: len(bundle.Version.Libraries), Downloaded: downloaded, Cached: cached,
		TotalBytes: total, ProfileSHA256: profileSHA256,
		ResolutionLockPath: filepath.ToSlash(lockPath), ResolutionLockSHA256: resolutionLockSHA256, ResolutionSourceURL: metadataURL, ResolutionSourceSHA256: resolutionSourceSHA256, MaterializationSHA256: materializationSHA256, ReproducibilitySHA256: resolution.ReproducibilitySHA256, ResolutionPinned: pinned != nil,
		LoaderCacheOnly: opts.LoaderCacheOnly, InstallerCacheHit: installerCacheHit, UpstreamRecoveryUsed: upstreamRecoveryUsed,
		Vanilla: vanilla, Files: files, Status: "installed-and-verified",
	}, nil
}

func legacyMinecraftArgumentsContainTweaker(arguments, expected string) bool {
	fields := strings.Fields(arguments)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--tweakClass" && fields[i+1] == expected {
			return true
		}
	}
	return false
}

func normalizeForgeLegacyRuntimeProfile(raw []byte, profile loaderVersionProfile, parent string) ([]byte, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		profile.InheritsFrom = parent
		out, err := json.MarshalIndent(profile, "", "  ")
		return out, true, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return nil, false, fmt.Errorf("Forge legacy versionInfo JSON повреждён: %w", err)
	}
	normalized := false
	var inherited string
	if value, ok := object["inheritsFrom"]; ok {
		_ = json.Unmarshal(value, &inherited)
	}
	if strings.TrimSpace(inherited) == "" {
		encoded, _ := json.Marshal(parent)
		object["inheritsFrom"] = encoded
		normalized = true
	} else if inherited != parent {
		return nil, false, fmt.Errorf("Forge legacy versionInfo inheritsFrom=%s, ожидался %s", inherited, parent)
	} else {
		// Профиль, уже наследующий правильную версию Vanilla, тоже
		// нормализуется. Флаг описывает итоговый инвариант, а не
		// факт перезаписи JSON во время текущей материализации.
		return append([]byte(nil), trimmed...), true, nil
	}
	out, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return out, normalized, nil
}

func canonicalLegacyForgeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(parsed.Hostname())
	cleanPath := strings.TrimRight(parsed.EscapedPath(), "/")
	if host == "files.minecraftforge.net" && (cleanPath == "" || cleanPath == "/maven") {
		return defaultForgeMavenBase
	}
	if host == "maven.minecraftforge.net" && parsed.Scheme == "http" {
		parsed.Scheme = "https"
		return strings.TrimRight(parsed.String(), "/")
	}
	return raw
}

func extractInstallerEntry(installerPath, entryName, destination string) error {
	zr, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	wanted := strings.TrimPrefix(strings.ReplaceAll(entryName, "\\", "/"), "/")
	for _, entry := range zr.File {
		name := strings.TrimPrefix(strings.ReplaceAll(entry.Name, "\\", "/"), "/")
		if name != wanted {
			continue
		}
		if strings.HasSuffix(name, "/") || entry.UncompressedSize64 > 1<<30 {
			return fmt.Errorf("installer entry %s недопустим", wanted)
		}
		return copyZipEntryAtomic(entry, destination)
	}
	return fmt.Errorf("installer entry %s отсутствует", wanted)
}

func verifyForgeLegacyUniversal(ctx context.Context, client *http.Client, coordinate, rel, actualSHA1 string, bundle installerBundle, strict, authenticatedEmbeddedInstaller bool) error {
	acceptable := map[string]bool{}
	baseURL := ""
	for _, lib := range append(append([]MojangLibrary(nil), bundle.Profile.Libraries...), bundle.Version.Libraries...) {
		if strings.TrimSpace(lib.Name) != strings.TrimSpace(coordinate) {
			continue
		}
		if value := strings.ToLower(strings.TrimSpace(lib.Downloads.Artifact.SHA1)); validSHA1Hex(value) {
			acceptable[value] = true
		}
		for _, value := range lib.Checksums {
			value = strings.ToLower(strings.TrimSpace(value))
			if validSHA1Hex(value) {
				acceptable[value] = true
			}
		}
		if strings.TrimSpace(lib.URL) != "" {
			baseURL = strings.TrimRight(canonicalLegacyForgeURL(strings.TrimSpace(lib.URL)), "/")
		}
	}
	if len(acceptable) > 0 {
		if !acceptable[strings.ToLower(actualSHA1)] {
			return fmt.Errorf("Forge legacy universal JAR SHA-1 mismatch: %s", actualSHA1)
		}
		return nil
	}
	if baseURL == "" {
		baseURL = defaultForgeMavenBase
	}
	shaURL := baseURL + "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/") + ".sha1"
	shaBytes, err := fetchLimitedBytes(ctx, client, shaURL, 64<<10)
	if err != nil {
		// Некоторые официальные артефакты Forge 1.7.10 в Maven больше не
		// публикуют сопутствующий файл .sha1 для универсального JAR. Он
		// извлекается непосредственно из скачанного установщика, чей SHA-1
		// уже проверил downloadVanillaArtifact. Только в этом узком случае
		// проверенный установщик служит подтверждением целостности ZIP-записи.
		// При иных отсутствующих хешах, сетевых сбоях или перепакованных
		// установщиках операция должна завершаться отказом.
		if authenticatedEmbeddedInstaller && strings.Contains(err.Error(), "HTTP 404") {
			return nil
		}
		if strict {
			return fmt.Errorf("Forge legacy universal SHA-1 sidecar: %w", err)
		}
		return nil
	}
	expected := parseSHA1Sidecar(string(shaBytes))
	if !validSHA1Hex(expected) {
		if strict {
			return errors.New("Forge legacy universal SHA-1 sidecar некорректен")
		}
		return nil
	}
	if !strings.EqualFold(expected, actualSHA1) {
		return fmt.Errorf("Forge legacy universal JAR SHA-1 mismatch: expected %s got %s", expected, actualSHA1)
	}
	return nil
}

func resolveForgeLikeVersion(ctx context.Context, client *http.Client, loader, minecraftVersion, requested, metadataOverride string) (string, string, string, error) {
	loaderVersion, artifactVersion, sourceURL, _, err := resolveForgeLikeVersionWithEvidence(ctx, client, loader, minecraftVersion, requested, metadataOverride)
	return loaderVersion, artifactVersion, sourceURL, err
}

func resolveForgeLikeVersionWithEvidence(ctx context.Context, client *http.Client, loader, minecraftVersion, requested, metadataOverride string) (string, string, string, string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = "latest-stable"
	}
	if !isMutableLoaderSelector(requested) {
		if err := validateForgeLikeVersionToken0272(requested); err != nil {
			return "", "", "", "", fmt.Errorf("invalid explicit %s version: %w", loader, err)
		}
	}
	metadataURL := strings.TrimSpace(metadataOverride)
	legacyNeoForge1201 := loader == "neoforge" && minecraftVersion == "1.20.1"
	if metadataURL == "" {
		if loader == "forge" {
			metadataURL = defaultForgeMavenBase + "/net/minecraftforge/forge/maven-metadata.xml"
		} else if legacyNeoForge1201 {
			metadataURL = defaultNeoForgeMavenBase + "/net/neoforged/forge/maven-metadata.xml"
		} else {
			metadataURL = defaultNeoForgeMavenBase + "/net/neoforged/neoforge/maven-metadata.xml"
		}
	}
	if requested != "latest" && requested != "latest-stable" && requested != "stable" && requested != "recommended" {
		if loader == "forge" {
			artifact := requested
			if !strings.HasPrefix(artifact, minecraftVersion+"-") {
				artifact = minecraftVersion + "-" + requested
			}
			resolved := strings.TrimPrefix(artifact, minecraftVersion+"-")
			sourceURL, sourceSHA := explicitResolutionSource(loader, minecraftVersion, requested, resolved, artifact)
			return resolved, artifact, sourceURL, sourceSHA, nil
		}
		if legacyNeoForge1201 {
			artifact := requested
			if !strings.HasPrefix(artifact, minecraftVersion+"-") {
				artifact = minecraftVersion + "-" + requested
			}
			sourceURL, sourceSHA := explicitResolutionSource(loader, minecraftVersion, requested, artifact, artifact)
			return artifact, artifact, sourceURL, sourceSHA, nil
		}
		if !neoForgeVersionMatchesMinecraft(requested, minecraftVersion) {
			return "", "", "", "", fmt.Errorf("NeoForge version %s не совместима с Minecraft %s", requested, minecraftVersion)
		}
		sourceURL, sourceSHA := explicitResolutionSource(loader, minecraftVersion, requested, requested, requested)
		return requested, requested, sourceURL, sourceSHA, nil
	}
	allowPrerelease := requested == "latest"
	semanticAttempts := 1
	if loader == "neoforge" {
		semanticAttempts = compatibilityHTTPAttempts
	}
	var lastSelectionErr error
	for attempt := 0; attempt < semanticAttempts; attempt++ {
		fetchURL := metadataURL
		if attempt > 0 {
			fetchURL = forgeLikeMetadataRefreshURL(metadataURL, attempt)
		}
		data, err := fetchForgeLikeMetadata(ctx, client, fetchURL)
		if err != nil {
			return "", "", metadataURL, "", fmt.Errorf("%s Maven metadata: %w", loader, err)
		}
		sourceSHA := sha256HexBytes(data)
		var metadata mavenMetadataXML
		if err := xml.Unmarshal(data, &metadata); err != nil {
			return "", "", metadataURL, "", fmt.Errorf("%s Maven metadata XML повреждён: %w", loader, err)
		}
		versions := metadata.Versioning.Versions.Version
		if len(versions) == 0 {
			lastSelectionErr = fmt.Errorf("%s Maven metadata не содержит versions", loader)
		} else {
			// Метаданные Maven не гарантируют числовой порядок. Ранее выбор последней
			// подходящей строки закреплял старые Forge 38.0.0/36.0.0, чьи загрузчики
			// или ресурспаки не работают с современными средами выполнения.
			best := ""
			bestCompatiblePrerelease := ""
			for _, raw := range versions {
				candidate := strings.TrimSpace(raw)
				if candidate == "" || validateForgeLikeVersionToken0272(candidate) != nil {
					continue
				}
				matches := false
				switch {
				case loader == "forge", legacyNeoForge1201:
					matches = strings.HasPrefix(candidate, minecraftVersion+"-")
				default:
					matches = neoForgeVersionMatchesMinecraft(candidate, minecraftVersion)
				}
				if !matches {
					continue
				}
				if isPrereleaseVersion(candidate) && !allowPrerelease {
					if bestCompatiblePrerelease == "" || compareForgeLikeVersions(candidate, bestCompatiblePrerelease) > 0 {
						bestCompatiblePrerelease = candidate
					}
					continue
				}
				if best == "" || compareForgeLikeVersions(candidate, best) > 0 {
					best = candidate
				}
			}
			if best != "" {
				if loader == "forge" {
					return strings.TrimPrefix(best, minecraftVersion+"-"), best, metadataURL, sourceSHA, nil
				}
				return best, best, metadataURL, sourceSHA, nil
			}
			if bestCompatiblePrerelease != "" {
				lastSelectionErr = fmt.Errorf("%s не имеет %s версии, совместимой с Minecraft %s; upstream содержит только prerelease (например %s), который запрещён запрошенной stable-политикой", loader, requested, minecraftVersion, bestCompatiblePrerelease)
			} else {
				lastSelectionErr = fmt.Errorf("%s не имеет %s версии, совместимой с Minecraft %s", loader, requested, minecraftVersion)
			}
		}
		if attempt+1 < semanticAttempts {
			if err := sleepContext(ctx, compatibilityRetryDelay(nil, attempt)); err != nil {
				return "", "", metadataURL, "", err
			}
		}
	}
	return "", "", metadataURL, "", fmt.Errorf("%w после %d fresh metadata snapshots", lastSelectionErr, semanticAttempts)
}

// Сравнивайте числовые компоненты релизов Maven, а не строки
// лексикографически или порядок строк в удалённом индексе. Предварительные
// релизы уже отфильтрованы вызывающей стороной для latest-stable.
func compareForgeLikeVersions(a, b string) int {
	parts := func(v string) []string {
		return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	}
	x, y := parts(a), parts(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		if i >= len(x) {
			return -1
		}
		if i >= len(y) {
			return 1
		}
		ai, aErr := strconv.ParseUint(x[i], 10, 64)
		bi, bErr := strconv.ParseUint(y[i], 10, 64)
		if aErr == nil && bErr == nil {
			if ai < bi {
				return -1
			}
			if ai > bi {
				return 1
			}
			continue
		}
		if cmp := strings.Compare(x[i], y[i]); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func forgeLikeMetadataRefreshURL(metadataURL string, attempt int) string {
	u, err := url.Parse(metadataURL)
	if err != nil {
		return metadataURL
	}
	query := u.Query()
	query.Set("_launcher_refresh", fmt.Sprintf("%d-%d", time.Now().UnixNano(), attempt))
	u.RawQuery = query.Encode()
	return u.String()
}

func fetchForgeLikeMetadata(ctx context.Context, client *http.Client, metadataURL string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < compatibilityHTTPAttempts; attempt++ {
		data, err := fetchLimitedBytes(ctx, client, metadataURL, 8<<20)
		if err == nil {
			return data, nil
		}
		lastErr = err
		// Метаданные Maven иногда возвращают 404 во время согласования индексов
		// репозитория и CDN. Повторяйте только этот запрос изменяемых метаданных;
		// загрузка конкретного артефакта остаётся строгой и при 404 завершается отказом.
		if !strings.Contains(err.Error(), "HTTP 404") || attempt+1 == compatibilityHTTPAttempts {
			break
		}
		if err := sleepContext(ctx, compatibilityRetryDelay(nil, attempt)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("metadata GET failed after %d attempts: %w", compatibilityHTTPAttempts, lastErr)
}

// Функция downloadForgeInstallerRecoveringTransport повторяет только прерванные передачи
// HTTP-тела установщиков с закреплённым SHA-1. Загрузчик артефактов Vanilla хранит
// неполные байты в .nlpart и атомарно публикует лишь JAR с проверенным хешем. Частичные
// файлы с неизвестным размером при следующей попытке загружаются заново. Не повторяйте
// попытки при неверных хешах, запрещённых путях, 404 и отменённых операциях.
func downloadForgeInstallerRecoveringTransport(ctx context.Context, client *http.Client, task vanillaDownloadTask, root string) (vanillaDownloadedFile, error) {
	const attempts = 3
	for attempt := 0; attempt < attempts; attempt++ {
		file, err := downloadVanillaArtifact(ctx, client, task, root)
		if err == nil {
			return file, nil
		}
		if ctx.Err() != nil {
			return vanillaDownloadedFile{}, ctx.Err()
		}
		var networkError net.Error
		transient := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) ||
			errors.Is(err, io.EOF) || (errors.As(err, &networkError) && networkError.Timeout())
		if !validSHA1Hex(task.SHA1) || !transient || attempt == attempts-1 {
			return vanillaDownloadedFile{}, err
		}
		if sleepErr := sleepContext(ctx, compatibilityRetryDelay(nil, attempt)); sleepErr != nil {
			return vanillaDownloadedFile{}, sleepErr
		}
	}
	return vanillaDownloadedFile{}, errors.New("unreachable installer recovery state")
}

func forgeInstallerURL(loader, minecraftVersion, artifactVersion string) string {
	if loader == "forge" {
		return fmt.Sprintf("%s/net/minecraftforge/forge/%s/forge-%s-installer.jar", defaultForgeMavenBase, artifactVersion, artifactVersion)
	}
	if loader == "neoforge" && minecraftVersion == "1.20.1" {
		return fmt.Sprintf("%s/net/neoforged/forge/%s/forge-%s-installer.jar", defaultNeoForgeMavenBase, artifactVersion, artifactVersion)
	}
	return fmt.Sprintf("%s/net/neoforged/neoforge/%s/neoforge-%s-installer.jar", defaultNeoForgeMavenBase, artifactVersion, artifactVersion)
}

func neoForgeVersionMatchesMinecraft(loaderVersion, minecraftVersion string) bool {
	loaderVersion = strings.TrimSpace(loaderVersion)
	minecraftVersion = strings.TrimSpace(minecraftVersion)
	parts := strings.Split(minecraftVersion, ".")
	if len(parts) < 2 {
		return false
	}
	if parts[0] == "1" {
		// Для версий 1.20.2–1.21.11 NeoForge использует формат <mc-minor>.<mc-patch>.<build>.
		// Minecraft 1.20.1 обрабатывается отдельно: его официальный артефакт —
		// net.neoforged:forge с версиями Forge вида 1.20.1-47.1.x.
		patch := "0"
		if len(parts) >= 3 && parts[2] != "" {
			patch = parts[2]
		}
		prefix := parts[1] + "." + patch
		return strings.HasPrefix(loaderVersion, prefix+".") || loaderVersion == prefix
	}
	// Начиная с Minecraft 26.1 NeoForge включает полную версию Minecraft в собственный
	// номер версии. Если компонент исправления Minecraft отсутствует, принимается 0:
	// 26.1 -> 26.1.0.x, 26.1.1 -> 26.1.1.x, 26.2 -> 26.2.0.x.
	patch := "0"
	if len(parts) >= 3 && parts[2] != "" {
		patch = parts[2]
	}
	prefix := parts[0] + "." + parts[1] + "." + patch
	return strings.HasPrefix(loaderVersion, prefix+".") || loaderVersion == prefix
}

func isPrereleaseVersion(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "alpha") || strings.Contains(lower, "beta") || strings.Contains(lower, "-rc") || strings.Contains(lower, "snapshot")
}

func inspectForgeInstaller(installerPath string) (installerBundle, error) {
	zr, err := zip.OpenReader(installerPath)
	if err != nil {
		return installerBundle{}, fmt.Errorf("installer JAR повреждён: %w", err)
	}
	defer zr.Close()
	profileBytes, err := readZipFileLimited(&zr.Reader, "install_profile.json", 8<<20)
	if err != nil {
		return installerBundle{}, fmt.Errorf("installer не содержит корректный install_profile.json: %w", err)
	}

	// Forge <=1.12.2 V1 хранит полный манифест запуска в versionInfo, а
	// универсальный JAR — в install.filePath. Файла version.json и конвейера
	// постобработки здесь намеренно нет: FMLTweaker применяет двоичные патчи
	// из универсального JAR к унаследованному клиенту Vanilla во время запуска.
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(profileBytes, &shape); err != nil {
		return installerBundle{}, fmt.Errorf("install_profile.json повреждён: %w", err)
	}
	if _, ok := shape["versionInfo"]; ok {
		var legacy forgeLegacyInstallerProfile
		if err := json.Unmarshal(profileBytes, &legacy); err != nil {
			return installerBundle{}, fmt.Errorf("legacy install_profile.json повреждён: %w", err)
		}
		if strings.TrimSpace(legacy.Install.Path) == "" || strings.TrimSpace(legacy.Install.FilePath) == "" || strings.TrimSpace(legacy.Install.Minecraft) == "" || len(bytes.TrimSpace(legacy.VersionInfo)) == 0 {
			return installerBundle{}, errors.New("legacy Forge install_profile.json не содержит install.path/filePath/minecraft/versionInfo")
		}
		var versionProfile loaderVersionProfile
		if err := json.Unmarshal(legacy.VersionInfo, &versionProfile); err != nil {
			return installerBundle{}, fmt.Errorf("legacy Forge versionInfo повреждён: %w", err)
		}
		return installerBundle{
			Version:       versionProfile,
			VersionRaw:    append([]byte(nil), legacy.VersionInfo...),
			Legacy:        true,
			LegacyMode:    "legacy-v1-universal",
			LegacyInstall: legacy.Install,
		}, nil
	}

	var profile forgeInstallerProfile
	if err := json.Unmarshal(profileBytes, &profile); err != nil {
		return installerBundle{}, fmt.Errorf("install_profile.json повреждён: %w", err)
	}
	versionPath := strings.TrimPrefix(strings.TrimSpace(profile.JSON), "/")
	if versionPath == "" {
		versionPath = "version.json"
	}
	versionBytes, err := readZipFileLimited(&zr.Reader, versionPath, 16<<20)
	if err != nil {
		return installerBundle{}, fmt.Errorf("installer не содержит %s: %w", versionPath, err)
	}
	var versionProfile loaderVersionProfile
	if err := json.Unmarshal(versionBytes, &versionProfile); err != nil {
		return installerBundle{}, fmt.Errorf("installer version.json повреждён: %w", err)
	}
	bundle := installerBundle{
		Profile:    profile,
		Version:    versionProfile,
		VersionRaw: append([]byte(nil), versionBytes...),
		ZipPath:    versionPath,
	}

	// Современный Forge переиздаёт часть установщиков 1.12.2 в контейнере V2,
	// но с намеренно пустым конвейером процессоров и данных. Это по-прежнему
	// устаревшая модель исполнения: универсальный JAR нужно подготовить, а патчи
	// FMLTweaker накладывает в памяти. Ошибочная трактовка как современного
	// процессорного установщика незаметно создаст неработоспособный клиент.
	if profile.Minecraft == "1.12.2" && len(profile.Processors) == 0 && len(profile.Data) == 0 {
		if strings.TrimSpace(profile.Path) == "" {
			return installerBundle{}, errors.New("Forge 1.12.2 empty-processor installer не содержит path для universal JAR")
		}
		bundle.Legacy = true
		bundle.LegacyMode = "legacy-v2-empty-processors"
	}
	return bundle, nil
}

func readZipFileLimited(zr *zip.Reader, wanted string, limit int64) ([]byte, error) {
	wanted = strings.TrimPrefix(strings.ReplaceAll(wanted, "\\", "/"), "/")
	for _, entry := range zr.File {
		name := strings.TrimPrefix(strings.ReplaceAll(entry.Name, "\\", "/"), "/")
		if name != wanted {
			continue
		}
		if entry.UncompressedSize64 > uint64(limit) {
			return nil, fmt.Errorf("entry %s превышает лимит", wanted)
		}
		r, err := entry.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		data, err := io.ReadAll(io.LimitReader(r, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("entry %s превышает лимит", wanted)
		}
		return data, nil
	}
	return nil, os.ErrNotExist
}

func extractInstallerData(installerPath, targetDir string, profile *forgeInstallerProfile) error {
	if profile == nil {
		return errors.New("installer profile отсутствует")
	}
	required := map[string]bool{}
	for key, data := range profile.Data {
		value := strings.TrimSpace(data.Client)
		if value == "" || (strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")) || isQuotedInstallerLiteral(value) {
			continue
		}
		rel, err := safeArchiveRelative(strings.TrimPrefix(value, "/"))
		if err != nil {
			return fmt.Errorf("installer data %s: %w", key, err)
		}
		required[rel] = false
	}
	if len(required) == 0 {
		return nil
	}
	zr, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, entry := range zr.File {
		name := strings.TrimPrefix(strings.ReplaceAll(entry.Name, "\\", "/"), "/")
		if _, wanted := required[name]; !wanted {
			continue
		}
		if strings.HasSuffix(name, "/") {
			return fmt.Errorf("installer data %s является каталогом", name)
		}
		clean, err := safeArchiveRelative(name)
		if err != nil {
			return fmt.Errorf("installer data: %w", err)
		}
		if entry.UncompressedSize64 > 512<<20 {
			return fmt.Errorf("installer data %s превышает 512 MiB", name)
		}
		dst := filepath.Join(targetDir, filepath.FromSlash(clean))
		if err := copyZipEntryAtomic(entry, dst); err != nil {
			return err
		}
		required[name] = true
	}
	missing := make([]string, 0)
	for name, extracted := range required {
		if !extracted {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("installer не содержит client data files: %s", strings.Join(missing, ", "))
	}
	return nil
}

func isQuotedInstallerLiteral(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"'))
}

func extractEmbeddedMaven(installerPath, clientDir string) ([]vanillaDownloadedFile, error) {
	zr, err := zip.OpenReader(installerPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	files := []vanillaDownloadedFile{}
	for _, entry := range zr.File {
		name := strings.ReplaceAll(entry.Name, "\\", "/")
		if !strings.HasPrefix(name, "maven/") || strings.HasSuffix(name, "/") {
			continue
		}
		rel, err := safeArchiveRelative(strings.TrimPrefix(name, "maven/"))
		if err != nil {
			return nil, fmt.Errorf("embedded Maven path: %w", err)
		}
		if rel == "" || strings.HasSuffix(rel, ".sha1") || strings.HasSuffix(rel, ".md5") || strings.HasSuffix(rel, ".sha256") || strings.HasSuffix(rel, ".sha512") || strings.HasSuffix(rel, ".pom") {
			continue
		}
		if entry.UncompressedSize64 > 1<<30 {
			return nil, fmt.Errorf("embedded Maven artifact %s превышает 1 GiB", rel)
		}
		dstRel := filepath.ToSlash(filepath.Join("libraries", rel))
		dst, err := secureClientDestination(clientDir, dstRel)
		if err != nil {
			return nil, err
		}
		if err := copyZipEntryAtomic(entry, dst); err != nil {
			return nil, err
		}
		sha1sum, sha256sum, size, err := hashFileSHA1SHA256(dst)
		if err != nil {
			return nil, err
		}
		files = append(files, vanillaDownloadedFile{Path: dstRel, Kind: "installer-embedded-library", Size: size, SHA1: sha1sum, SHA256: sha256sum})
	}
	return files, nil
}

func safeArchiveRelative(value string) (string, error) {
	value = strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean != value {
		return "", fmt.Errorf("archive traversal path: %s", value)
	}
	return clean, nil
}

func copyZipEntryAtomic(entry *zip.File, dst string) error {
	if entry.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("installer содержит symlink: %s", entry.Name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	r, err := entry.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	tmp := dst + ".nlpart"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(r, 1<<30))
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("extract %s failed: %v %v %v", entry.Name, copyErr, syncErr, closeErr)
	}
	if err := replaceFileAtomicPortable(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func materializeForgeLibraries(ctx context.Context, client *http.Client, clientDir string, libraries *[]MojangLibrary, loader string, workers int, strict bool, selectedTargets ...vanillaTarget) ([]vanillaDownloadedFile, error) {
	if len(selectedTargets) == 0 {
		selectedTargets = []vanillaTarget{currentVanillaTarget()}
	}
	for i, target := range selectedTargets {
		normalized, err := normalizeVanillaTarget(target)
		if err != nil {
			return nil, fmt.Errorf("Forge library target[%d]: %w", i, err)
		}
		selectedTargets[i] = normalized
	}
	if libraries == nil || len(*libraries) == 0 {
		return nil, nil
	}
	if client == nil {
		client = secureHTTPClient()
	}
	tasks := []vanillaDownloadTask{}
	type forgeLibraryDownloadIdentity struct {
		SHA1 string
		URL  string
		Size int64
	}
	seen := map[string]forgeLibraryDownloadIdentity{}
	localFiles := []vanillaDownloadedFile{}
	applicable := make(map[int]bool, len(*libraries))
	for i := range *libraries {
		lib := &(*libraries)[i]
		if strings.TrimSpace(lib.Name) == "" {
			return nil, fmt.Errorf("library[%d] не содержит name", i)
		}
		if lib.ClientReq != nil && !*lib.ClientReq {
			continue
		}
		// Keep non-applicable libraries in the version profile for downstream
		// target-specific launches; do not fetch their JARs for this build.
		selected := false
		for _, target := range selectedTargets {
			if rulesAllowTarget(lib.Rules, target) && libraryArtifactAppliesToTarget(lib.Name, target) {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		applicable[i] = true
		// В versionInfo Forge 1.7.x могут повторяться координаты только нативных
		// артефактов Mojang. lwjgl-platform, jinput-platform и старые мосты платформы
		// Twitch содержат архивы с классификаторами, но не имеют обычного Maven JAR
		// или сопутствующего .sha1. Vanilla уже подготовил проверенные классификаторы.
		// Не создавайте несуществующий базовый JAR для таких записей.
		if isLegacyNativeClassifierContainer(*lib) {
			continue
		}
		canonical, err := mavenCoordinatePath(lib.Name)
		if err != nil {
			return nil, fmt.Errorf("library %s: %w", lib.Name, err)
		}
		rel := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(lib.Downloads.Artifact.Path)), "libraries/")
		if rel == "" {
			rel = canonical
		}
		// Reject a different Maven artifact masquerading as the requested dependency.
		if rel != canonical {
			return nil, fmt.Errorf("library %s: artifact.path %q differs from Maven identity %q", lib.Name, rel, canonical)
		}
		if err := validateVanillaRelativePath(rel); err != nil {
			return nil, fmt.Errorf("library %s path: %w", lib.Name, err)
		}
		dstRel := "libraries/" + rel
		dst, err := secureClientDestination(clientDir, dstRel)
		if err != nil {
			return nil, fmt.Errorf("library %s destination: %w", lib.Name, err)
		}
		artifact := lib.Downloads.Artifact
		if info, err := os.Stat(dst); err == nil && !info.IsDir() {
			sha1sum, sha256sum, size, err := hashFileSHA1SHA256(dst)
			if err != nil {
				return nil, err
			}
			if artifact.SHA1 != "" && !strings.EqualFold(artifact.SHA1, sha1sum) {
				return nil, fmt.Errorf("local library %s SHA-1 mismatch", lib.Name)
			}
			if artifact.SHA1 == "" && hasLegacySHA1Checksums(lib.Checksums) && !legacySHA1Matches(lib.Checksums, sha1sum) {
				return nil, fmt.Errorf("local legacy library %s SHA-1 не совпадает ни с одним checksums", lib.Name)
			}
			if artifact.Size > 0 && artifact.Size != size {
				return nil, fmt.Errorf("local library %s size mismatch", lib.Name)
			}
			artifact.Path = rel
			artifact.SHA1 = sha1sum
			artifact.Size = size
			lib.Downloads.Artifact = artifact
			localFiles = append(localFiles, vanillaDownloadedFile{Path: dstRel, Kind: loader + "-library", Size: size, SHA1: sha1sum, SHA256: sha256sum, Cached: true})
			continue
		}
		artifactURL := canonicalLegacyForgeURL(strings.TrimSpace(artifact.URL))
		if artifactURL == "" {
			base := canonicalLegacyForgeURL(strings.TrimSpace(lib.URL))
			if base == "" {
				if lib.ClientReq != nil || lib.ServerReq != nil || len(lib.Checksums) > 0 {
					base = defaultLegacyForgeRepositoryForCoordinate(lib.Name)
				} else {
					base = defaultRepositoryForCoordinate(lib.Name, loader)
				}
			}
			artifactURL = strings.TrimRight(base, "/") + "/" + rel
		}
		if err := validateRemoteURL(artifactURL); err != nil {
			return nil, fmt.Errorf("library %s URL: %w", lib.Name, err)
		}
		expected := strings.ToLower(strings.TrimSpace(artifact.SHA1))
		if expected == "" {
			shaBytes, err := fetchLimitedBytes(ctx, client, artifactURL+".sha1", 64<<10)
			if err == nil {
				expected = parseSHA1Sidecar(string(shaBytes))
			} else if fallback := firstLegacySHA1(lib.Checksums); fallback != "" {
				expected = fallback
			} else if strict {
				return nil, fmt.Errorf("library %s: SHA-1 sidecar: %w", lib.Name, err)
			}
		}
		if strict && !validSHA1Hex(expected) {
			return nil, fmt.Errorf("library %s не имеет корректного SHA-1", lib.Name)
		}
		artifact.Path = rel
		artifact.URL = artifactURL
		artifact.SHA1 = expected
		lib.Downloads.Artifact = artifact
		identity := forgeLibraryDownloadIdentity{SHA1: expected, URL: artifactURL, Size: artifact.Size}
		if previous, ok := seen[dstRel]; ok {
			shaConflict := previous.SHA1 != identity.SHA1
			sizeConflict := previous.Size > 0 && identity.Size > 0 && previous.Size != identity.Size
			unverifiedSourceConflict := identity.SHA1 == "" && previous.URL != identity.URL
			if shaConflict || sizeConflict || unverifiedSourceConflict {
				return nil, fmt.Errorf("конфликтующие artifacts для %s", dstRel)
			}
			// В метаданных установщика или версии Forge может повторяться один артефакт Maven. Ставьте
			// его в очередь лишь однажды, чтобы параллельные исполнители не использовали общий .nlpart.
			continue
		}
		seen[dstRel] = identity
		tasks = append(tasks, vanillaDownloadTask{Path: dstRel, URL: artifactURL, SHA1: expected, Size: artifact.Size, Kind: loader + "-library"})
	}
	downloaded, err := runVanillaDownloads(ctx, client, clientDir, tasks, workers)
	if err != nil {
		return nil, err
	}
	byPath := map[string]vanillaDownloadedFile{}
	for _, file := range downloaded {
		byPath[file.Path] = file
	}
	for i := range *libraries {
		if !applicable[i] {
			continue
		}
		lib := &(*libraries)[i]
		rel := strings.TrimPrefix(filepath.ToSlash(lib.Downloads.Artifact.Path), "libraries/")
		if rel == "" {
			continue
		}
		if file, ok := byPath["libraries/"+rel]; ok {
			artifact := lib.Downloads.Artifact
			artifact.Size = file.Size
			if artifact.SHA1 == "" {
				artifact.SHA1 = file.SHA1
			}
			lib.Downloads.Artifact = artifact
		}
	}
	return dedupeDownloadedFiles(append(localFiles, downloaded...)), nil
}

func isLegacyNativeClassifierContainer(lib MojangLibrary) bool {
	if hasMojangDownloadDescriptor(lib.Downloads.Artifact) || len(lib.Natives) == 0 {
		return false
	}
	coordinate := strings.Split(lib.Name, ":")
	if len(coordinate) < 3 {
		return false
	}
	return coordinate[0] == "org.lwjgl.lwjgl" && coordinate[1] == "lwjgl-platform" ||
		coordinate[0] == "net.java.jinput" && coordinate[1] == "jinput-platform" ||
		coordinate[0] == "tv.twitch" && (coordinate[1] == "twitch-platform" || coordinate[1] == "twitch-external-platform")
}

func hasLegacySHA1Checksums(values []string) bool {
	return firstLegacySHA1(values) != ""
}

func firstLegacySHA1(values []string) string {
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if validSHA1Hex(value) {
			return value
		}
	}
	return ""
}

func legacySHA1Matches(values []string, actual string) bool {
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if validSHA1Hex(value) && strings.EqualFold(value, actual) {
			return true
		}
	}
	return false
}

func defaultLegacyForgeRepositoryForCoordinate(coordinate string) string {
	group := strings.Split(strings.TrimSpace(strings.Split(coordinate, "@")[0]), ":")[0]
	if strings.HasPrefix(group, "net.minecraftforge") || strings.HasPrefix(group, "de.oceanlabs") || strings.HasPrefix(group, "cpw.mods") {
		return defaultForgeMavenBase
	}
	return defaultMojangLibraryBase
}

func defaultRepositoryForCoordinate(coordinate, loader string) string {
	group := strings.Split(strings.TrimSpace(strings.Split(coordinate, "@")[0]), ":")[0]
	if strings.HasPrefix(group, "net.minecraftforge") || strings.HasPrefix(group, "de.oceanlabs") || strings.HasPrefix(group, "cpw.mods") {
		return defaultForgeMavenBase
	}
	if strings.HasPrefix(group, "net.neoforged") {
		return defaultNeoForgeMavenBase
	}
	if strings.HasPrefix(group, "com.mojang") {
		return defaultMojangLibraryBase
	}
	if loader == "neoforge" && strings.HasPrefix(group, "net.neoforged") {
		return defaultNeoForgeMavenBase
	}
	return defaultMavenCentralBase
}

func mavenCoordinatePath(coordinate string) (string, error) {
	coordinate = strings.TrimSpace(coordinate)
	ext := "jar"
	if at := strings.LastIndex(coordinate, "@"); at >= 0 {
		ext = coordinate[at+1:]
		coordinate = coordinate[:at]
		if ext == "" || strings.ContainsAny(ext, `/\\:`) {
			return "", fmt.Errorf("некорректное Maven extension")
		}
	}
	parts := strings.Split(coordinate, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return "", fmt.Errorf("Maven coordinate %q должен иметь group:artifact:version[:classifier][@ext]", coordinate)
	}
	for _, part := range parts {
		if strings.TrimSpace(part) == "" || strings.ContainsAny(part, `/\\`) {
			return "", fmt.Errorf("Maven coordinate %q содержит недопустимую часть", coordinate)
		}
	}
	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact, ver := parts[1], parts[2]
	name := artifact + "-" + ver
	if len(parts) == 4 {
		name += "-" + parts[3]
	}
	name += "." + ext
	return path.Join(group, artifact, ver, name), nil
}

type forgeProcessorContext struct {
	Loader           string
	MinecraftVersion string
	ClientDir        string
	InstallerPath    string
	InstallerDataDir string
	JavaExecutable   string
	StrictSandbox    bool
	Profile          *forgeInstallerProfile
	Timeout          time.Duration
}

// The processor cache is valid only for the exact Java, processor JAR and
// dependency JAR bytes. Installer metadata alone is not sufficient.
func fingerprintForgeProcessor0273(pc forgeProcessorContext, p forgeProcessor) (string, error) {
	jar, err := resolveProcessorArtifactPath(pc.ClientDir, p.Jar)
	if err != nil {
		return "", err
	}
	cp := []string{jar}
	for _, coordinate := range p.Classpath {
		path, err := resolveProcessorArtifactPath(pc.ClientDir, coordinate)
		if err != nil {
			return "", err
		}
		cp = append(cp, path)
	}
	return hashProcessorInputs0273(pc.JavaExecutable, cp)
}

func runForgeProcessors(ctx context.Context, pc forgeProcessorContext) (processorStats, error) {
	if pc.Profile == nil {
		return processorStats{}, errors.New("processor profile отсутствует")
	}
	journal, rebuilt, err := loadForgeProcessorJournal(pc)
	if err != nil {
		return processorStats{}, err
	}
	stats := processorStats{JournalPath: filepath.ToSlash(forgeProcessorJournalPath(pc)), JournalRebuilt: rebuilt}
	for index, processor := range pc.Profile.Processors {
		if !processorAppliesToClient(processor.Sides) {
			continue
		}
		if strings.TrimSpace(processor.Jar) == "" {
			return stats, fmt.Errorf("processor[%d] не содержит jar", index)
		}
		identity := forgeProcessorIdentity(pc, index, processor)
		inputSHA, err := fingerprintForgeProcessor0273(pc, processor)
		if err != nil {
			return stats, fmt.Errorf("processor[%d] input hash: %w", index, err)
		}
		key := processorJournalKey(index)
		entry, hasEntry := journal.Entries[key]
		entryMatches := hasEntry && entry.IdentitySHA256 == identity && entry.InputSHA256 == inputSHA
		// Прерванный процессор может оставить проверенные выходные файлы для принятия либо
		// потребовать чистого повторного запуска. Оба варианта являются настоящим восстановлением;
		// второй учитывайте только после успешного запуска и проверки результата.
		interrupted := entryMatches && (entry.State == "running" || entry.State == "failed")
		allReady, err := processorOutputsMatch(pc, processor)
		if err != nil {
			return stats, fmt.Errorf("processor[%d] outputs: %w", index, err)
		}
		if allReady && entryMatches && len(processor.Outputs) > 0 {
			recovered := entryMatches && (entry.State == "running" || entry.State == "failed")
			if _, err := markProcessorJournal(pc, &journal, index, identity, inputSHA, "completed", "", recovered, ""); err != nil {
				return stats, fmt.Errorf("processor[%d] journal completion: %w", index, err)
			}
			if err := factoryRecorderFromContext0271(ctx).recordProcessor(pc, index, processor); err != nil {
				return stats, err
			}
			stats.Skipped++
			if recovered {
				stats.Recovered++
			}
			continue
		}
		if len(processor.Outputs) > 0 && !allReady || (len(processor.Outputs) > 0 && allReady && !entryMatches) {
			if err := quarantineProcessorOutputs(pc, processor, fmt.Sprintf("processor[%d] journal recovery found incomplete or corrupt outputs", index)); err != nil {
				return stats, fmt.Errorf("processor[%d] recovery cleanup: %w", index, err)
			}
		}
		procJar, err := resolveProcessorArtifactPath(pc.ClientDir, processor.Jar)
		if err != nil {
			return stats, fmt.Errorf("processor[%d] jar: %w", index, err)
		}
		mainClass, err := readJarMainClass(procJar)
		if err != nil {
			return stats, fmt.Errorf("processor[%d] main class: %w", index, err)
		}
		classpath := []string{procJar}
		for _, coordinate := range processor.Classpath {
			resolved, err := resolveProcessorArtifactPath(pc.ClientDir, coordinate)
			if err != nil {
				return stats, fmt.Errorf("processor[%d] classpath %s: %w", index, coordinate, err)
			}
			classpath = append(classpath, resolved)
		}
		args := make([]string, 0, len(processor.Args))
		for _, arg := range processor.Args {
			resolved, err := resolveProcessorToken(pc, arg)
			if err != nil {
				return stats, fmt.Errorf("processor[%d] arg %q: %w", index, arg, err)
			}
			args = append(args, resolved)
		}
		if _, err := markProcessorJournal(pc, &journal, index, identity, inputSHA, "running", "", false, ""); err != nil {
			return stats, fmt.Errorf("processor[%d] journal start: %w", index, err)
		}
		cmdArgs := append([]string{"-cp", strings.Join(classpath, string(os.PathListSeparator)), mainClass}, args...)
		logPath, runErr := runIsolatedProcessor0273(ctx, pc, index, cmdArgs)
		if runErr != nil {
			_, _ = markProcessorJournal(pc, &journal, index, identity, inputSHA, "failed", logPath, false, runErr.Error())
			return stats, fmt.Errorf("processor[%d] isolated worker: %w (log: %s)", index, runErr, logPath)
		}
		allReady, err = processorOutputsMatch(pc, processor)
		if err != nil {
			_, _ = markProcessorJournal(pc, &journal, index, identity, inputSHA, "failed", logPath, false, err.Error())
			return stats, fmt.Errorf("processor[%d] output verification: %w", index, err)
		}
		if len(processor.Outputs) > 0 && !allReady {
			_, _ = markProcessorJournal(pc, &journal, index, identity, inputSHA, "failed", logPath, false, "expected outputs were not produced")
			return stats, fmt.Errorf("processor[%d] не создал ожидаемые outputs", index)
		}
		journalSHA, err := markProcessorJournal(pc, &journal, index, identity, inputSHA, "completed", logPath, interrupted, "")
		if err != nil {
			return stats, fmt.Errorf("processor[%d] journal commit: %w", index, err)
		}
		stats.JournalSHA256 = journalSHA
		if err := factoryRecorderFromContext0271(ctx).recordProcessor(pc, index, processor); err != nil {
			return stats, err
		}
		stats.Ran++
		if interrupted {
			stats.Recovered++
		}
	}
	if stats.JournalSHA256 == "" {
		sha, err := persistForgeProcessorJournal(pc, journal)
		if err != nil {
			return stats, err
		}
		stats.JournalSHA256 = sha
	}
	return stats, nil
}

func processorAppliesToClient(sides []string) bool {
	if len(sides) == 0 {
		return true
	}
	for _, side := range sides {
		if strings.EqualFold(strings.TrimSpace(side), "client") {
			return true
		}
	}
	return false
}

// Reject output symlinks and paths outside the materialized client root,
// including symlinks in an existing parent directory. This check runs before
// a digest can be trusted for crash recovery.
func validateProcessorOutput0273(root, output string) error {
	base, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, absolute)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("processor output outside client root: %s", output)
	}
	_, err = secureClientDestination(base, filepath.ToSlash(rel))
	return err
}

func processorOutputsMatch(pc forgeProcessorContext, processor forgeProcessor) (bool, error) {
	if len(processor.Outputs) == 0 {
		return false, nil
	}
	for outputToken, expected := range processor.Outputs {
		outputPath, err := resolveProcessorToken(pc, outputToken)
		if err != nil {
			return false, err
		}
		if err := validateProcessorOutput0273(pc.ClientDir, outputPath); err != nil {
			return false, err
		}
		expectedResolved, err := resolveProcessorToken(pc, expected)
		if err != nil {
			return false, err
		}
		expectedResolved = strings.Trim(strings.TrimSpace(expectedResolved), "'\"")
		ok, err := fileMatchesExpectedDigest(outputPath, expectedResolved)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func resolveProcessorToken(pc forgeProcessorContext, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if isQuotedInstallerLiteral(raw) {
		raw = raw[1 : len(raw)-1]
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return processorArtifactPath(pc.ClientDir, raw[1:len(raw)-1], false)
	}
	var out strings.Builder
	for cursor := 0; cursor < len(raw); {
		open := strings.IndexByte(raw[cursor:], '{')
		if open < 0 {
			out.WriteString(raw[cursor:])
			break
		}
		open += cursor
		out.WriteString(raw[cursor:open])
		closeRel := strings.IndexByte(raw[open+1:], '}')
		if closeRel < 0 {
			return "", fmt.Errorf("незакрытый processor token в %q", raw)
		}
		close := open + 1 + closeRel
		key := raw[open+1 : close]
		if key == "" || strings.ContainsAny(key, "{}") {
			return "", fmt.Errorf("некорректный processor token {%s}", key)
		}
		value, err := resolveProcessorNamedToken(pc, key)
		if err != nil {
			return "", err
		}
		out.WriteString(value)
		cursor = close + 1
	}
	if strings.ContainsRune(out.String(), '}') {
		return "", fmt.Errorf("лишняя закрывающая скобка processor token в %q", raw)
	}
	return out.String(), nil
}

func resolveProcessorNamedToken(pc forgeProcessorContext, key string) (string, error) {
	switch key {
	case "ROOT":
		return filepath.Abs(pc.ClientDir)
	case "MINECRAFT_JAR":
		root, _ := filepath.Abs(pc.ClientDir)
		return filepath.Join(root, "versions", pc.MinecraftVersion, pc.MinecraftVersion+".jar"), nil
	case "MINECRAFT_VERSION":
		return pc.MinecraftVersion, nil
	case "INSTALLER":
		return filepath.Abs(pc.InstallerPath)
	case "LIBRARY_DIR":
		root, _ := filepath.Abs(pc.ClientDir)
		return filepath.Join(root, "libraries"), nil
	case "SIDE":
		return "client", nil
	default:
		value, ok := pc.Profile.Data[key]
		if !ok {
			return "", fmt.Errorf("неизвестный installer data token {%s}", key)
		}
		return resolveInstallerDataValue(pc, value.Client)
	}
}

func resolveInstallerDataValue(pc forgeProcessorContext, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("installer data client value пуст")
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return processorArtifactPath(pc.ClientDir, value[1:len(value)-1], false)
	}
	if isQuotedInstallerLiteral(value) {
		return value[1 : len(value)-1], nil
	}
	rel, err := safeArchiveRelative(strings.TrimPrefix(value, "/"))
	if err != nil {
		return "", err
	}
	full := filepath.Join(pc.InstallerDataDir, filepath.FromSlash(rel))
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("installer data %s не извлечён: %w", value, err)
	}
	return filepath.Abs(full)
}

func resolveProcessorArtifactPath(clientDir, coordinate string) (string, error) {
	return processorArtifactPath(clientDir, coordinate, true)
}

func processorArtifactPath(clientDir, coordinate string, requireExisting bool) (string, error) {
	rel, err := mavenCoordinatePath(strings.TrimSpace(coordinate))
	if err != nil {
		return "", err
	}
	full := filepath.Join(clientDir, "libraries", filepath.FromSlash(rel))
	if requireExisting {
		info, statErr := os.Stat(full)
		if statErr != nil || info.IsDir() {
			return "", fmt.Errorf("artifact %s отсутствует: %s", coordinate, full)
		}
	}
	return filepath.Abs(full)
}

func readJarMainClass(jarPath string) (string, error) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	manifest, err := readZipFileLimited(&zr.Reader, "META-INF/MANIFEST.MF", 1<<20)
	if err != nil {
		return "", errors.New("processor JAR не содержит META-INF/MANIFEST.MF")
	}
	fields := parseManifestFields(manifest)
	mainClass := strings.TrimSpace(fields["Main-Class"])
	if mainClass == "" {
		return "", errors.New("processor JAR manifest не содержит Main-Class")
	}
	if strings.ContainsAny(mainClass, "\r\n\t ") {
		return "", errors.New("processor Main-Class некорректен")
	}
	return mainClass, nil
}

func parseManifestFields(data []byte) map[string]string {
	fields := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	current := ""
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.HasPrefix(line, " ") && current != "" {
			fields[current] += strings.TrimPrefix(line, " ")
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			current = ""
			continue
		}
		current = strings.TrimSpace(parts[0])
		fields[current] = strings.TrimSpace(parts[1])
	}
	return fields
}

func fileMatchesExpectedDigest(filePath, expected string) (bool, error) {
	expected = strings.ToLower(strings.TrimSpace(expected))
	expected = strings.TrimPrefix(expected, "sha1:")
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if len(expected) == 40 {
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return false, err
		}
		return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected), nil
	}
	if len(expected) == 64 {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return false, err
		}
		return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected), nil
	}
	return false, fmt.Errorf("неподдерживаемый output digest %q", expected)
}

func selectInstallerJava(explicit string, minimumMajor int) (string, error) {
	candidate := strings.TrimSpace(explicit)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_JAVA"))
	}
	if candidate == "" {
		path, err := exec.LookPath("java")
		if err != nil {
			return "", errors.New("Forge/NeoForge installer требует Java; укажите --java или NEVERLAUNCHER_JAVA (можно использовать Managed Java из Runtime)")
		}
		candidate = path
	}
	if runtime.GOOS == "windows" {
		// Git Bash может экспортировать /c/.../bin/java или C:/.../bin/java;
		// нативной проверке файлов в Go нужен конкретный путь к исполняемому файлу.
		if len(candidate) > 3 && candidate[0] == '/' && candidate[2] == '/' &&
			((candidate[1] >= 'a' && candidate[1] <= 'z') || (candidate[1] >= 'A' && candidate[1] <= 'Z')) {
			candidate = candidate[1:2] + ":/" + candidate[3:]
		}
		if !strings.EqualFold(filepath.Ext(candidate), ".exe") {
			candidate += ".exe"
		}
	}
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("Java executable недоступен: %s", candidate)
	}
	major, err := javaMajorVersion(candidate)
	if err != nil {
		return "", err
	}
	if minimumMajor > 0 && major < minimumMajor {
		return "", fmt.Errorf("installer Java %d старее требуемой Minecraft Java %d", major, minimumMajor)
	}
	return candidate, nil
}

func javaMajorVersion(javaPath string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, javaPath, "-version").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("java -version failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	text := string(output)
	start := strings.Index(text, `"`)
	if start < 0 {
		return 0, fmt.Errorf("java -version не содержит version string: %s", strings.TrimSpace(text))
	}
	end := strings.Index(text[start+1:], `"`)
	if end < 0 {
		return 0, fmt.Errorf("java -version имеет некорректный output")
	}
	ver := text[start+1 : start+1+end]
	parts := strings.Split(ver, ".")
	if len(parts) == 0 {
		return 0, fmt.Errorf("не удалось разобрать Java version %q", ver)
	}
	majorText := parts[0]
	if majorText == "1" && len(parts) > 1 {
		majorText = parts[1]
	}
	major, err := strconv.Atoi(majorText)
	if err != nil {
		return 0, fmt.Errorf("не удалось разобрать Java major %q", ver)
	}
	return major, nil
}

func hashFileSHA1SHA256(filePath string) (string, string, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", "", 0, err
	}
	h1 := sha1.New()
	h256 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h1, h256), f); err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h256.Sum(nil)), info.Size(), nil
}

func dedupeDownloadedFiles(files []vanillaDownloadedFile) []vanillaDownloadedFile {
	byPath := map[string]vanillaDownloadedFile{}
	for _, file := range files {
		if file.Path == "" {
			continue
		}
		if current, ok := byPath[file.Path]; ok {
			if current.SHA256 != "" && file.SHA256 != "" && current.SHA256 != file.SHA256 {
				// Более поздняя проверка не должна незаметно скрывать конфликтующий артефакт.
				continue
			}
			if current.Cached && !file.Cached {
				byPath[file.Path] = file
			}
			continue
		}
		byPath[file.Path] = file
	}
	out := make([]vanillaDownloadedFile, 0, len(byPath))
	for _, file := range byPath {
		out = append(out, file)
	}
	return out
}

func sanitizeVersionToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

type limitedBuffer struct {
	bytes.Buffer
	Limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.Limit <= 0 {
		return original, nil
	}
	remaining := b.Limit - b.Buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return original, nil
}
