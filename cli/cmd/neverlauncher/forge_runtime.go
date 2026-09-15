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
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	Loader           string
	MinecraftVersion string
	LoaderVersion    string
	ClientDir        string
	JavaExecutable   string
	InstallerURL     string
	InstallerSHA1    string
	MavenMetadataURL string
	VersionManifest  string
	AssetBaseURL     string
	LibraryBaseURL   string
	Targets          []vanillaTarget
	Workers          int
	StrictUpstream   bool
	ProcessorTimeout time.Duration
	HTTPClient       *http.Client
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

type forgeMaterializeResult struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	ToolVersion      string                  `json:"toolVersion"`
	Loader           string                  `json:"loader"`
	MinecraftVersion string                  `json:"minecraftVersion"`
	LoaderVersion    string                  `json:"loaderVersion"`
	ArtifactVersion  string                  `json:"artifactVersion"`
	ProfileID        string                  `json:"profileId"`
	ProfilePath      string                  `json:"profilePath"`
	MainClass        string                  `json:"mainClass"`
	ClientDir        string                  `json:"clientDir"`
	JavaMajorVersion int                     `json:"javaMajorVersion"`
	InstallerSHA1    string                  `json:"installerSha1"`
	InstallerSHA256  string                  `json:"installerSha256"`
	ProcessorCount   int                     `json:"processorCount"`
	ProcessorRan     int                     `json:"processorRan"`
	ProcessorSkipped int                     `json:"processorSkipped"`
	LibraryCount     int                     `json:"libraryCount"`
	Downloaded       int                     `json:"downloaded"`
	Cached           int                     `json:"cached"`
	TotalBytes       int64                   `json:"totalBytes"`
	ProfileSHA256    string                  `json:"profileSha256"`
	Vanilla          vanillaInstallResult    `json:"vanilla"`
	Files            []vanillaDownloadedFile `json:"files"`
	Status           string                  `json:"status"`
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
	Profile forgeInstallerProfile
	Version loaderVersionProfile
	ZipPath string
}

type processorStats struct {
	Ran     int
	Skipped int
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
	clientDir := flagValue(args, "--client-dir", filepath.Join(".neverlauncher", loader, minecraftVersion))
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
	return forgeMaterializeOptions{
		Loader:           loader,
		MinecraftVersion: minecraftVersion,
		LoaderVersion:    strings.TrimSpace(flagValue(args, "--loader-version", "latest-stable")),
		ClientDir:        clientDir,
		JavaExecutable:   strings.TrimSpace(flagValue(args, "--java", "")),
		InstallerURL:     strings.TrimSpace(flagValue(args, "--installer-url", "")),
		InstallerSHA1:    strings.TrimSpace(flagValue(args, "--installer-sha1", "")),
		MavenMetadataURL: strings.TrimSpace(flagValue(args, "--maven-metadata-url", "")),
		VersionManifest:  flagValue(args, "--version-manifest", defaultMojangVersionManifest),
		AssetBaseURL:     flagValue(args, "--asset-base-url", defaultMojangAssetBase),
		LibraryBaseURL:   flagValue(args, "--library-base-url", defaultMojangLibraryBase),
		Targets:          targets,
		Workers:          workers,
		StrictUpstream:   !strings.EqualFold(flagValue(args, "--strict-upstream", "true"), "false"),
		ProcessorTimeout: timeout,
	}, nil
}

func installForgeLike(ctx context.Context, opts forgeMaterializeOptions) (forgeMaterializeResult, error) {
	loader := strings.ToLower(strings.TrimSpace(opts.Loader))
	if loader != "forge" && loader != "neoforge" {
		return forgeMaterializeResult{}, fmt.Errorf("поддерживаются только Forge и NeoForge, получен %s", loader)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = secureHTTPClient()
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

	loaderVersion, artifactVersion, metadataURL, err := resolveForgeLikeVersion(ctx, opts.HTTPClient, loader, vanilla.MinecraftVersion, opts.LoaderVersion, opts.MavenMetadataURL)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	installerURL := opts.InstallerURL
	if installerURL == "" {
		installerURL = forgeInstallerURL(loader, artifactVersion)
	}
	if err := validateRemoteURL(installerURL); err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("installer URL: %w", err)
	}
	installerSHA1 := strings.ToLower(strings.TrimSpace(opts.InstallerSHA1))
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

	installerRel := filepath.ToSlash(filepath.Join(".neverlauncher", "installers", loader, sanitizeVersionToken(artifactVersion), "installer.jar"))
	installerFile, err := downloadVanillaArtifact(ctx, opts.HTTPClient, vanillaDownloadTask{Path: installerRel, URL: installerURL, SHA1: installerSHA1, Kind: loader + "-installer"}, filepath.Join(opts.ClientDir, filepath.FromSlash(installerRel)))
	if err != nil {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer download: %w", loader, err)
	}
	installerPath := filepath.Join(opts.ClientDir, filepath.FromSlash(installerRel))
	bundle, err := inspectForgeInstaller(installerPath)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	// Forge uses spec=0 for the classic processor-based 1.13+ installer format;
	// NeoForge inherited this format and may use newer spec values. The actual
	// production boundary is presence of version.json + processor metadata, not
	// an arbitrary minimum spec number.
	if bundle.Profile.JSON == "" && bundle.Profile.Version == "" {
		return forgeMaterializeResult{}, fmt.Errorf("%s installer profile не содержит version/json metadata; legacy pre-1.13 installer format в 0.10.4 не поддерживается", loader)
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

	javaPath, err := selectInstallerJava(opts.JavaExecutable, vanilla.JavaMajorVersion)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	installerDataDir := filepath.Join(opts.ClientDir, ".neverlauncher", "installers", loader, sanitizeVersionToken(artifactVersion), "data")
	if err := extractInstallerData(installerPath, installerDataDir); err != nil {
		return forgeMaterializeResult{}, err
	}

	files := make([]vanillaDownloadedFile, 0)
	embeddedFiles, err := extractEmbeddedMaven(installerPath, opts.ClientDir)
	if err != nil {
		return forgeMaterializeResult{}, err
	}
	files = append(files, embeddedFiles...)

	profileFiles, err := materializeForgeLibraries(ctx, opts.HTTPClient, opts.ClientDir, &bundle.Profile.Libraries, loader, opts.Workers, opts.StrictUpstream)
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
	})
	if err != nil {
		return forgeMaterializeResult{}, err
	}

	versionFiles, err := materializeForgeLibraries(ctx, opts.HTTPClient, opts.ClientDir, &bundle.Version.Libraries, loader, opts.Workers, opts.StrictUpstream)
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
	if err := writeAtomicBytes(filepath.Join(opts.ClientDir, filepath.FromSlash(profilePath)), profileBytes, 0o644); err != nil {
		return forgeMaterializeResult{}, err
	}
	profileSHA := sha256.Sum256(profileBytes)
	files = append(files, vanillaDownloadedFile{Path: profilePath, Kind: loader + "-profile", Size: int64(len(profileBytes)), SHA256: hex.EncodeToString(profileSHA[:])})

	files = dedupeDownloadedFiles(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
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
		"profileSha256": hex.EncodeToString(profileSHA[:]), "installerUrl": installerURL,
		"installerSha1": installerSHA1, "installerSha256": installerFile.SHA256,
		"mavenMetadata": metadataURL, "processorRan": stats.Ran, "processorSkipped": stats.Skipped,
		"status": "installed-and-verified",
	}
	stateBytes, _ := json.MarshalIndent(state, "", "  ")
	statePath := filepath.Join(opts.ClientDir, ".neverlauncher", loader+"-install.json")
	if err := writeAtomicBytes(statePath, append(stateBytes, '\n'), 0o600); err != nil {
		return forgeMaterializeResult{}, err
	}

	return forgeMaterializeResult{
		SchemaVersion: "1.0", ToolVersion: version, Loader: loader,
		MinecraftVersion: vanilla.MinecraftVersion, LoaderVersion: loaderVersion, ArtifactVersion: artifactVersion,
		ProfileID: bundle.Version.ID, ProfilePath: profilePath, MainClass: bundle.Version.MainClass,
		ClientDir: opts.ClientDir, JavaMajorVersion: vanilla.JavaMajorVersion,
		InstallerSHA1: installerSHA1, InstallerSHA256: installerFile.SHA256,
		ProcessorCount: len(bundle.Profile.Processors), ProcessorRan: stats.Ran, ProcessorSkipped: stats.Skipped,
		LibraryCount: len(bundle.Profile.Libraries) + len(bundle.Version.Libraries), Downloaded: downloaded, Cached: cached,
		TotalBytes: total, ProfileSHA256: hex.EncodeToString(profileSHA[:]), Vanilla: vanilla, Files: files,
		Status: "installed-and-verified",
	}, nil
}

func resolveForgeLikeVersion(ctx context.Context, client *http.Client, loader, minecraftVersion, requested, metadataOverride string) (string, string, string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = "latest-stable"
	}
	metadataURL := strings.TrimSpace(metadataOverride)
	if metadataURL == "" {
		if loader == "forge" {
			metadataURL = defaultForgeMavenBase + "/net/minecraftforge/forge/maven-metadata.xml"
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
			return strings.TrimPrefix(artifact, minecraftVersion+"-"), artifact, metadataURL, nil
		}
		return requested, requested, metadataURL, nil
	}
	data, err := fetchLimitedBytes(ctx, client, metadataURL, 8<<20)
	if err != nil {
		return "", "", metadataURL, fmt.Errorf("%s Maven metadata: %w", loader, err)
	}
	var metadata mavenMetadataXML
	if err := xml.Unmarshal(data, &metadata); err != nil {
		return "", "", metadataURL, fmt.Errorf("%s Maven metadata XML повреждён: %w", loader, err)
	}
	versions := metadata.Versioning.Versions.Version
	if len(versions) == 0 {
		return "", "", metadataURL, fmt.Errorf("%s Maven metadata не содержит versions", loader)
	}
	allowPrerelease := requested == "latest"
	for i := len(versions) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(versions[i])
		if candidate == "" || (!allowPrerelease && isPrereleaseVersion(candidate)) {
			continue
		}
		if loader == "forge" {
			if !strings.HasPrefix(candidate, minecraftVersion+"-") {
				continue
			}
			return strings.TrimPrefix(candidate, minecraftVersion+"-"), candidate, metadataURL, nil
		}
		if neoForgeVersionMatchesMinecraft(candidate, minecraftVersion) {
			return candidate, candidate, metadataURL, nil
		}
	}
	return "", "", metadataURL, fmt.Errorf("%s не имеет %s версии, совместимой с Minecraft %s", loader, requested, minecraftVersion)
}

func forgeInstallerURL(loader, artifactVersion string) string {
	if loader == "forge" {
		return fmt.Sprintf("%s/net/minecraftforge/forge/%s/forge-%s-installer.jar", defaultForgeMavenBase, artifactVersion, artifactVersion)
	}
	return fmt.Sprintf("%s/net/neoforged/neoforge/%s/neoforge-%s-installer.jar", defaultNeoForgeMavenBase, artifactVersion, artifactVersion)
}

func neoForgeVersionMatchesMinecraft(loaderVersion, minecraftVersion string) bool {
	parts := strings.Split(strings.TrimSpace(minecraftVersion), ".")
	if len(parts) < 2 || parts[0] != "1" {
		return false
	}
	patch := "0"
	if len(parts) >= 3 && parts[2] != "" {
		patch = parts[2]
	}
	return strings.HasPrefix(loaderVersion, parts[1]+"."+patch+".") || loaderVersion == parts[1]+"."+patch
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
	return installerBundle{Profile: profile, Version: versionProfile, ZipPath: versionPath}, nil
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

func extractInstallerData(installerPath, targetDir string) error {
	zr, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, entry := range zr.File {
		name := strings.ReplaceAll(entry.Name, "\\", "/")
		if !strings.HasPrefix(name, "data/") || strings.HasSuffix(name, "/") {
			continue
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
	}
	return nil
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
		dst := filepath.Join(clientDir, filepath.FromSlash(dstRel))
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
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func materializeForgeLibraries(ctx context.Context, client *http.Client, clientDir string, libraries *[]MojangLibrary, loader string, workers int, strict bool) ([]vanillaDownloadedFile, error) {
	if libraries == nil || len(*libraries) == 0 {
		return nil, nil
	}
	tasks := []vanillaDownloadTask{}
	seen := map[string]string{}
	localFiles := []vanillaDownloadedFile{}
	for i := range *libraries {
		lib := &(*libraries)[i]
		if strings.TrimSpace(lib.Name) == "" {
			return nil, fmt.Errorf("library[%d] не содержит name", i)
		}
		rel := strings.TrimSpace(lib.Downloads.Artifact.Path)
		if rel == "" {
			var err error
			rel, err = mavenCoordinatePath(lib.Name)
			if err != nil {
				return nil, fmt.Errorf("library %s: %w", lib.Name, err)
			}
		}
		rel = strings.TrimPrefix(filepath.ToSlash(rel), "libraries/")
		if err := validateVanillaRelativePath(rel); err != nil {
			return nil, fmt.Errorf("library %s path: %w", lib.Name, err)
		}
		dstRel := "libraries/" + rel
		dst := filepath.Join(clientDir, filepath.FromSlash(dstRel))
		artifact := lib.Downloads.Artifact
		if info, err := os.Stat(dst); err == nil && !info.IsDir() {
			sha1sum, sha256sum, size, err := hashFileSHA1SHA256(dst)
			if err != nil {
				return nil, err
			}
			if artifact.SHA1 != "" && !strings.EqualFold(artifact.SHA1, sha1sum) {
				return nil, fmt.Errorf("local library %s SHA-1 mismatch", lib.Name)
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
		artifactURL := strings.TrimSpace(artifact.URL)
		if artifactURL == "" {
			base := strings.TrimSpace(lib.URL)
			if base == "" {
				base = defaultRepositoryForCoordinate(lib.Name, loader)
			}
			artifactURL = strings.TrimRight(base, "/") + "/" + rel
		}
		if err := validateRemoteURL(artifactURL); err != nil {
			return nil, fmt.Errorf("library %s URL: %w", lib.Name, err)
		}
		expected := strings.ToLower(strings.TrimSpace(artifact.SHA1))
		if expected == "" {
			shaBytes, err := fetchLimitedBytes(ctx, client, artifactURL+".sha1", 64<<10)
			if err != nil {
				if strict {
					return nil, fmt.Errorf("library %s: SHA-1 sidecar: %w", lib.Name, err)
				}
			} else {
				expected = parseSHA1Sidecar(string(shaBytes))
			}
		}
		if strict && !validSHA1Hex(expected) {
			return nil, fmt.Errorf("library %s не имеет корректного SHA-1", lib.Name)
		}
		if previous, ok := seen[dstRel]; ok && previous != expected {
			return nil, fmt.Errorf("конфликтующие artifacts для %s", dstRel)
		}
		seen[dstRel] = expected
		artifact.Path = rel
		artifact.URL = artifactURL
		artifact.SHA1 = expected
		lib.Downloads.Artifact = artifact
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
	Profile          *forgeInstallerProfile
	Timeout          time.Duration
}

func runForgeProcessors(ctx context.Context, pc forgeProcessorContext) (processorStats, error) {
	if pc.Profile == nil {
		return processorStats{}, errors.New("processor profile отсутствует")
	}
	stats := processorStats{}
	for index, processor := range pc.Profile.Processors {
		if !processorAppliesToClient(processor.Sides) {
			continue
		}
		if strings.TrimSpace(processor.Jar) == "" {
			return stats, fmt.Errorf("processor[%d] не содержит jar", index)
		}
		allReady, err := processorOutputsMatch(pc, processor)
		if err != nil {
			return stats, fmt.Errorf("processor[%d] outputs: %w", index, err)
		}
		if allReady && len(processor.Outputs) > 0 {
			stats.Skipped++
			continue
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
		timeout := pc.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Minute
		}
		procCtx, cancel := context.WithTimeout(ctx, timeout)
		cmdArgs := append([]string{"-cp", strings.Join(classpath, string(os.PathListSeparator)), mainClass}, args...)
		cmd := exec.CommandContext(procCtx, pc.JavaExecutable, cmdArgs...)
		cmd.Dir = pc.ClientDir
		var output limitedBuffer
		output.Limit = 2 << 20
		cmd.Stdout = &output
		cmd.Stderr = &output
		runErr := cmd.Run()
		cancel()
		if procCtx.Err() == context.DeadlineExceeded {
			return stats, fmt.Errorf("processor[%d] превысил timeout %s", index, timeout)
		}
		if runErr != nil {
			return stats, fmt.Errorf("processor[%d] завершился с ошибкой: %w\n%s", index, runErr, output.String())
		}
		allReady, err = processorOutputsMatch(pc, processor)
		if err != nil {
			return stats, fmt.Errorf("processor[%d] output verification: %w", index, err)
		}
		if len(processor.Outputs) > 0 && !allReady {
			return stats, fmt.Errorf("processor[%d] не создал ожидаемые outputs", index)
		}
		stats.Ran++
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

func processorOutputsMatch(pc forgeProcessorContext, processor forgeProcessor) (bool, error) {
	if len(processor.Outputs) == 0 {
		return false, nil
	}
	for outputToken, expected := range processor.Outputs {
		outputPath, err := resolveProcessorToken(pc, outputToken)
		if err != nil {
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
	if len(raw) >= 2 && ((raw[0] == '\'' && raw[len(raw)-1] == '\'') || (raw[0] == '"' && raw[len(raw)-1] == '"')) {
		raw = raw[1 : len(raw)-1]
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return processorArtifactPath(pc.ClientDir, raw[1:len(raw)-1], false)
	}
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") && strings.Count(raw, "{") == 1 {
		key := raw[1 : len(raw)-1]
		switch key {
		case "ROOT":
			return filepath.Abs(pc.ClientDir)
		case "MINECRAFT_JAR":
			root, _ := filepath.Abs(pc.ClientDir)
			return filepath.Join(root, "versions", pc.MinecraftVersion, pc.MinecraftVersion+".jar"), nil
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
	out := raw
	for _, key := range []string{"ROOT", "MINECRAFT_JAR", "INSTALLER", "LIBRARY_DIR", "SIDE"} {
		if strings.Contains(out, "{"+key+"}") {
			value, err := resolveProcessorToken(pc, "{"+key+"}")
			if err != nil {
				return "", err
			}
			out = strings.ReplaceAll(out, "{"+key+"}", value)
		}
	}
	return out, nil
}

func resolveInstallerDataValue(pc forgeProcessorContext, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("installer data client value пуст")
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return processorArtifactPath(pc.ClientDir, value[1:len(value)-1], false)
	}
	if strings.HasPrefix(value, "/") {
		rel, err := safeArchiveRelative(strings.TrimPrefix(value, "/"))
		if err != nil {
			return "", err
		}
		full := filepath.Join(pc.InstallerDataDir, filepath.FromSlash(rel))
		if _, err := os.Stat(full); err != nil {
			return "", fmt.Errorf("installer data %s не извлечён: %w", value, err)
		}
		return filepath.Abs(full)
	}
	return value, nil
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
			return "", errors.New("Forge/NeoForge installer требует Java; укажите --java или NEVERLAUNCHER_JAVA (можно использовать Managed Java из NeverRuntime)")
		}
		candidate = path
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
				// A later verification result must not silently hide a conflicting artifact.
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
