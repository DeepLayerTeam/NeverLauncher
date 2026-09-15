package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultFabricMetaBase = "https://meta.fabricmc.net/v2"
	defaultQuiltMetaBase  = "https://meta.quiltmc.org/v3"
)

type loaderMaterializeOptions struct {
	Loader           string
	MinecraftVersion string
	LoaderVersion    string
	ClientDir        string
	VersionManifest  string
	AssetBaseURL     string
	LibraryBaseURL   string
	MetaBaseURL      string
	Targets          []vanillaTarget
	Workers          int
	StrictUpstream   bool
	HTTPClient       *http.Client
}

type loaderMetaEntry struct {
	Loader       loaderMetaVersion `json:"loader"`
	Intermediary loaderMetaVersion `json:"intermediary"`
}

type loaderMetaVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Maven     string `json:"maven"`
	Version   string `json:"version"`
	Stable    bool   `json:"stable"`
}

type loaderVersionProfile struct {
	ID            string          `json:"id"`
	InheritsFrom  string          `json:"inheritsFrom"`
	Type          string          `json:"type,omitempty"`
	MainClass     string          `json:"mainClass"`
	Libraries     []MojangLibrary `json:"libraries"`
	Arguments     MojangArguments `json:"arguments,omitempty"`
	MinecraftArgs string          `json:"minecraftArguments,omitempty"`
	Time          string          `json:"time,omitempty"`
	ReleaseTime   string          `json:"releaseTime,omitempty"`
}

type loaderMaterializeResult struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	ToolVersion      string                  `json:"toolVersion"`
	Loader           string                  `json:"loader"`
	MinecraftVersion string                  `json:"minecraftVersion"`
	LoaderVersion    string                  `json:"loaderVersion"`
	ProfileID        string                  `json:"profileId"`
	ProfilePath      string                  `json:"profilePath"`
	MainClass        string                  `json:"mainClass"`
	ClientDir        string                  `json:"clientDir"`
	JavaMajorVersion int                     `json:"javaMajorVersion"`
	LibraryCount     int                     `json:"libraryCount"`
	Downloaded       int                     `json:"downloaded"`
	Cached           int                     `json:"cached"`
	TotalBytes       int64                   `json:"totalBytes"`
	ProfileSHA256    string                  `json:"profileSha256"`
	Vanilla          vanillaInstallResult    `json:"vanilla"`
	Files            []vanillaDownloadedFile `json:"files"`
	Status           string                  `json:"status"`
}

func handleRuntimeFabricInstall(args []string) error {
	return handleRuntimeLoaderInstall("fabric", args)
}

func handleRuntimeQuiltInstall(args []string) error {
	return handleRuntimeLoaderInstall("quilt", args)
}

func handleRuntimeFabricPackage(args []string) error {
	return handleRuntimeLoaderPackage("fabric", args)
}

func handleRuntimeQuiltPackage(args []string) error {
	return handleRuntimeLoaderPackage("quilt", args)
}

func handleRuntimeLoaderInstall(loader string, args []string) error {
	opts, err := parseLoaderMaterializeOptions(loader, args)
	if err != nil {
		return err
	}
	result, err := installMetaLoader(context.Background(), opts)
	if err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), result)
}

func handleRuntimeLoaderPackage(loader string, args []string) error {
	opts, err := parseLoaderMaterializeOptions(loader, args)
	if err != nil {
		return err
	}
	result, err := installMetaLoader(context.Background(), opts)
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

func parseLoaderMaterializeOptions(loader string, args []string) (loaderMaterializeOptions, error) {
	loader = strings.ToLower(strings.TrimSpace(loader))
	if loader != "fabric" && loader != "quilt" {
		return loaderMaterializeOptions{}, fmt.Errorf("meta loader %s не поддерживается", loader)
	}
	minecraftVersion := strings.TrimSpace(flagValue(args, "--minecraft", "latest-release"))
	clientDir := flagValue(args, "--client-dir", filepath.Join(".neverlauncher", loader, minecraftVersion))
	workers, err := strconv.Atoi(flagValue(args, "--workers", "12"))
	if err != nil || workers < 1 || workers > 64 {
		return loaderMaterializeOptions{}, errors.New("--workers должен быть числом от 1 до 64")
	}
	targets, err := parseVanillaTargets(flagValue(args, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
	if err != nil {
		return loaderMaterializeOptions{}, err
	}
	metaBase := flagValue(args, "--meta-base-url", defaultMetaBaseForLoader(loader))
	if err := validateMetaBaseURL(metaBase); err != nil {
		return loaderMaterializeOptions{}, err
	}
	return loaderMaterializeOptions{
		Loader:           loader,
		MinecraftVersion: minecraftVersion,
		LoaderVersion:    strings.TrimSpace(flagValue(args, "--loader-version", "latest-stable")),
		ClientDir:        clientDir,
		VersionManifest:  flagValue(args, "--version-manifest", defaultMojangVersionManifest),
		AssetBaseURL:     flagValue(args, "--asset-base-url", defaultMojangAssetBase),
		LibraryBaseURL:   flagValue(args, "--library-base-url", defaultMojangLibraryBase),
		MetaBaseURL:      strings.TrimRight(metaBase, "/"),
		Targets:          targets,
		Workers:          workers,
		StrictUpstream:   !strings.EqualFold(flagValue(args, "--strict-upstream", "true"), "false"),
	}, nil
}

func defaultMetaBaseForLoader(loader string) string {
	if loader == "quilt" {
		return defaultQuiltMetaBase
	}
	return defaultFabricMetaBase
}

func validateMetaBaseURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("Meta API base URL пуст")
	}
	return validateRemoteURL(strings.TrimRight(raw, "/") + "/versions/loader/probe")
}

func installMetaLoader(ctx context.Context, opts loaderMaterializeOptions) (loaderMaterializeResult, error) {
	loader := strings.ToLower(strings.TrimSpace(opts.Loader))
	if loader != "fabric" && loader != "quilt" {
		return loaderMaterializeResult{}, fmt.Errorf("поддерживаются только Fabric и Quilt, получен %s", loader)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = secureHTTPClient()
	}
	if opts.MetaBaseURL == "" {
		opts.MetaBaseURL = defaultMetaBaseForLoader(loader)
	}
	if err := validateMetaBaseURL(opts.MetaBaseURL); err != nil {
		return loaderMaterializeResult{}, err
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
		return loaderMaterializeResult{}, fmt.Errorf("%s base Vanilla: %w", loader, err)
	}

	selectedEntry, err := resolveMetaLoaderVersion(ctx, opts.HTTPClient, opts.MetaBaseURL, vanilla.MinecraftVersion, opts.LoaderVersion)
	if err != nil {
		return loaderMaterializeResult{}, err
	}
	selectedLoader := selectedEntry.Loader.Version
	profileURL := fmt.Sprintf("%s/versions/loader/%s/%s/profile/json", strings.TrimRight(opts.MetaBaseURL, "/"), vanilla.MinecraftVersion, selectedLoader)
	profileBytes, err := fetchJSONBytes(ctx, opts.HTTPClient, profileURL, 16<<20)
	if err != nil {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile: %w", loader, err)
	}
	var profile loaderVersionProfile
	if err := json.Unmarshal(profileBytes, &profile); err != nil {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile JSON повреждён: %w", loader, err)
	}
	if profile.ID == "" {
		profile.ID = fmt.Sprintf("%s-loader-%s-%s", loader, selectedLoader, vanilla.MinecraftVersion)
	}
	if err := validateLoaderProfileID(profile.ID); err != nil {
		return loaderMaterializeResult{}, err
	}
	if profile.InheritsFrom == "" {
		profile.InheritsFrom = vanilla.MinecraftVersion
	}
	if profile.InheritsFrom != vanilla.MinecraftVersion {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile inheritsFrom=%s, ожидался %s", loader, profile.InheritsFrom, vanilla.MinecraftVersion)
	}
	if profile.MainClass == "" {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile не содержит mainClass", loader)
	}
	if len(profile.Libraries) == 0 {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile не содержит libraries", loader)
	}
	if selectedEntry.Loader.Maven != "" && !profileHasLibrary(profile.Libraries, selectedEntry.Loader.Maven) {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile не содержит выбранный loader artifact %s", loader, selectedEntry.Loader.Maven)
	}
	if selectedEntry.Intermediary.Maven != "" && !profileHasLibrary(profile.Libraries, selectedEntry.Intermediary.Maven) {
		return loaderMaterializeResult{}, fmt.Errorf("%s profile не содержит intermediary artifact %s", loader, selectedEntry.Intermediary.Maven)
	}
	if profile.Type == "" {
		profile.Type = "release"
	}

	files, err := materializeLoaderLibraries(ctx, opts.HTTPClient, opts.ClientDir, &profile, opts.Workers, opts.StrictUpstream)
	if err != nil {
		return loaderMaterializeResult{}, err
	}
	profileBytes, err = json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return loaderMaterializeResult{}, err
	}
	profileBytes = append(profileBytes, '\n')
	profilePath := filepath.ToSlash(filepath.Join("versions", profile.ID, profile.ID+".json"))
	if err := writeAtomicBytes(filepath.Join(opts.ClientDir, filepath.FromSlash(profilePath)), profileBytes, 0o644); err != nil {
		return loaderMaterializeResult{}, err
	}
	profileSHA := sha256.Sum256(profileBytes)
	files = append(files, vanillaDownloadedFile{
		Path:   profilePath,
		Kind:   loader + "-profile",
		Size:   int64(len(profileBytes)),
		SHA256: hex.EncodeToString(profileSHA[:]),
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	downloaded, cached := 0, 0
	var total int64
	for _, file := range files {
		if file.Cached {
			cached++
		} else if strings.HasPrefix(file.Kind, loader+"-") && file.Kind != loader+"-profile" {
			downloaded++
		}
		total += file.Size
	}
	state := map[string]any{
		"schemaVersion":    "1.0",
		"toolVersion":      version,
		"loader":           loader,
		"minecraftVersion": vanilla.MinecraftVersion,
		"loaderVersion":    selectedLoader,
		"profileId":        profile.ID,
		"profilePath":      profilePath,
		"profileSha256":    hex.EncodeToString(profileSHA[:]),
		"status":           "installed-and-verified",
	}
	stateBytes, _ := json.MarshalIndent(state, "", "  ")
	statePath := filepath.Join(opts.ClientDir, ".neverlauncher", loader+"-install.json")
	if err := writeAtomicBytes(statePath, append(stateBytes, '\n'), 0o600); err != nil {
		return loaderMaterializeResult{}, err
	}

	return loaderMaterializeResult{
		SchemaVersion:    "1.0",
		ToolVersion:      version,
		Loader:           loader,
		MinecraftVersion: vanilla.MinecraftVersion,
		LoaderVersion:    selectedLoader,
		ProfileID:        profile.ID,
		ProfilePath:      profilePath,
		MainClass:        profile.MainClass,
		ClientDir:        opts.ClientDir,
		JavaMajorVersion: vanilla.JavaMajorVersion,
		LibraryCount:     len(profile.Libraries),
		Downloaded:       downloaded,
		Cached:           cached,
		TotalBytes:       total,
		ProfileSHA256:    hex.EncodeToString(profileSHA[:]),
		Vanilla:          vanilla,
		Files:            files,
		Status:           "installed-and-verified",
	}, nil
}

func resolveMetaLoaderVersion(ctx context.Context, client *http.Client, metaBase, minecraftVersion, requested string) (loaderMetaEntry, error) {
	url := fmt.Sprintf("%s/versions/loader/%s", strings.TrimRight(metaBase, "/"), minecraftVersion)
	data, err := fetchJSONBytes(ctx, client, url, 16<<20)
	if err != nil {
		return loaderMetaEntry{}, fmt.Errorf("loader version metadata: %w", err)
	}
	var entries []loaderMetaEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return loaderMetaEntry{}, fmt.Errorf("loader version metadata повреждены: %w", err)
	}
	if len(entries) == 0 {
		return loaderMetaEntry{}, fmt.Errorf("для Minecraft %s нет совместимых loader versions", minecraftVersion)
	}
	requested = strings.TrimSpace(requested)
	if requested == "" || requested == "latest" || requested == "latest-stable" || requested == "stable" || requested == "recommended" {
		for _, entry := range entries {
			if entry.Loader.Version != "" && entry.Loader.Stable {
				return entry, nil
			}
		}
		for _, entry := range entries {
			if entry.Loader.Version != "" {
				return entry, nil
			}
		}
		return loaderMetaEntry{}, errors.New("Meta API не вернул loader.version")
	}
	for _, entry := range entries {
		if entry.Loader.Version == requested {
			return entry, nil
		}
	}
	return loaderMetaEntry{}, fmt.Errorf("loader %s несовместим с Minecraft %s по Meta API", requested, minecraftVersion)
}

func profileHasLibrary(libraries []MojangLibrary, coordinate string) bool {
	coordinate = strings.TrimSpace(coordinate)
	for _, library := range libraries {
		if strings.TrimSpace(library.Name) == coordinate {
			return true
		}
	}
	return false
}

func validateLoaderProfileID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\\`) {
		return fmt.Errorf("loader profile id некорректен: %q", id)
	}
	return nil
}

func materializeLoaderLibraries(ctx context.Context, client *http.Client, clientDir string, profile *loaderVersionProfile, workers int, strict bool) ([]vanillaDownloadedFile, error) {
	if workers < 1 {
		workers = 12
	}
	tasks := make([]vanillaDownloadTask, 0, len(profile.Libraries))
	seen := map[string]string{}
	for index := range profile.Libraries {
		lib := &profile.Libraries[index]
		if strings.TrimSpace(lib.Name) == "" {
			return nil, fmt.Errorf("loader profile library[%d] не содержит name", index)
		}
		artifact := lib.Downloads.Artifact
		rel := strings.TrimSpace(artifact.Path)
		if rel == "" {
			var err error
			rel, err = strictMavenPath(lib.Name)
			if err != nil {
				return nil, fmt.Errorf("library %s: %w", lib.Name, err)
			}
		}
		rel = strings.TrimPrefix(filepath.ToSlash(rel), "libraries/")
		if err := validateVanillaRelativePath(rel); err != nil {
			return nil, fmt.Errorf("library %s path: %w", lib.Name, err)
		}
		artifactURL := strings.TrimSpace(artifact.URL)
		if artifactURL == "" {
			base := strings.TrimSpace(lib.URL)
			if base == "" {
				return nil, fmt.Errorf("loader library %s не содержит Maven repository URL", lib.Name)
			}
			artifactURL = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(rel, "/")
		}
		if err := validateRemoteURL(artifactURL); err != nil {
			return nil, fmt.Errorf("loader library %s URL: %w", lib.Name, err)
		}
		expectedSHA1 := strings.ToLower(strings.TrimSpace(artifact.SHA1))
		if expectedSHA1 == "" {
			shaURL := artifactURL + ".sha1"
			shaBytes, err := fetchLimitedBytes(ctx, client, shaURL, 64<<10)
			if err != nil {
				if strict {
					return nil, fmt.Errorf("loader library %s: не удалось получить SHA-1: %w", lib.Name, err)
				}
			} else {
				expectedSHA1 = parseSHA1Sidecar(string(shaBytes))
			}
		}
		if strict && !validSHA1Hex(expectedSHA1) {
			return nil, fmt.Errorf("loader library %s: Maven repository не предоставил корректный SHA-1", lib.Name)
		}
		if expectedSHA1 != "" && !validSHA1Hex(expectedSHA1) {
			return nil, fmt.Errorf("loader library %s: некорректный SHA-1", lib.Name)
		}
		path := "libraries/" + rel
		if previous, ok := seen[path]; ok {
			if previous != expectedSHA1 {
				return nil, fmt.Errorf("loader profile содержит конфликтующие artifacts для %s", path)
			}
		} else {
			seen[path] = expectedSHA1
			tasks = append(tasks, vanillaDownloadTask{Path: path, URL: artifactURL, SHA1: expectedSHA1, Size: artifact.Size, Kind: "loader-library"})
		}
		lib.Downloads.Artifact = MojangDownload{Path: rel, URL: artifactURL, SHA1: expectedSHA1, Size: artifact.Size}
	}

	files, err := runVanillaDownloads(ctx, client, clientDir, tasks, workers)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]vanillaDownloadedFile, len(files))
	for _, file := range files {
		byPath[file.Path] = file
	}
	for index := range profile.Libraries {
		lib := &profile.Libraries[index]
		rel := strings.TrimPrefix(filepath.ToSlash(lib.Downloads.Artifact.Path), "libraries/")
		path := "libraries/" + rel
		file, ok := byPath[path]
		if !ok {
			return nil, fmt.Errorf("loader library %s не материализована", lib.Name)
		}
		artifact := lib.Downloads.Artifact
		artifact.Size = file.Size
		if artifact.SHA1 == "" {
			artifact.SHA1 = file.SHA1
		}
		lib.Downloads.Artifact = artifact
	}
	return files, nil
}

func strictMavenPath(name string) (string, error) {
	parts := strings.Split(strings.TrimSpace(name), ":")
	if len(parts) < 3 || len(parts) > 4 {
		return "", fmt.Errorf("Maven coordinate %q должен иметь group:artifact:version[:classifier]", name)
	}
	for _, part := range parts[:3] {
		if strings.TrimSpace(part) == "" || strings.ContainsAny(part, `/\\`) {
			return "", fmt.Errorf("Maven coordinate %q содержит недопустимую часть", name)
		}
	}
	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact, ver := parts[1], parts[2]
	classifier := ""
	if len(parts) == 4 {
		if strings.TrimSpace(parts[3]) == "" || strings.ContainsAny(parts[3], `/\\`) {
			return "", fmt.Errorf("Maven coordinate %q содержит недопустимый classifier", name)
		}
		classifier = "-" + parts[3]
	}
	return filepath.ToSlash(filepath.Join(group, artifact, ver, artifact+"-"+ver+classifier+".jar")), nil
}

func fetchLimitedBytes(ctx context.Context, client *http.Client, rawURL string, max int64) ([]byte, error) {
	if err := validateRemoteURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NeverLauncher/"+version+" LoaderMaterializer")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	reader := io.LimitReader(resp.Body, max+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("response превышает лимит %d bytes", max)
	}
	return data, nil
}

func parseSHA1Sidecar(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return ""
	}
	candidate := strings.ToLower(strings.TrimSpace(fields[0]))
	if validSHA1Hex(candidate) {
		return candidate
	}
	return ""
}

func validSHA1Hex(value string) bool {
	if len(value) != sha1.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
