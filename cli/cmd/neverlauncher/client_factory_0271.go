package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The factory uses the existing, tested materializers as executable install
// adapters. Its lock is an immutable receipt for exact inputs and on-disk
// outputs, not an optimistic description of what an installer might produce.
const factoryPlanSchema0271 = "neverlauncher.client-factory.install-plan.v1"

type factorySource0271 struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	URL    string `json:"url"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type factoryOutput0271 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type factoryProcessor0271 struct {
	Index          int                 `json:"index"`
	IdentitySHA256 string              `json:"identitySha256"`
	Jar            string              `json:"jar"`
	Classpath      []string            `json:"classpath"`
	Arguments      []string            `json:"arguments"`
	Outputs        []factoryOutput0271 `json:"outputs"`
}
type factoryStep0271 struct {
	ID       string   `json:"id"`
	Adapter  string   `json:"adapter"`
	Requires []string `json:"requires,omitempty"`
}
type factoryJava0271 struct {
	Major                     int    `json:"major"`
	ProcessorExecutableSHA256 string `json:"processorExecutableSha256,omitempty"`
}
type factoryResolution0271 struct {
	Selector          string `json:"selector"`
	ArtifactVersion   string `json:"artifactVersion,omitempty"`
	SourceURL         string `json:"sourceUrl"`
	SourceSHA256      string `json:"sourceSha256"`
	PayloadURL        string `json:"payloadUrl"`
	PayloadSHA256     string `json:"payloadSha256"`
	ProfileSHA256     string `json:"profileSha256"`
	ResolvedVersion   string `json:"resolvedVersion,omitempty"`
	LoaderMaven       string `json:"loaderMaven,omitempty"`
	IntermediaryMaven string `json:"intermediaryMaven,omitempty"`
}
type factoryLaunch0271 struct {
	ProfilePath      string `json:"profilePath"`
	MainClass        string `json:"mainClass"`
	AssetIndex       string `json:"assetIndex"`
	NativesDirectory string `json:"nativesDirectory"`
}
type factoryPlan0271 struct {
	SchemaVersion          string                   `json:"schemaVersion"`
	MinecraftVersion       string                   `json:"minecraftVersion"`
	MinecraftReleaseType   string                   `json:"minecraftReleaseType,omitempty"`
	Loader                 string                   `json:"loader"`
	LoaderVersion          string                   `json:"loaderVersion,omitempty"`
	Targets                []vanillaTarget          `json:"targets"`
	Java                   factoryJava0271          `json:"java"`
	Launch                 factoryLaunch0271        `json:"launch"`
	Steps                  []factoryStep0271        `json:"steps"`
	Sources                []factorySource0271      `json:"sources"`
	Processors             []factoryProcessor0271   `json:"processors"`
	Outputs                []factoryOutput0271      `json:"outputs"`
	LoaderResolutionSHA256 string                   `json:"loaderResolutionSha256,omitempty"`
	Resolution             *factoryResolution0271   `json:"resolution,omitempty"`
	Legacy                 *legacyLaunch0278        `json:"legacy,omitempty"`
	Compatibility          *compatLock0279          `json:"compatibility,omitempty"`
	AdapterPins            []factoryAdapterPin02711 `json:"adapterPins,omitempty"`
	ReproducibilitySHA256  string                   `json:"reproducibilitySha256"`
}
type factoryBuildOptions0271 struct {
	Loader                string
	Minecraft             string
	LoaderVersion         string
	ClientDir             string
	VersionManifest       string
	AssetBaseURL          string
	LibraryBaseURL        string
	MetaBaseURL           string
	InstallerURL          string
	InstallerSHA1         string
	InstallerSourceFile   string
	InstallerSourceSHA256 string
	MavenMetadataURL      string
	JavaExecutable        string
	ProcessorTimeout      time.Duration
	ProcessorSandbox      string
	Targets               []vanillaTarget
	Workers               int
	StrictUpstream        bool
	UpgradeAdapters       bool
	SharedCacheDir        string
	HTTPClient            *http.Client
}
type factoryRecorderKey0271 struct{}
type factoryRecorder0271 struct {
	mu         sync.Mutex
	sources    map[string]factorySource0271
	processors map[string]factoryProcessor0271
}

func factoryRecorderFromContext0271(ctx context.Context) *factoryRecorder0271 {
	if rec, ok := ctx.Value(factoryRecorderKey0271{}).(*factoryRecorder0271); ok {
		return rec
	}
	return nil
}
func (r *factoryRecorder0271) recordSource(s factorySource0271) error {
	if r == nil {
		return nil
	}
	if err := validateVanillaRelativePath(s.Path); err != nil {
		return err
	}
	if s.URL == "" || !isSHA256Hex0271(s.SHA256) || s.Size < 0 {
		return fmt.Errorf("invalid recorded source %s", s.Path)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, exists := r.sources[s.Path]; exists {
		if prev.SHA256 != s.SHA256 || prev.Size != s.Size {
			return fmt.Errorf("source %s changed during the same install", s.Path)
		}
		return nil // identical bytes can be used by multiple adapters
	}
	r.sources[s.Path] = s
	return nil
}
func (r *factoryRecorder0271) recordTasks(tasks []vanillaDownloadTask, files []vanillaDownloadedFile) error {
	if r == nil {
		return nil
	}
	byPath := make(map[string]vanillaDownloadedFile, len(files))
	for _, f := range files {
		byPath[f.Path] = f
	}
	for _, t := range tasks {
		f, ok := byPath[t.Path]
		if !ok {
			return fmt.Errorf("factory source %s not downloaded", t.Path)
		}
		if err := r.recordSource(factorySource0271{Path: t.Path, Kind: t.Kind, URL: t.URL, SHA1: strings.ToLower(f.SHA1), SHA256: f.SHA256, Size: f.Size}); err != nil {
			return err
		}
	}
	return nil
}
func (r *factoryRecorder0271) recordProcessor(pc forgeProcessorContext, index int, p forgeProcessor) error {
	if r == nil {
		return nil
	}
	out := make([]factoryOutput0271, 0, len(p.Outputs))
	for token := range p.Outputs {
		full, err := resolveProcessorToken(pc, token)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(pc.ClientDir, full)
		if err != nil || validateVanillaRelativePath(filepath.ToSlash(rel)) != nil {
			return fmt.Errorf("processor[%d] output escapes client root: %s", index, token)
		}
		sum, size, err := hashFile(full)
		if err != nil {
			return err
		}
		out = append(out, factoryOutput0271{Path: filepath.ToSlash(rel), SHA256: sum, Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	entry := factoryProcessor0271{Index: index, IdentitySHA256: forgeProcessorIdentity(pc, index, p), Jar: p.Jar, Classpath: append([]string{}, p.Classpath...), Arguments: append([]string{}, p.Args...), Outputs: out}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strconv.Itoa(index)
	r.processors[key] = entry
	return nil
}
func isSHA256Hex0271(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func factoryDigest0271(p factoryPlan0271) (string, error) {
	p.ReproducibilitySHA256 = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func factoryPlanPath0271(root string) string {
	return filepath.Join(root, ".neverlauncher", "install-plan.json")
}
func readFactoryPlan0271(root string) (factoryPlan0271, error) {
	var p factoryPlan0271
	raw, err := os.ReadFile(factoryPlanPath0271(root))
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if err = validateFactoryPlan0271(p); err != nil {
		return p, err
	}
	return p, nil
}
func validateFactoryPlan0271(p factoryPlan0271) error {
	if p.SchemaVersion != factoryPlanSchema0271 {
		return fmt.Errorf("unsupported factory schema %q", p.SchemaVersion)
	}
	if p.Loader != "vanilla" && p.Loader != "fabric" && p.Loader != "quilt" && p.Loader != "forge" && p.Loader != "neoforge" {
		return errors.New("unknown factory loader")
	}
	if strings.TrimSpace(p.MinecraftVersion) == "" || isMutableMinecraft0271(p.MinecraftVersion) || p.Java.Major < 1 || p.Launch.MainClass == "" {
		return errors.New("incomplete factory launch identity")
	}
	if p.MinecraftReleaseType != "" && p.MinecraftReleaseType != "release" && p.MinecraftReleaseType != "snapshot" && p.MinecraftReleaseType != "old_beta" && p.MinecraftReleaseType != "old_alpha" {
		return fmt.Errorf("invalid Minecraft release type %q", p.MinecraftReleaseType)
	}
	if len(p.Targets) == 0 || !reflect.DeepEqual(p.Steps, factorySteps0271(p.Loader)) || len(p.Sources) == 0 || len(p.Outputs) == 0 {
		return errors.New("factory plan has no targets, executable steps or outputs")
	}
	if err := factoryAdapterTargetCheck02711(p); err != nil {
		return err
	}
	if err := validateFactoryAdapterPins02711(p); err != nil {
		return err
	}
	if p.Loader != "vanilla" && (p.LoaderVersion == "" || isMutableLoaderSelector(p.LoaderVersion) || !isSHA256Hex0271(p.LoaderResolutionSHA256) || p.Resolution == nil || !isSHA256Hex0271(p.Resolution.SourceSHA256) || !isSHA256Hex0271(p.Resolution.PayloadSHA256) || !isSHA256Hex0271(p.Resolution.ProfileSHA256)) {
		return errors.New("factory loader is not pinned")
	}
	if p.Resolution != nil && p.Resolution.ResolvedVersion != "" && p.Resolution.ResolvedVersion != p.LoaderVersion {
		return errors.New("factory loader resolution version disagrees with plan")
	}
	seen := map[string]bool{}
	for _, o := range p.Outputs {
		if err := validateVanillaRelativePath(o.Path); err != nil {
			return err
		}
		if seen[o.Path] || !isSHA256Hex0271(o.SHA256) || o.Size < 0 {
			return fmt.Errorf("invalid/duplicate factory output %s", o.Path)
		}
		seen[o.Path] = true
	}
	seenSources := map[string]bool{}
	for _, s := range p.Sources {
		if seenSources[s.Path] {
			return fmt.Errorf("duplicate factory source %s", s.Path)
		}
		seenSources[s.Path] = true
		if err := validateVanillaRelativePath(s.Path); err != nil {
			return err
		}
		if s.URL == "" || !isSHA256Hex0271(s.SHA256) || s.Size < 0 || (s.SHA1 != "" && !validSHA1Hex(s.SHA1)) {
			return fmt.Errorf("invalid factory source %s", s.Path)
		}
	}
	digest, err := factoryDigest0271(p)
	if err != nil {
		return err
	}
	if digest != p.ReproducibilitySHA256 {
		return fmt.Errorf("factory plan digest mismatch: %s != %s", p.ReproducibilitySHA256, digest)
	}
	return nil
}

// Only data files participate in the reproducibility hash. Materializer logs,
// temporary downloads, journals, state paths and lock files are excluded.
func scanFactoryOutputs0271(root string) ([]factoryOutput0271, error) {
	outputs := []factoryOutput0271{}
	err := filepath.WalkDir(root, func(full string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		normalized := filepath.ToSlash(rel)
		if normalized == ".neverlauncher" && d.IsDir() {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not allowed in reproducible factory output: %s", normalized)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular factory output %s", normalized)
		}
		if err := validateVanillaRelativePath(normalized); err != nil {
			return err
		}
		sum, size, err := hashFile(full)
		if err != nil {
			return err
		}
		outputs = append(outputs, factoryOutput0271{Path: normalized, SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Path < outputs[j].Path })
	return outputs, nil
}
func verifyFactoryPlan0271(root string, p factoryPlan0271) error {
	if err := validateFactoryPlan0271(p); err != nil {
		return err
	}
	if p.Loader != "vanilla" {
		lock := defaultLoaderResolutionLockPath(root, p.Loader)
		raw, err := os.ReadFile(lock)
		if err != nil {
			return fmt.Errorf("loader resolution lock: %w", err)
		}
		if sha256HexBytes(raw) != p.LoaderResolutionSHA256 {
			return errors.New("loader resolution lock has changed")
		}
		var resolution loaderResolutionLock
		if err := json.Unmarshal(raw, &resolution); err != nil {
			return err
		}
		if resolution.ResolutionSourceSHA256 != p.Resolution.SourceSHA256 || resolution.PayloadSHA256 != p.Resolution.PayloadSHA256 || resolution.RuntimeProfileSHA256 != p.Resolution.ProfileSHA256 || (p.Resolution.ResolvedVersion != "" && resolution.ResolvedVersion != p.Resolution.ResolvedVersion) || (p.Resolution.LoaderMaven != "" && resolution.LoaderMaven != p.Resolution.LoaderMaven) || (p.Resolution.IntermediaryMaven != "" && resolution.IntermediaryMaven != p.Resolution.IntermediaryMaven) {
			return errors.New("loader resolution details differ from InstallPlan")
		}
	}
	for _, src := range p.Sources {
		if !strings.HasPrefix(src.Path, ".neverlauncher/") {
			continue
		}
		full, err := secureClientDestination(root, src.Path)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(full)
		if err != nil {
			return err
		}
		if sum != src.SHA256 || size != src.Size {
			return fmt.Errorf("factory internal source has changed: %s", src.Path)
		}
	}
	actual, err := scanFactoryOutputs0271(root)
	if err != nil {
		return err
	}
	if len(actual) != len(p.Outputs) {
		return fmt.Errorf("factory output count mismatch: locked=%d actual=%d", len(p.Outputs), len(actual))
	}
	for i, a := range actual {
		if a != p.Outputs[i] {
			return fmt.Errorf("factory output mismatch: expected %+v got %+v", p.Outputs[i], a)
		}
	}
	if err := verifyLegacyLaunch0278(root, p); err != nil {
		return fmt.Errorf("legacy launch verification: %w", err)
	}
	if err := verifyCompat0279(root, p); err != nil {
		return fmt.Errorf("authlib/classloader verification: %w", err)
	}
	if err := verifyAuthlibProvenance0279(root, p); err != nil {
		return fmt.Errorf("authlib provenance verification: %w", err)
	}
	return nil
}
func normalizedFactoryOptions0271(o factoryBuildOptions0271) (factoryBuildOptions0271, error) {
	o.Loader = strings.ToLower(strings.TrimSpace(o.Loader))
	if o.Loader == "" {
		o.Loader = "vanilla"
	}
	switch o.Loader {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		return o, fmt.Errorf("unsupported factory adapter %s", o.Loader)
	}
	if strings.TrimSpace(o.ClientDir) == "" {
		return o, errors.New("factory --client-dir required")
	}
	if strings.TrimSpace(o.Minecraft) == "" {
		return o, errors.New("factory --minecraft required")
	}
	if !o.StrictUpstream {
		return o, errors.New("Client Factory requires strict upstream checksum verification")
	}
	if o.Workers == 0 {
		o.Workers = 12
	}
	if o.Workers < 1 || o.Workers > 64 {
		return o, errors.New("workers must be between 1 and 64")
	}
	if o.LoaderVersion == "" && o.Loader != "vanilla" {
		o.LoaderVersion = "latest-stable"
	}
	if len(o.Targets) == 0 {
		o.Targets = []vanillaTarget{currentVanillaTarget()}
	}
	seen := map[string]bool{}
	normalized := []vanillaTarget{}
	for _, target := range o.Targets {
		n, err := normalizeVanillaTarget(target)
		if err != nil {
			return o, err
		}
		k := n.OS + "/" + n.Arch
		if !seen[k] {
			normalized = append(normalized, n)
			seen[k] = true
		}
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].OS+normalized[i].Arch < normalized[j].OS+normalized[j].Arch })
	o.Targets = normalized
	if o.VersionManifest == "" {
		o.VersionManifest = defaultMojangVersionManifest
	}
	if o.AssetBaseURL == "" {
		o.AssetBaseURL = defaultMojangAssetBase
	}
	if o.LibraryBaseURL == "" {
		o.LibraryBaseURL = defaultMojangLibraryBase
	}
	if o.HTTPClient == nil {
		o.HTTPClient = secureHTTPClient()
	}
	if o.ProcessorTimeout == 0 {
		o.ProcessorTimeout = 10 * time.Minute
	}
	if o.ProcessorTimeout < time.Second || o.ProcessorTimeout > time.Hour {
		return o, errors.New("processor timeout must be between 1s and 1h")
	}
	if o.ProcessorSandbox != "" && o.ProcessorSandbox != "process" && o.ProcessorSandbox != "required" {
		return o, errors.New("processor sandbox must be process or required")
	}
	return o, nil
}
func isMutableMinecraft0271(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "latest", "latest-release", "latest-snapshot", "release", "snapshot":
		return true
	default:
		return false
	}
}

func factorySteps0271(loader string) []factoryStep0271 {
	s := []factoryStep0271{{ID: "vanilla", Adapter: "vanilla"}}
	prev := "vanilla"
	if loader != "vanilla" {
		s = append(s, factoryStep0271{ID: "loader", Adapter: loader, Requires: []string{prev}})
		prev = "loader"
	}
	return append(s, factoryStep0271{ID: "verify", Adapter: "sha256-verify", Requires: []string{prev}}, factoryStep0271{ID: "publish", Adapter: "atomic-publish", Requires: []string{"verify"}})
}

// A sibling lock remains effective while root is atomically replaced.
func acquireFactoryLock0271(dst string) (func(), error) {
	lockPath := dst + ".client-factory.lock"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("factory client directory is locked (%s): %w", lockPath, err)
	}
	_, _ = fmt.Fprintf(f, "pid=%d\nstarted=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	if err = f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(lockPath)
		return nil, err
	}
	_ = f.Close()
	return func() { _ = os.Remove(lockPath) }, nil
}
func copyFactoryExisting0271(from, to string) error {
	info, err := os.Lstat(from)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("factory destination is not a regular directory")
	}
	return filepath.WalkDir(from, func(src string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(from, src)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if filepath.ToSlash(rel) == ".neverlauncher/materialize.lock" {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains symlink %s", rel)
		}
		dest := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("source contains nonregular file %s", rel)
		}
		fin, err := os.Open(src)
		if err != nil {
			return err
		}
		st, err := d.Info()
		if err != nil {
			_ = fin.Close()
			return err
		}
		if err = os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			_ = fin.Close()
			return err
		}
		fout, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, st.Mode().Perm())
		if err != nil {
			_ = fin.Close()
			return err
		}
		_, copyErr := io.Copy(fout, fin)
		if copyErr == nil {
			copyErr = fout.Sync()
		}
		closeErr := fout.Close()
		_ = fin.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
func executeFactoryBuild0271(ctx context.Context, raw factoryBuildOptions0271) (factoryPlan0271, error) {
	o, err := normalizedFactoryOptions0271(raw)
	if err != nil {
		return factoryPlan0271{}, err
	}
	dst, err := filepath.Abs(o.ClientDir)
	if err != nil {
		return factoryPlan0271{}, err
	}
	ctx, err = sharedArtifactsContext0277(ctx, o.SharedCacheDir, dst)
	if err != nil {
		return factoryPlan0271{}, err
	}
	release, err := acquireFactoryLock0271(dst)
	if err != nil {
		return factoryPlan0271{}, err
	}
	defer release()
	prior, readErr := readFactoryPlan0271(dst)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return factoryPlan0271{}, fmt.Errorf("cannot trust existing install-plan: %w", readErr)
	}
	hasPrior := readErr == nil
	if hasPrior {
		if !o.UpgradeAdapters {
			if err := requireCurrentFactoryAdapters02711(prior); err != nil {
				return factoryPlan0271{}, fmt.Errorf("explicit adapter upgrade required (--upgrade-adapters): %w", err)
			}
		}
		if prior.Loader != o.Loader {
			return factoryPlan0271{}, fmt.Errorf("locked loader %s is not %s", prior.Loader, o.Loader)
		}
		if o.Minecraft != prior.MinecraftVersion && !isMutableMinecraft0271(o.Minecraft) {
			return factoryPlan0271{}, errors.New("locked Minecraft version differs from requested version")
		}
		if o.Loader != "vanilla" && o.LoaderVersion != prior.LoaderVersion && !isMutableLoaderSelector(o.LoaderVersion) {
			return factoryPlan0271{}, errors.New("locked loader version differs from requested version")
		}
		if len(o.Targets) != len(prior.Targets) {
			return factoryPlan0271{}, errors.New("locked targets differ")
		}
		for i, t := range o.Targets {
			if t != prior.Targets[i] {
				return factoryPlan0271{}, errors.New("locked target differs")
			}
		}
		if err := verifyFactoryPlan0271(dst, prior); err != nil {
			return factoryPlan0271{}, fmt.Errorf("existing factory build is corrupt: %w", err)
		}
		o.Minecraft = prior.MinecraftVersion
		if o.Loader != "vanilla" {
			o.LoaderVersion = prior.LoaderVersion
		}
	} else if _, err := os.Stat(dst); err == nil {
		entries, err := os.ReadDir(dst)
		if err != nil {
			return factoryPlan0271{}, err
		}
		if len(entries) > 0 {
			return factoryPlan0271{}, errors.New("factory requires an empty destination or an existing verified install-plan; use a separate directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return factoryPlan0271{}, err
	}
	// Sibling staging makes failure non-destructive; no file in the destination
	// is modified until every step and SHA-256 has been verified.
	staging, err := os.MkdirTemp(filepath.Dir(dst), ".factory-staging-")
	if err != nil {
		return factoryPlan0271{}, err
	}
	defer os.RemoveAll(staging)
	if hasPrior {
		if err := copyFactoryExisting0271(dst, staging); err != nil {
			return factoryPlan0271{}, err
		}
		if o.UpgradeAdapters && !reflect.DeepEqual(prior.AdapterPins, currentFactoryAdapterPins02711(o.Loader)) {
			if err := invalidateFactoryProcessorRecovery02711(staging, o.Loader); err != nil {
				return factoryPlan0271{}, err
			}
		}
	}
	rec := &factoryRecorder0271{sources: map[string]factorySource0271{}, processors: map[string]factoryProcessor0271{}}
	ctx = context.WithValue(ctx, factoryRecorderKey0271{}, rec)
	base := vanillaInstallOptions{MinecraftVersion: o.Minecraft, ClientDir: staging, VersionManifest: o.VersionManifest, AssetBaseURL: o.AssetBaseURL, LibraryBaseURL: o.LibraryBaseURL, Targets: o.Targets, Workers: o.Workers, StrictUpstream: o.StrictUpstream, HTTPClient: o.HTTPClient}
	var vanilla vanillaInstallResult
	var loaderVersion, profilePath, mainClass, loaderResolutionSHA, processorExecutableSHA string
	var resolvedIdentity *factoryResolution0271
	// One executor, shared context, shared source recorder and output verifier.
	switch o.Loader {
	case "vanilla":
		vanilla, err = installVanilla(ctx, base)
		if err != nil {
			return factoryPlan0271{}, err
		}
		profilePath = filepath.ToSlash(filepath.Join("versions", vanilla.MinecraftVersion, vanilla.MinecraftVersion+".json"))
		mainClass = vanilla.MainClass
	case "fabric", "quilt":
		result, e := installMetaLoader(ctx, loaderMaterializeOptions{Loader: o.Loader, MinecraftVersion: o.Minecraft, LoaderVersion: o.LoaderVersion, ClientDir: staging, VersionManifest: o.VersionManifest, AssetBaseURL: o.AssetBaseURL, LibraryBaseURL: o.LibraryBaseURL, MetaBaseURL: o.MetaBaseURL, Targets: o.Targets, Workers: o.Workers, StrictUpstream: o.StrictUpstream, HTTPClient: o.HTTPClient})
		if e != nil {
			return factoryPlan0271{}, e
		}
		vanilla = result.Vanilla
		loaderVersion = result.LoaderVersion
		profilePath = result.ProfilePath
		mainClass = result.MainClass
	case "forge", "neoforge":
		result, e := installForgeLike(ctx, forgeMaterializeOptions{Loader: o.Loader, MinecraftVersion: o.Minecraft, LoaderVersion: o.LoaderVersion, ClientDir: staging, JavaExecutable: o.JavaExecutable, InstallerURL: o.InstallerURL, InstallerSHA1: o.InstallerSHA1, InstallerSourceFile: o.InstallerSourceFile, InstallerSourceSHA256: o.InstallerSourceSHA256, MavenMetadataURL: o.MavenMetadataURL, VersionManifest: o.VersionManifest, AssetBaseURL: o.AssetBaseURL, LibraryBaseURL: o.LibraryBaseURL, Targets: o.Targets, Workers: o.Workers, StrictUpstream: o.StrictUpstream, ProcessorTimeout: o.ProcessorTimeout, ProcessorSandbox: o.ProcessorSandbox, HTTPClient: o.HTTPClient})
		if e != nil {
			return factoryPlan0271{}, e
		}
		vanilla = result.Vanilla
		loaderVersion = result.LoaderVersion
		profilePath = result.ProfilePath
		mainClass = result.MainClass
		installerRel := filepath.ToSlash(filepath.Join(".neverlauncher", "installers", o.Loader, sanitizeVersionToken(result.ArtifactVersion), "installer.jar"))
		pinned, e := readLoaderResolutionLock(defaultLoaderResolutionLockPath(staging, o.Loader), o.Loader, vanilla.MinecraftVersion, o.LoaderVersion)
		if e != nil || pinned == nil {
			return factoryPlan0271{}, fmt.Errorf("missing Forge installer evidence: %v", e)
		}
		if e = rec.recordSource(factorySource0271{Path: installerRel, Kind: o.Loader + "-installer", URL: pinned.PayloadURL, SHA256: pinned.PayloadSHA256, Size: factoryFileSize0271(filepath.Join(staging, filepath.FromSlash(installerRel)))}); e != nil {
			return factoryPlan0271{}, e
		}
	}
	if o.Loader != "vanilla" {
		rawLock, e := os.ReadFile(defaultLoaderResolutionLockPath(staging, o.Loader))
		if e != nil {
			return factoryPlan0271{}, e
		}
		loaderResolutionSHA = sha256HexBytes(rawLock)
		var lock loaderResolutionLock
		if err := json.Unmarshal(rawLock, &lock); err != nil {
			return factoryPlan0271{}, err
		}
		resolvedIdentity = &factoryResolution0271{Selector: lock.Selector, ArtifactVersion: lock.ArtifactVersion, SourceURL: lock.ResolutionSourceURL, SourceSHA256: lock.ResolutionSourceSHA256, PayloadURL: lock.PayloadURL, PayloadSHA256: lock.PayloadSHA256, ProfileSHA256: lock.RuntimeProfileSHA256, ResolvedVersion: lock.ResolvedVersion, LoaderMaven: lock.LoaderMaven, IntermediaryMaven: lock.IntermediaryMaven}
	}
	if o.Loader == "forge" || o.Loader == "neoforge" {
		selected, err := selectInstallerJava(o.JavaExecutable, vanilla.JavaMajorVersion)
		if err != nil {
			return factoryPlan0271{}, err
		}
		processorExecutableSHA, _, err = hashFile(selected)
		if err != nil {
			return factoryPlan0271{}, err
		}
	}
	var legacyRecipe *legacyLaunch0278
	if !hasPrior || prior.Legacy != nil {
		legacyRecipe, err = resolveLegacyLaunch0278(staging, o.Loader, vanilla.MinecraftVersion, profilePath, vanilla.JavaMajorVersion, o.Targets)
	}
	if err != nil {
		return factoryPlan0271{}, err
	}
	if err := writeLegacyLaunch0278(staging, legacyRecipe); err != nil {
		return factoryPlan0271{}, err
	}
	outputs, err := scanFactoryOutputs0271(staging)
	if err != nil {
		return factoryPlan0271{}, err
	}
	sources := make([]factorySource0271, 0, len(rec.sources))
	for _, s := range rec.sources {
		sources = append(sources, s)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	processors := make([]factoryProcessor0271, 0, len(rec.processors))
	for _, p := range rec.processors {
		processors = append(processors, p)
	}
	sort.Slice(processors, func(i, j int) bool { return processors[i].Index < processors[j].Index })
	p := factoryPlan0271{SchemaVersion: factoryPlanSchema0271, MinecraftVersion: vanilla.MinecraftVersion, MinecraftReleaseType: vanilla.ReleaseType, Loader: o.Loader, LoaderVersion: loaderVersion, Targets: o.Targets, Java: factoryJava0271{Major: vanilla.JavaMajorVersion, ProcessorExecutableSHA256: processorExecutableSHA}, Launch: factoryLaunch0271{ProfilePath: profilePath, MainClass: mainClass, AssetIndex: vanilla.AssetIndex, NativesDirectory: "natives"}, Steps: factorySteps0271(o.Loader), Sources: sources, Processors: processors, Outputs: outputs, AdapterPins: currentFactoryAdapterPins02711(o.Loader), LoaderResolutionSHA256: loaderResolutionSHA, Resolution: resolvedIdentity, Legacy: legacyRecipe}
	if hasPrior {
		p.Compatibility = prior.Compatibility
		// Source order and metadata can be re-observed, but previously pinned
		// outputs and loader identity are immutable. This is a true replay.
		if p.MinecraftVersion != prior.MinecraftVersion || p.MinecraftReleaseType != prior.MinecraftReleaseType || p.LoaderVersion != prior.LoaderVersion || p.Java != prior.Java || p.Launch != prior.Launch || p.LoaderResolutionSHA256 != prior.LoaderResolutionSHA256 || !reflect.DeepEqual(p.Resolution, prior.Resolution) || !reflect.DeepEqual(p.Legacy, prior.Legacy) {
			return factoryPlan0271{}, errors.New("rebuild changed pinned runtime identity")
		}
		if !o.UpgradeAdapters {
			if len(p.Outputs) != len(prior.Outputs) {
				return factoryPlan0271{}, errors.New("rebuild changed output count")
			}
			for i := range p.Outputs {
				if p.Outputs[i] != prior.Outputs[i] {
					return factoryPlan0271{}, fmt.Errorf("rebuild changed %s", p.Outputs[i].Path)
				}
			}
			// Preserve the original evidence only on an unchanged adapter replay.
			p.Sources = prior.Sources
			p.Processors = prior.Processors
		} else {
			if err := checkAdapterUpgradeSources02711(prior.Sources, p.Sources); err != nil {
				return factoryPlan0271{}, err
			}
		}
	}
	p.ReproducibilitySHA256, err = factoryDigest0271(p)
	if err != nil {
		return factoryPlan0271{}, err
	}
	if hasPrior && !o.UpgradeAdapters && p.ReproducibilitySHA256 != prior.ReproducibilitySHA256 {
		return factoryPlan0271{}, errors.New("rebuild identity differs from lockfile")
	}
	rawPlan, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return factoryPlan0271{}, err
	}
	if err := writeAtomicBytes(factoryPlanPath0271(staging), append(rawPlan, '\n'), 0o600); err != nil {
		return factoryPlan0271{}, err
	}
	if err := verifyFactoryPlan0271(staging, p); err != nil {
		return factoryPlan0271{}, err
	}
	if err := replaceDirectoryAtomicPortable(staging, dst); err != nil {
		return factoryPlan0271{}, err
	}
	return p, nil
}
func factoryFileSize0271(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return st.Size()
}

func rejectFactoryOutputPath0271(root, output string) error {
	output = strings.TrimSpace(output)
	if output == "" || output == "-" {
		return nil
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absOutput)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("--output must be outside managed client directory (otherwise the lock would become invalid)")
	}
	return nil
}

func handleRuntimeFactory0271(args []string) error {
	if len(args) < 1 {
		return errors.New("runtime client-factory requires build|verify|inspect|install-client|install-mods|download-installer|launch-installer|workspace|apply-workspace|dedup-libraries|lwjgl-download|patch-authlib")
	}
	mode := args[0]
	if mode == "certify-ga" || mode == "ga-sign-join" {
		return handleFactoryGA0280(args)
	}
	if mode == "certify-keygen" || mode == "certify-run" || mode == "certify-verify" || mode == "certify-matrix" {
		return handleRuntimeCertification02712(args)
	}
	if mode != "build" && mode != "verify" && mode != "inspect" {
		if mode == "adapter-inspect" || mode == "adapter-verify" {
			return handleRuntimeFactoryAdapters02711(args)
		}
		if mode == "trusted-install" || mode == "trusted-verify" || mode == "trusted-inspect" || mode == "trusted-remove" {
			return handleTrustedJVM0306(args)
		}
		if mode == "compat-inspect" || mode == "compat-verify" || mode == "compat-apply" {
			return handleRuntimeCompat0279(args)
		}
		if mode == "legacy-inspect" || mode == "legacy-run" {
			return handleRuntimeLegacy0278(args)
		}
		if mode == "verify-publication" || mode == "export-modpack-artifacts" {
			return handlePermissionGates0276(args)
		}
		if mode == "inspect-modpack" || mode == "inspectmodpack" || mode == "import-modpack" || mode == "importmodpack" {
			return handleModpack0275(args)
		}
		return handleRuntimeMirror0274(args)
	}
	args = args[1:]
	dir := strings.TrimSpace(flagValue(args, "--client-dir", ""))
	if dir == "" {
		return errors.New("--client-dir required")
	}
	if err := rejectFactoryOutputPath0271(dir, flagValue(args, "--output", "")); err != nil {
		return err
	}
	switch mode {
	case "verify", "inspect":
		p, err := readFactoryPlan0271(dir)
		if err != nil {
			return err
		}
		if mode == "verify" {
			if err = verifyFactoryPlan0271(dir, p); err != nil {
				return err
			}
			if err = requireCurrentFactoryAdapters02711(p); err != nil {
				return err
			}
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), p)
	case "build":
		targets, err := parseVanillaTargets(flagValue(args, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
		if err != nil {
			return err
		}
		workers, err := strconv.Atoi(flagValue(args, "--workers", "12"))
		if err != nil {
			return err
		}
		timeout, err := time.ParseDuration(flagValue(args, "--processor-timeout", "10m"))
		if err != nil {
			return err
		}
		opts := factoryBuildOptions0271{Loader: flagValue(args, "--loader", "vanilla"), Minecraft: flagValue(args, "--minecraft", "latest-release"), LoaderVersion: flagValue(args, "--loader-version", "latest-stable"), ClientDir: dir, Targets: targets, Workers: workers, StrictUpstream: !strings.EqualFold(flagValue(args, "--strict-upstream", "true"), "false"), UpgradeAdapters: flagBool(args, "--upgrade-adapters", false), VersionManifest: flagValue(args, "--version-manifest", defaultMojangVersionManifest), AssetBaseURL: flagValue(args, "--asset-base-url", defaultMojangAssetBase), LibraryBaseURL: flagValue(args, "--library-base-url", defaultMojangLibraryBase), MetaBaseURL: flagValue(args, "--meta-base-url", ""), InstallerURL: flagValue(args, "--installer-url", ""), InstallerSHA1: flagValue(args, "--installer-sha1", ""), InstallerSourceFile: flagValue(args, "--installer-file", ""), InstallerSourceSHA256: flagValue(args, "--installer-sha256", ""), MavenMetadataURL: flagValue(args, "--maven-metadata-url", ""), JavaExecutable: flagValue(args, "--java", ""), ProcessorTimeout: timeout, ProcessorSandbox: strings.ToLower(strings.TrimSpace(flagValue(args, "--processor-sandbox", "process"))), SharedCacheDir: strings.TrimSpace(flagValue(args, "--shared-cache-dir", ""))}
		p, err := executeFactoryBuild0271(context.Background(), opts)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), p)
	default:
		return fmt.Errorf("unknown client-factory command %s", mode)
	}
}
