package main

// MirrorHelper-equivalent commands are executable operations on the same
// checksum-verified Client Factory tree. They never edit a published tree
// in-place; all modifications go through a checked sibling staging directory.
import (
	"archive/zip"
	"bytes"
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
	"sort"
	"strconv"
	"strings"
	"time"
)

const mirrorActionsPath0274 = ".neverlauncher/mirror-actions.json"

type mirrorArtifact0274 struct {
	Path      string `json:"path"`
	URL       string `json:"url,omitempty"`
	File      string `json:"file,omitempty"`
	SHA256    string `json:"sha256"`
	Side      string `json:"side,omitempty"`
	ProjectID string `json:"projectId,omitempty"`
	VersionID string `json:"versionId,omitempty"`
}
type mirrorWorkspaceLibrary0405 struct {
	Coordinate string `json:"coordinate"`
	URL        string `json:"url,omitempty"`
	File       string `json:"file,omitempty"`
	SHA256     string `json:"sha256"`
}
type mirrorWorkspaceAuthlibPatch0405 struct {
	Target         string `json:"target"`
	Patch          string `json:"patch"`
	BaseSHA256     string `json:"baseSha256"`
	PatchSHA256    string `json:"patchSha256"`
	ExpectedSHA256 string `json:"expectedSha256"`
}
type mirrorWorkspace0274 struct {
	SchemaVersion  string                            `json:"schemaVersion"`
	Minecraft      string                            `json:"minecraft"`
	Loader         string                            `json:"loader"`
	LoaderVersion  string                            `json:"loaderVersion,omitempty"`
	Modpack        string                            `json:"modpack,omitempty"`
	Mods           []mirrorArtifact0274              `json:"mods,omitempty"`
	Libraries      []mirrorWorkspaceLibrary0405      `json:"libraries,omitempty"`
	Compatibility  string                            `json:"compatibility,omitempty"`
	AuthlibPatches []mirrorWorkspaceAuthlibPatch0405 `json:"authlibPatches,omitempty"`
}
type mirrorAction0274 struct {
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
	SourceURL string `json:"sourceUrl,omitempty"`
	ProjectID string `json:"projectId,omitempty"`
	VersionID string `json:"versionId,omitempty"`
}
type mirrorActions0274 struct {
	SchemaVersion string             `json:"schemaVersion"`
	Actions       []mirrorAction0274 `json:"actions"`
}

func mirrorCheckedHash0274(path, expected string) (int64, error) {
	if !isSHA256Hex0271(expected) {
		return 0, errors.New("expected SHA-256 must be 64 hex characters")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("not a regular file: %s", path)
	}
	hash, size, err := hashFile(path)
	if err != nil {
		return 0, err
	}
	if !strings.EqualFold(hash, expected) {
		return 0, fmt.Errorf("SHA-256 mismatch: %s", path)
	}
	return size, nil
}

func mirrorCopyVerified0274(ctx context.Context, dst string, a mirrorArtifact0274) (int64, error) {
	if !isSHA256Hex0271(a.SHA256) {
		return 0, errors.New("SHA-256 required for every artifact")
	}
	if (a.URL == "") == (a.File == "") {
		return 0, errors.New("exactly one of url or file required")
	}
	if _, err := os.Lstat(dst); err == nil {
		return 0, fmt.Errorf("refusing overwrite: %s", dst)
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".mirror-download-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	const limit = int64(512 << 20)
	var reader io.ReadCloser
	if a.File != "" {
		st, e := os.Lstat(a.File)
		if e != nil {
			tmp.Close()
			return 0, e
		}
		if !st.Mode().IsRegular() {
			tmp.Close()
			return 0, errors.New("source-file must be a regular file")
		}
		reader, err = os.Open(a.File)
	} else {
		if err = validateRemoteURL(a.URL); err != nil {
			tmp.Close()
			return 0, err
		}
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
		if e != nil {
			tmp.Close()
			return 0, e
		}
		client := secureHTTPClient()
		client.Timeout = 3 * time.Minute
		response, e := client.Do(request)
		if e != nil {
			tmp.Close()
			return 0, e
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			tmp.Close()
			return 0, fmt.Errorf("artifact HTTP %d", response.StatusCode)
		}
		if response.ContentLength > limit {
			response.Body.Close()
			tmp.Close()
			return 0, errors.New("artifact too large")
		}
		reader = response.Body
	}
	if err != nil {
		tmp.Close()
		return 0, err
	}
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(reader, limit+1))
	closeErr := reader.Close()
	syncErr := tmp.Sync()
	fileCloseErr := tmp.Close()
	if copyErr != nil {
		return 0, copyErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if syncErr != nil {
		return 0, syncErr
	}
	if fileCloseErr != nil {
		return 0, fileCloseErr
	}
	if size > limit {
		return 0, errors.New("artifact too large")
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), a.SHA256) {
		return 0, errors.New("downloaded artifact SHA-256 mismatch")
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return 0, err
	}
	return size, nil
}

func mirrorAddArtifacts0274(ctx context.Context, stage string, entries []mirrorArtifact0274, kind string) ([]mirrorAction0274, error) {
	if len(entries) == 0 {
		return nil, errors.New("empty artifact list")
	}
	seen := map[string]bool{}
	actions := make([]mirrorAction0274, 0, len(entries))
	for _, a := range entries {
		if err := validateVanillaRelativePath(a.Path); err != nil {
			return nil, err
		}
		if kind == "install-mods" && (!strings.HasPrefix(a.Path, "mods/") || !strings.HasSuffix(strings.ToLower(a.Path), ".jar")) {
			return nil, fmt.Errorf("mods must have mods/*.jar path: %s", a.Path)
		}
		if (kind == "lwjgl-download" || kind == "library-install") && (!strings.HasPrefix(a.Path, "libraries/") || !strings.HasSuffix(strings.ToLower(a.Path), ".jar")) {
			return nil, errors.New("LWJGL artifact must be libraries/*.jar")
		}
		if a.Side != "" && a.Side != "client" && a.Side != "both" {
			return nil, fmt.Errorf("unsupported side %q (server-only mod cannot be installed in client)", a.Side)
		}
		if seen[a.Path] {
			return nil, fmt.Errorf("duplicate artifact path %s", a.Path)
		}
		seen[a.Path] = true
		dst, err := secureClientDestination(stage, a.Path)
		if err != nil {
			return nil, err
		}
		if _, statErr := os.Lstat(dst); statErr == nil {
			// Repeated install of identical immutable content is a no-op.
			if _, err := mirrorCheckedHash0274(dst, a.SHA256); err != nil {
				return nil, fmt.Errorf("existing artifact conflicts with requested bytes: %s: %w", a.Path, err)
			}
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		_, err = mirrorCopyVerified0274(ctx, dst, a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Path, err)
		}
		actions = append(actions, mirrorAction0274{Kind: kind, Path: a.Path, After: strings.ToLower(a.SHA256), SourceURL: a.URL, ProjectID: a.ProjectID, VersionID: a.VersionID})
	}
	return actions, nil
}

func mirrorTransactional0274(ctx context.Context, dir string, operate func(string) ([]mirrorAction0274, error)) (factoryPlan0271, error) {
	if strings.TrimSpace(dir) == "" {
		return factoryPlan0271{}, errors.New("--client-dir is required")
	}
	dst, err := filepath.Abs(dir)
	if err != nil {
		return factoryPlan0271{}, err
	}
	release, err := acquireFactoryLock0271(dst)
	if err != nil {
		return factoryPlan0271{}, err
	}
	defer release()
	plan, err := readFactoryPlan0271(dst)
	if err != nil {
		return plan, err
	}
	if err = verifyFactoryPlan0271(dst, plan); err != nil {
		return plan, err
	}
	if len(plan.AdapterPins) > 0 {
		// Legacy 0.27.10 fixtures/workspaces remain editable without silently
		// assigning a new adapter version. Any versioned plan with an obsolete
		// fingerprint must be rebuilt explicitly before it can be changed.
		if err = requireCurrentFactoryAdapters02711(plan); err != nil {
			return plan, fmt.Errorf("cannot modify client using obsolete adapter: %w", err)
		}
	}
	stage, err := os.MkdirTemp(filepath.Dir(dst), ".mirror-stage-")
	if err != nil {
		return plan, err
	}
	defer os.RemoveAll(stage)
	if err = copyFactoryExisting0271(dst, stage); err != nil {
		return plan, err
	}
	changes, err := operate(stage)
	if err != nil {
		return plan, err
	}
	if len(changes) == 0 {
		return plan, nil // idempotent no-op
	}
	if err := attachCompatToPlan0279(stage, &plan); err != nil {
		return plan, err
	}
	ledger := mirrorActions0274{SchemaVersion: "neverlauncher.mirror-actions.v1", Actions: []mirrorAction0274{}}
	if raw, e := os.ReadFile(filepath.Join(stage, mirrorActionsPath0274)); e == nil {
		if err = json.Unmarshal(raw, &ledger); err != nil {
			return plan, err
		}
		if ledger.SchemaVersion != "neverlauncher.mirror-actions.v1" {
			return plan, errors.New("unknown mirror actions schema")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return plan, e
	}
	for _, change := range changes {
		// Hardlink topology is not part of the content digest. Re-deduplicating
		// after a portable staging copy must not invent a new source identity.
		alreadyRecorded := false
		if change.Kind == "dedup-libraries" {
			for _, old := range ledger.Actions {
				if old.Kind == change.Kind && old.Path == change.Path && old.After == change.After {
					alreadyRecorded = true
					break
				}
			}
		}
		if !alreadyRecorded {
			ledger.Actions = append(ledger.Actions, change)
		}
	}
	raw, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return plan, err
	}
	ledgerPath := filepath.Join(stage, mirrorActionsPath0274)
	if err = writeAtomicBytes(ledgerPath, append(raw, '\n'), 0600); err != nil {
		return plan, err
	}
	sum, size, err := hashFile(ledgerPath)
	if err != nil {
		return plan, err
	}
	ledgerSource := factorySource0271{Path: mirrorActionsPath0274, Kind: "verified-manual-actions", URL: "internal:mirror-actions", SHA256: sum, Size: size}
	found := false
	for i, s := range plan.Sources {
		if s.Path == mirrorActionsPath0274 {
			plan.Sources[i] = ledgerSource
			found = true
			break
		}
	}
	if !found {
		plan.Sources = append(plan.Sources, ledgerSource)
	}
	for _, change := range changes {
		if change.Kind != "install-mods" && change.Kind != "library-install" && change.Kind != "lwjgl-download" && change.Kind != "modpack-import" && change.Kind != "authlib-patch-source" && change.Kind != "compat-artifact" && change.Kind != "compat-receipt" {
			continue
		}
		full, err := secureClientDestination(stage, change.Path)
		if err != nil {
			return plan, err
		}
		_, size, err := hashFile(full)
		if err != nil {
			return plan, err
		}
		source := change.SourceURL
		if source == "" {
			source = "local:sha256:" + change.After
		}
		for _, earlier := range plan.Sources {
			if earlier.Path == change.Path {
				return plan, fmt.Errorf("artifact source already recorded: %s", change.Path)
			}
		}
		plan.Sources = append(plan.Sources, factorySource0271{
			Path: change.Path, Kind: change.Kind, URL: source, SHA256: change.After, Size: size,
		})
	}
	// Provenance of any authlib byte changes must be pinned as an internal
	// InstallPlan source, not just left in an unverified sidecar.
	if full := filepath.Join(stage, filepath.FromSlash(authlibProvenancePath0279)); true {
		if st, statErr := os.Lstat(full); statErr == nil {
			if !st.Mode().IsRegular() {
				return plan, errors.New("authlib provenance is not a regular file")
			}
			sum, size, e := hashFile(full)
			if e != nil {
				return plan, e
			}
			src := factorySource0271{Path: authlibProvenancePath0279, Kind: "authlib-transform-provenance", URL: "internal:authlib-provenance", SHA256: sum, Size: size}
			found := false
			for i := range plan.Sources {
				if plan.Sources[i].Path == src.Path {
					plan.Sources[i] = src
					found = true
					break
				}
			}
			if !found {
				plan.Sources = append(plan.Sources, src)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return plan, statErr
		}
	}
	sort.Slice(plan.Sources, func(i, j int) bool { return plan.Sources[i].Path < plan.Sources[j].Path })
	plan.Outputs, err = scanFactoryOutputs0271(stage)
	if err != nil {
		return plan, err
	}
	plan.ReproducibilitySHA256, err = factoryDigest0271(plan)
	if err != nil {
		return plan, err
	}
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return plan, err
	}
	if err = writeAtomicBytes(factoryPlanPath0271(stage), append(encoded, '\n'), 0600); err != nil {
		return plan, err
	}
	if err = verifyFactoryPlan0271(stage, plan); err != nil {
		return plan, err
	}
	if err = replaceDirectoryAtomicPortable(stage, dst); err != nil {
		return plan, err
	}
	return plan, nil
}

func mirrorReadMods0274(manifest string) ([]mirrorArtifact0274, error) {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return nil, err
	}
	if len(raw) > 4<<20 {
		return nil, errors.New("manifest exceeds 4 MiB")
	}
	var entries []mirrorArtifact0274
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&entries); err != nil {
		return nil, err
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("extra data after artifact manifest")
	}
	if len(entries) > 2000 {
		return nil, errors.New("too many mods")
	}
	return entries, nil
}

// Register an exact LWJGL library in the active version profile. Classifier
// natives require OS-specific rules and are deliberately download-only until
// the target-aware native resolver in 0.27.7; never place them on every OS's
// classpath implicitly.
func mirrorRegisterLibrary0405(stage string, plan factoryPlan0271, coordinate, rel, source string) (mirrorAction0274, error) {
	if len(strings.Split(coordinate, ":")) != 3 {
		return mirrorAction0274{}, errors.New("native/classifier LWJGL jars cannot be registered without OS target rules")
	}
	profile, err := secureClientDestination(stage, plan.Launch.ProfilePath)
	if err != nil {
		return mirrorAction0274{}, err
	}
	priorSHA, _, err := hashFile(profile)
	if err != nil {
		return mirrorAction0274{}, err
	}
	raw, err := os.ReadFile(profile)
	if err != nil {
		return mirrorAction0274{}, err
	}
	var decoded map[string]json.RawMessage
	if err = json.Unmarshal(raw, &decoded); err != nil {
		return mirrorAction0274{}, err
	}
	var libs []json.RawMessage
	if len(decoded["libraries"]) > 0 {
		if err = json.Unmarshal(decoded["libraries"], &libs); err != nil {
			return mirrorAction0274{}, err
		}
	}
	for _, rawLib := range libs {
		var lib struct {
			Name string `json:"name"`
		}
		if err = json.Unmarshal(rawLib, &lib); err != nil {
			return mirrorAction0274{}, err
		}
		if lib.Name == coordinate {
			return mirrorAction0274{}, fmt.Errorf("library already registered: %s", coordinate)
		}
	}
	full, err := secureClientDestination(stage, rel)
	if err != nil {
		return mirrorAction0274{}, err
	}
	sha1, _, size, err := hashFileSHA1SHA256(full)
	if err != nil {
		return mirrorAction0274{}, err
	}
	entry, err := json.Marshal(MojangLibrary{Name: coordinate, Downloads: MojangLibraryDownloads{Artifact: MojangDownload{Path: strings.TrimPrefix(rel, "libraries/"), URL: source, SHA1: sha1, Size: size}}})
	if err != nil {
		return mirrorAction0274{}, err
	}
	libs = append(libs, entry)
	decoded["libraries"], err = json.Marshal(libs)
	if err != nil {
		return mirrorAction0274{}, err
	}
	updated, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return mirrorAction0274{}, err
	}
	if err = writeAtomicBytes(profile, append(updated, '\n'), 0644); err != nil {
		return mirrorAction0274{}, err
	}
	updatedSHA, _, err := hashFile(profile)
	if err != nil {
		return mirrorAction0274{}, err
	}
	return mirrorAction0274{Kind: "lwjgl-register", Path: plan.Launch.ProfilePath, Before: priorSHA, After: updatedSHA}, nil
}

func mirrorPatchAuthlib0274(stage, target, patch, baseSHA, patchSHA, expectedSHA string) ([]mirrorAction0274, error) {
	if !strings.HasPrefix(target, "libraries/com/mojang/authlib/") || !strings.HasSuffix(strings.ToLower(target), ".jar") {
		return nil, errors.New("authlib patch target must be libraries/com/mojang/authlib/**/*.jar")
	}
	dst, err := secureClientDestination(stage, target)
	if err != nil {
		return nil, err
	}
	if _, err = mirrorCheckedHash0274(dst, baseSHA); err != nil {
		return nil, fmt.Errorf("base authlib: %w", err)
	}
	if _, err = mirrorCheckedHash0274(patch, patchSHA); err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}
	if !isSHA256Hex0271(expectedSHA) {
		return nil, errors.New("--expected-sha256 of patched JAR required")
	}
	base, err := zip.OpenReader(dst)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	overlay, err := zip.OpenReader(patch)
	if err != nil {
		return nil, err
	}
	defer overlay.Close()
	patches := map[string]*zip.File{}
	if len(overlay.File) > 256 || len(base.File) > 4096 {
		return nil, errors.New("authlib archive contains excessive entries")
	}
	var patchBytes uint64
	for _, f := range overlay.File {
		patchBytes += f.UncompressedSize64
		if patchBytes > 64<<20 {
			return nil, errors.New("authlib patch exceeds 64 MiB")
		}
		if err = validateVanillaRelativePath(f.Name); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(f.Name, "com/mojang/authlib/") || !strings.HasSuffix(f.Name, ".class") || f.UncompressedSize64 > 8<<20 || !f.Mode().IsRegular() {
			return nil, fmt.Errorf("unauthorized authlib patch entry %q", f.Name)
		}
		if _, ok := patches[f.Name]; ok {
			return nil, errors.New("duplicate patch entry")
		}
		patches[f.Name] = f
	}
	if len(patches) == 0 {
		return nil, errors.New("patch contains no authlib classes")
	}
	// Reject signed archives before opening a writable output. A modified
	// class invalidates embedded signature metadata; silently publishing it
	// would create a broken runtime JAR.
	for _, f := range base.File {
		if f.FileInfo().IsDir() {
			continue
		}
		upper := strings.ToUpper(f.Name)
		if strings.HasPrefix(upper, "META-INF/") && (strings.HasSuffix(upper, ".SF") || strings.HasSuffix(upper, ".RSA") || strings.HasSuffix(upper, ".DSA") || strings.HasSuffix(upper, ".EC")) {
			return nil, errors.New("signed authlib archive cannot be transformed by class overlay")
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".authlib-patched-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	writer := zip.NewWriter(tmp)
	seen := map[string]bool{}
	var expanded uint64
	writeEntry := func(name string, entry *zip.File) error {
		expanded += entry.UncompressedSize64
		if expanded > 256<<20 {
			return errors.New("expanded authlib exceeds 256 MiB")
		}
		if err := validateVanillaRelativePath(name); err != nil {
			return err
		}
		if entry.UncompressedSize64 > 128<<20 {
			return errors.New("oversized authlib entry")
		}
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0644)
		out, err := writer.CreateHeader(h)
		if err != nil {
			return err
		}
		in, err := entry.Open()
		if err != nil {
			return err
		}
		defer in.Close()
		n, err := io.Copy(out, io.LimitReader(in, 128<<20+1))
		if err != nil {
			return err
		}
		if n > 128<<20 {
			return errors.New("authlib entry exceeded limit")
		}
		return nil
	}
	for _, f := range base.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if seen[f.Name] {
			writer.Close()
			tmp.Close()
			return nil, errors.New("duplicate base archive entry")
		}
		seen[f.Name] = true
		if patchEntry, ok := patches[f.Name]; ok {
			if err = writeEntry(f.Name, patchEntry); err != nil {
				writer.Close()
				tmp.Close()
				return nil, err
			}
		} else if err = writeEntry(f.Name, f); err != nil {
			writer.Close()
			tmp.Close()
			return nil, err
		}
	}
	patchNames := make([]string, 0, len(patches))
	for name := range patches {
		patchNames = append(patchNames, name)
	}
	sort.Strings(patchNames)
	for _, name := range patchNames {
		entry := patches[name]
		if !seen[name] {
			if err = writeEntry(name, entry); err != nil {
				writer.Close()
				tmp.Close()
				return nil, err
			}
		}
	}
	if err = writer.Close(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err = tmp.Close(); err != nil {
		return nil, err
	}
	if _, err = mirrorCheckedHash0274(tmp.Name(), expectedSHA); err != nil {
		return nil, err
	}
	if err = replaceFileAtomicPortable(tmp.Name(), dst); err != nil {
		return nil, err
	}
	// Pin the actual overlay bytes in the build, not just its digest.
	patchRel := ".neverlauncher/compat/patches/" + strings.ToLower(patchSHA) + ".jar"
	patchDst, err := secureClientDestination(stage, patchRel)
	if err != nil {
		return nil, err
	}
	if _, statErr := os.Lstat(patchDst); errors.Is(statErr, os.ErrNotExist) {
		if _, err := mirrorCopyVerified0274(context.Background(), patchDst, mirrorArtifact0274{File: patch, SHA256: patchSHA}); err != nil {
			return nil, err
		}
	} else if statErr != nil {
		return nil, statErr
	} else {
		if _, err := mirrorCheckedHash0274(patchDst, patchSHA); err != nil {
			return nil, err
		}
	}
	if err := addAuthlibProvenance0279(stage, authlibChange0279{
		Rule: "authlib-class-overlay.sha256.v1", Path: target,
		BeforeSHA256: strings.ToLower(baseSHA), PatchSHA256: strings.ToLower(patchSHA), AfterSHA256: strings.ToLower(expectedSHA),
	}); err != nil {
		return nil, err
	}
	return []mirrorAction0274{
		{Kind: "authlib-patch-source", Path: patchRel, After: strings.ToLower(patchSHA)},
		{Kind: "patch-authlib", Path: target, Before: strings.ToLower(baseSHA), After: strings.ToLower(expectedSHA)},
	}, nil
}

// Deduplicate only byte-identical library JARs. Linking happens in sibling
// staging and never removes classpath entries or changes content. A portable
// copy is NOT reported as deduplication: inability to hardlink is an error.
func mirrorDedupeLibraries0274(stage string) ([]mirrorAction0274, error) {
	libs := filepath.Join(stage, "libraries")
	if st, err := os.Stat(libs); err != nil {
		return nil, err
	} else if !st.IsDir() {
		return nil, errors.New("libraries is not a directory")
	}
	canonical := map[string]string{}
	actions := []mirrorAction0274{}
	err := filepath.WalkDir(libs, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular library: %s", path)
		}
		if !strings.HasSuffix(strings.ToLower(path), ".jar") {
			return nil
		}
		sha, _, err := hashFile(path)
		if err != nil {
			return err
		}
		first, ok := canonical[sha]
		if !ok {
			canonical[sha] = path
			return nil
		}
		a, err := os.Lstat(first)
		if err != nil {
			return err
		}
		b, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if os.SameFile(a, b) {
			return nil
		}
		temp := path + ".mirror-link"
		if err = os.Link(first, temp); err != nil {
			return fmt.Errorf("dedup hardlink unavailable for %s: %w", path, err)
		}
		if err = replaceFileAtomicPortable(temp, path); err != nil {
			os.Remove(temp)
			return err
		}
		rel, _ := filepath.Rel(stage, path)
		actions = append(actions, mirrorAction0274{Kind: "dedup-libraries", Path: filepath.ToSlash(rel), After: sha})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return actions, nil
}

func mirrorReadWorkspace0274(path string) (mirrorWorkspace0274, error) {
	var ws mirrorWorkspace0274
	raw, err := os.ReadFile(path)
	if err != nil {
		return ws, err
	}
	if len(raw) > 4<<20 {
		return ws, errors.New("workspace too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&ws); err != nil {
		return ws, err
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ws, errors.New("extra data after workspace JSON")
	}
	if ws.SchemaVersion != "neverlauncher.mirror-workspace.v1" {
		return ws, errors.New("unsupported workspace schema")
	}
	switch ws.Loader {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		return ws, errors.New("unknown workspace loader")
	}
	if strings.TrimSpace(ws.Minecraft) == "" {
		return ws, errors.New("workspace.minecraft required")
	}
	if len(ws.Mods) > 2000 || len(ws.Libraries) > 128 || len(ws.AuthlibPatches) > 16 {
		return ws, errors.New("workspace exceeds artifact limits")
	}
	for i := range ws.Mods {
		if ws.Mods[i].File != "" && !filepath.IsAbs(ws.Mods[i].File) {
			ws.Mods[i].File = filepath.Join(filepath.Dir(path), ws.Mods[i].File)
		}
	}
	for i := range ws.Libraries {
		lib := &ws.Libraries[i]
		mavenPath, err := strictMavenPath(lib.Coordinate)
		if err != nil {
			return ws, fmt.Errorf("workspace library %q: %w", lib.Coordinate, err)
		}
		if !strings.HasSuffix(strings.ToLower(mavenPath), ".jar") || strings.Count(lib.Coordinate, ":") != 2 {
			return ws, fmt.Errorf("workspace library must be a non-classifier JAR: %s", lib.Coordinate)
		}
		if !isSHA256Hex0271(lib.SHA256) || (lib.URL == "") == (lib.File == "") {
			return ws, fmt.Errorf("workspace library %s requires SHA-256 and exactly one source", lib.Coordinate)
		}
		if lib.File != "" && !filepath.IsAbs(lib.File) {
			lib.File = filepath.Join(filepath.Dir(path), lib.File)
		}
	}
	for i := range ws.AuthlibPatches {
		entry := &ws.AuthlibPatches[i]
		if !isSHA256Hex0271(entry.BaseSHA256) || !isSHA256Hex0271(entry.PatchSHA256) || !isSHA256Hex0271(entry.ExpectedSHA256) {
			return ws, fmt.Errorf("authlib patch %d must pin base, overlay and output SHA-256", i)
		}
		if entry.Patch == "" {
			return ws, fmt.Errorf("authlib patch %d has no source file", i)
		}
		if !filepath.IsAbs(entry.Patch) {
			entry.Patch = filepath.Join(filepath.Dir(path), entry.Patch)
		}
	}
	for _, ref := range []*string{&ws.Modpack, &ws.Compatibility} {
		if *ref != "" && !filepath.IsAbs(*ref) {
			*ref = filepath.Join(filepath.Dir(path), *ref)
		}
	}
	return ws, nil
}

func handleRuntimeMirror0274(args []string) error {
	if len(args) == 0 {
		return errors.New("client-factory commands: build,verify,inspect,install-client,install-mods,download-installer,launch-installer,workspace,apply-workspace,dedup-libraries,lwjgl-download,patch-authlib")
	}
	command := strings.ToLower(args[0])
	flags := args[1:]
	dir := flagValue(flags, "--client-dir", "")
	output := flagValue(flags, "--output", "")
	if err := rejectFactoryOutputPath0271(dir, output); err != nil {
		return err
	}
	switch command {
	case "install-client", "installclient":
		return handleRuntimeFactory0271(append([]string{"build"}, flags...))
	case "launch-installer", "launchinstaller":
		loader := strings.ToLower(flagValue(flags, "--loader", ""))
		if loader != "forge" && loader != "neoforge" {
			return errors.New("launch-installer requires --loader forge|neoforge")
		}
		return handleRuntimeFactory0271(append([]string{"build"}, flags...))
	case "install-mods", "installmods":
		manifest := flagValue(flags, "--manifest", "")
		versionID := flagValue(flags, "--modrinth-version", "")
		if (manifest == "") == (versionID == "") {
			return errors.New("provide exactly one of --manifest or --modrinth-version")
		}
		var mods []mirrorArtifact0274
		var err error
		if manifest != "" {
			mods, err = mirrorReadMods0274(manifest)
		} else {
			plan, readErr := readFactoryPlan0271(dir)
			if readErr != nil {
				return readErr
			}
			if readErr = verifyFactoryPlan0271(dir, plan); readErr != nil {
				return readErr
			}
			mods, err = resolveModrinthMods0274(context.Background(), flagValue(flags, "--modrinth-api", ""), versionID, plan)
		}
		if err != nil {
			return err
		}
		p, err := mirrorTransactional0274(context.Background(), dir, func(stage string) ([]mirrorAction0274, error) {
			return mirrorAddArtifacts0274(context.Background(), stage, mods, "install-mods")
		})
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, p)
	case "lwjgl-download", "lwjgldownload":
		coord := flagValue(flags, "--coordinate", "")
		if !strings.HasPrefix(coord, "org.lwjgl:") && !strings.HasPrefix(coord, "org.lwjgl.lwjgl:") {
			return errors.New("--coordinate must refer to an org.lwjgl Maven artifact")
		}
		mavenPath, err := strictMavenPath(coord)
		if err != nil {
			return err
		}
		rel := "libraries/" + mavenPath
		if explicit := flagValue(flags, "--path", ""); explicit != "" && explicit != rel {
			return errors.New("--path does not match exact LWJGL Maven coordinate")
		}
		uri := flagValue(flags, "--url", "")
		if uri == "" {
			uri = defaultMavenCentralBase + "/" + mavenPath
		}
		artifact := mirrorArtifact0274{Path: rel, URL: uri, File: flagValue(flags, "--source-file", ""), SHA256: flagValue(flags, "--sha256", "")}
		if artifact.File != "" && flagValue(flags, "--url", "") == "" {
			artifact.URL = ""
		}
		register := strings.EqualFold(flagValue(flags, "--register", "true"), "true")
		p, err := mirrorTransactional0274(context.Background(), dir, func(stage string) ([]mirrorAction0274, error) {
			changes, err := mirrorAddArtifacts0274(context.Background(), stage, []mirrorArtifact0274{artifact}, "lwjgl-download")
			if err != nil {
				return nil, err
			}
			if register {
				plan, err := readFactoryPlan0271(stage)
				if err != nil {
					return nil, err
				}
				source := artifact.URL
				if source == "" {
					source = "local:sha256:" + artifact.SHA256
				}
				action, err := mirrorRegisterLibrary0405(stage, plan, coord, rel, source)
				if err != nil {
					return nil, err
				}
				changes = append(changes, action)
			}
			return changes, nil
		})
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, p)
	case "patch-authlib", "patchauthlib":
		p, err := mirrorTransactional0274(context.Background(), dir, func(stage string) ([]mirrorAction0274, error) {
			return mirrorPatchAuthlib0274(stage, flagValue(flags, "--target", ""), flagValue(flags, "--patch", ""), flagValue(flags, "--base-sha256", ""), flagValue(flags, "--patch-sha256", ""), flagValue(flags, "--expected-sha256", ""))
		})
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, p)
	case "dedup-libraries", "deduplibraries":
		p, err := mirrorTransactional0274(context.Background(), dir, mirrorDedupeLibraries0274)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, p)
	case "workspace":
		ws, err := mirrorReadWorkspace0274(flagValue(flags, "--file", ""))
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, ws)
	case "apply-workspace", "applyworkspace":
		ws, err := mirrorReadWorkspace0274(flagValue(flags, "--file", ""))
		if err != nil {
			return err
		}
		if dir == "" {
			return errors.New("--client-dir required")
		}
		// Refuse implicit upgrades to an existing client. New workspaces are built
		// into an independent destination, then every artifact is verified.
		if _, err := os.Lstat(dir); err == nil {
			return errors.New("workspace target exists: use new --client-dir to avoid changing existing releases")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			return err
		}
		stage, err := os.MkdirTemp(filepath.Dir(abs), ".workspace-stage-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		targets, err := parseVanillaTargets(flagValue(flags, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
		if err != nil {
			return err
		}
		workers, err := strconv.Atoi(flagValue(flags, "--workers", "12"))
		if err != nil {
			return fmt.Errorf("invalid --workers: %w", err)
		}
		processorTimeout, err := time.ParseDuration(flagValue(flags, "--processor-timeout", "10m"))
		if err != nil {
			return fmt.Errorf("invalid --processor-timeout: %w", err)
		}
		options := factoryBuildOptions0271{
			Loader: ws.Loader, Minecraft: ws.Minecraft, LoaderVersion: ws.LoaderVersion, Targets: targets,
			Workers: workers, ProcessorTimeout: processorTimeout,
			ClientDir: filepath.Join(stage, "client"), StrictUpstream: true, SharedCacheDir: strings.TrimSpace(flagValue(flags, "--shared-cache-dir", "")),
			VersionManifest:       flagValue(flags, "--version-manifest", ""),
			AssetBaseURL:          flagValue(flags, "--asset-base-url", ""),
			LibraryBaseURL:        flagValue(flags, "--library-base-url", ""),
			MetaBaseURL:           flagValue(flags, "--meta-base-url", ""),
			MavenMetadataURL:      flagValue(flags, "--maven-metadata-url", ""),
			InstallerURL:          flagValue(flags, "--installer-url", ""),
			InstallerSHA1:         flagValue(flags, "--installer-sha1", ""),
			InstallerSourceFile:   flagValue(flags, "--installer-file", ""),
			InstallerSourceSHA256: flagValue(flags, "--installer-sha256", ""),
			JavaExecutable:        flagValue(flags, "--java", ""),
			ProcessorSandbox:      flagValue(flags, "--processor-sandbox", "process"),
		}
		// A workspace can build from an exact, verified .mrpack/CurseForge
		// archive. Verify the pack's loader before downloading anything: a
		// workspace may never silently substitute its game or loader version.
		if ws.Modpack != "" {
			spec, reader, e := parseModpack0275(ws.Modpack, strings.EqualFold(flagValue(flags, "--include-optional", "false"), "true"))
			if e != nil {
				return e
			}
			_ = reader.Close()
			if spec.Minecraft != ws.Minecraft || spec.Loader != ws.Loader || spec.LoaderVersion != ws.LoaderVersion {
				return fmt.Errorf("modpack conflicts with workspace Minecraft/loader: pack=%s/%s/%s workspace=%s/%s/%s", spec.Minecraft, spec.Loader, spec.LoaderVersion, ws.Minecraft, ws.Loader, ws.LoaderVersion)
			}
			_, err = importModpackWithGates0276(context.Background(), ws.Modpack, options.ClientDir,
				flagValue(flags, "--manual-dir", ""), flagValue(flags, "--curseforge-api", ""),
				flagValue(flags, "--curseforge-api-key", os.Getenv("NEVERLAUNCHER_CURSEFORGE_API_KEY")),
				strings.EqualFold(flagValue(flags, "--include-optional", "false"), "true"), options,
				flagValue(flags, "--permissions-file", ""), flagValue(flags, "--distribution", "local"))
		} else {
			_, err = executeFactoryBuild0271(context.Background(), options)
		}
		if err != nil {
			return err
		}
		// Apply local mods and registered Maven libraries together. The
		// transaction fails closed on any missing or mismatched artifact.
		if len(ws.Mods) > 0 || len(ws.Libraries) > 0 {
			_, err = mirrorTransactional0274(context.Background(), options.ClientDir, func(root string) ([]mirrorAction0274, error) {
				changes := []mirrorAction0274{}
				if len(ws.Mods) > 0 {
					mods, e := mirrorAddArtifacts0274(context.Background(), root, ws.Mods, "install-mods")
					if e != nil {
						return nil, e
					}
					changes = append(changes, mods...)
				}
				for _, lib := range ws.Libraries {
					mavenPath, e := strictMavenPath(lib.Coordinate)
					if e != nil {
						return nil, e
					}
					rel := "libraries/" + mavenPath
					added, e := mirrorAddArtifacts0274(context.Background(), root, []mirrorArtifact0274{{Path: rel, URL: lib.URL, File: lib.File, SHA256: lib.SHA256}}, "library-install")
					if e != nil {
						return nil, e
					}
					changes = append(changes, added...)
					plan, e := readFactoryPlan0271(root)
					if e != nil {
						return nil, e
					}
					source := lib.URL
					if source == "" {
						source = "local:sha256:" + strings.ToLower(lib.SHA256)
					}
					registered, e := mirrorRegisterLibrary0405(root, plan, lib.Coordinate, rel, source)
					if e != nil {
						return nil, e
					}
					changes = append(changes, registered)
				}
				return changes, nil
			})
			if err != nil {
				return err
			}
		}
		if len(ws.AuthlibPatches) > 0 {
			_, err = mirrorTransactional0274(context.Background(), options.ClientDir, func(root string) ([]mirrorAction0274, error) {
				changes := []mirrorAction0274{}
				for _, patch := range ws.AuthlibPatches {
					applied, e := mirrorPatchAuthlib0274(root, patch.Target, patch.Patch, patch.BaseSHA256, patch.PatchSHA256, patch.ExpectedSHA256)
					if e != nil {
						return nil, e
					}
					changes = append(changes, applied...)
				}
				return changes, nil
			})
			if err != nil {
				return err
			}
		}
		if ws.Compatibility != "" {
			request, e := compatReadRequest0279(ws.Compatibility)
			if e != nil {
				return e
			}
			_, err = mirrorTransactional0274(context.Background(), options.ClientDir, func(root string) ([]mirrorAction0274, error) {
				plan, e := readFactoryPlan0271(root)
				if e != nil {
					return nil, e
				}
				return compatApply0279(context.Background(), root, plan, request, strings.EqualFold(flagValue(flags, "--allow-auth-agent", "false"), "true"))
			})
			if err != nil {
				return err
			}
		}
		p, err := readFactoryPlan0271(options.ClientDir)
		if err != nil {
			return err
		}
		if err = verifyFactoryPlan0271(options.ClientDir, p); err != nil {
			return err
		}
		if err = os.Rename(options.ClientDir, abs); err != nil {
			return err
		}
		return writeOrPrintJSON(output, p)
	case "download-installer", "downloadinstaller":
		loader := strings.ToLower(flagValue(flags, "--loader", ""))
		if loader != "forge" && loader != "neoforge" {
			return errors.New("--loader forge|neoforge required")
		}
		mc := flagValue(flags, "--minecraft", "")
		if mc == "" {
			return errors.New("--minecraft required")
		}
		cache := flagValue(flags, "--cache-dir", "")
		if cache == "" {
			return errors.New("--cache-dir required")
		}
		resolved, artifact, _, err := resolveForgeLikeVersion(context.Background(), secureHTTPClient(), loader, mc, flagValue(flags, "--loader-version", "latest-stable"), flagValue(flags, "--maven-metadata-url", ""))
		if err != nil {
			return err
		}
		uri := forgeInstallerURL(loader, mc, artifact)
		if override := flagValue(flags, "--url", ""); override != "" {
			uri = override
		}
		sha := strings.ToLower(flagValue(flags, "--sha256", ""))
		if !isSHA256Hex0271(sha) {
			return errors.New("download-installer requires pinned --sha256; mutable checksum sidecars are not trusted")
		}
		destDir := filepath.Join(cache, loader, sanitizeVersionToken(artifact))
		if err = os.MkdirAll(destDir, 0755); err != nil {
			return err
		}
		dest := filepath.Join(destDir, "installer.jar")
		release, err := acquireFactoryLock0271(dest)
		if err != nil {
			return err
		}
		defer release()
		if _, e := os.Lstat(dest); e == nil {
			if _, err = mirrorCheckedHash0274(dest, sha); err != nil {
				return err
			}
		} else if errors.Is(e, os.ErrNotExist) {
			_, err = mirrorCopyVerified0274(context.Background(), dest, mirrorArtifact0274{URL: uri, SHA256: sha})
			if err != nil {
				return err
			}
		} else {
			return e
		}
		return writeOrPrintJSON(output, map[string]any{"loader": loader, "minecraft": mc, "loaderVersion": resolved, "artifactVersion": artifact, "path": dest, "sha256": sha, "source": uri, "status": "verified"})
	default:
		return fmt.Errorf("unknown client-factory command %q", command)
	}
}
