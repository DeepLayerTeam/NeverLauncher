package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const componentUpdateManifestFile0157 = "COMPONENT_UPDATE_MANIFEST.json"
const componentUpdateStateFile0157 = ".neverlauncher/component-update-state.json"
const componentTreeSchema0157 = "1.0"

type componentUpdateArtifact0157 struct {
	Component                 string `json:"component"`
	SourcePath                string `json:"sourcePath"`
	TargetPath                string `json:"targetPath"`
	SHA256                    string `json:"sha256"`
	Size                      int64  `json:"size"`
	Executable                bool   `json:"executable,omitempty"`
	SignerThumbprint          string `json:"signerThumbprint,omitempty"`
	TimestampSignerThumbprint string `json:"timestampSignerThumbprint,omitempty"`
}

type componentUpdateManifest0157 struct {
	SchemaVersion  string                        `json:"schemaVersion"`
	Product        string                        `json:"product"`
	ProductVersion string                        `json:"productVersion"`
	Platform       string                        `json:"platform"`
	Architecture   string                        `json:"architecture"`
	Layout         string                        `json:"layout"`
	TrustMode      string                        `json:"trustMode"`
	BundleName     string                        `json:"bundleName,omitempty"`
	Components     []componentUpdateArtifact0157 `json:"components"`
	SupportFiles   []componentUpdateArtifact0157 `json:"supportFiles,omitempty"`
}

type componentUpdateState0157 struct {
	SchemaVersion string                        `json:"schemaVersion"`
	ToolVersion   string                        `json:"toolVersion"`
	Version       string                        `json:"version"`
	Platform      string                        `json:"platform"`
	Architecture  string                        `json:"architecture"`
	UpdatedAt     string                        `json:"updatedAt"`
	Components    []componentUpdateArtifact0157 `json:"components"`
}

type componentTreeJournal0157 struct {
	SchemaVersion string `json:"schemaVersion"`
	EngineVersion string `json:"engineVersion"`
	ID            string `json:"id"`
	Root          string `json:"root"`
	LiveRel       string `json:"liveRel"`
	StagePath     string `json:"stagePath"`
	BackupPath    string `json:"backupPath"`
	FailedPath    string `json:"failedPath"`
	FromVersion   string `json:"fromVersion,omitempty"`
	ToVersion     string `json:"toVersion"`
	Phase         string `json:"phase"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	Error         string `json:"error,omitempty"`
}

func componentTransactionalUpdateRequired0157(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 7)))
}

func componentUpdateCurrentTarget0157() (DeliveryTarget, error) {
	return currentDeliveryTarget()
}

func validSHA256Hex0157(value string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == sha256.Size
}

func validateComponentRelativePath0157(value string) error {
	if err := validateUpdaterPath0156(value); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(value), ".neverlauncher/updater/") {
		return fmt.Errorf("component path conflicts with updater control directory: %s", value)
	}
	return nil
}

func readComponentUpdateManifest0157(path string) (componentUpdateManifest0157, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return componentUpdateManifest0157{}, err
	}
	if len(raw) == 0 || len(raw) > 512*1024 {
		return componentUpdateManifest0157{}, errors.New("component update manifest size is invalid")
	}
	var manifest componentUpdateManifest0157
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return componentUpdateManifest0157{}, fmt.Errorf("invalid %s: %w", componentUpdateManifestFile0157, err)
	}
	return manifest, nil
}

func validateComponentUpdateManifest0157(manifest componentUpdateManifest0157, manifestDir string, allowDevelopment bool) error {
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || strings.TrimSpace(manifest.ProductVersion) == "" {
		return errors.New("component update manifest identity/schema mismatch")
	}
	target, err := componentUpdateCurrentTarget0157()
	if err != nil {
		return err
	}
	platform, err := normalizeDeliveryPlatform(manifest.Platform)
	if err != nil {
		return err
	}
	arch, err := normalizeDeliveryArchitecture(manifest.Architecture)
	if err != nil {
		return err
	}
	if platform != target.Platform || arch != target.Architecture {
		return fmt.Errorf("component package target mismatch: package=%s/%s host=%s/%s", platform, arch, target.Platform, target.Architecture)
	}
	if manifest.Platform != platform || manifest.Architecture != arch {
		return errors.New("component package target must use canonical platform/architecture")
	}
	if manifest.Layout != "adjacent-files" && manifest.Layout != "macos-app-bundle" {
		return fmt.Errorf("unsupported component update layout %q", manifest.Layout)
	}
	if manifest.Layout == "macos-app-bundle" && platform != "macos" {
		return errors.New("macos-app-bundle layout is valid only on macOS")
	}
	if len(manifest.Components) != 3 {
		return errors.New("component update manifest must contain exactly Desktop, NeverGuard and NeverRuntime")
	}
	expected := map[string]bool{"desktop": false, "guard": false, "runtime": false}
	seenTargets := map[string]bool{}
	sourceBase := manifestDir
	if manifest.Layout == "macos-app-bundle" && filepath.Base(manifestDir) == "Resources" {
		contents := filepath.Dir(manifestDir)
		sourceBase = filepath.Dir(contents)
	}
	for _, item := range append(append([]componentUpdateArtifact0157{}, manifest.Components...), manifest.SupportFiles...) {
		if err := validateComponentRelativePath0157(item.SourcePath); err != nil {
			return fmt.Errorf("unsafe component source path %q: %w", item.SourcePath, err)
		}
		if err := validateComponentRelativePath0157(item.TargetPath); err != nil {
			return fmt.Errorf("unsafe component target path %q: %w", item.TargetPath, err)
		}
		if item.Size <= 0 || !validSHA256Hex0157(item.SHA256) {
			return fmt.Errorf("invalid component metadata for %s", item.Component)
		}
		key := strings.ToLower(item.TargetPath)
		if runtime.GOOS != "windows" {
			key = item.TargetPath
		}
		if seenTargets[key] {
			return fmt.Errorf("duplicate component target path %s", item.TargetPath)
		}
		seenTargets[key] = true
		source := filepath.Join(sourceBase, filepath.FromSlash(item.SourcePath))
		if err := verifyUpdaterFile0156(source, item.Size, item.SHA256); err != nil {
			return fmt.Errorf("component package source verify %s: %w", item.SourcePath, err)
		}
	}
	for _, item := range manifest.Components {
		if _, ok := expected[item.Component]; !ok {
			return fmt.Errorf("unknown required component %q", item.Component)
		}
		if expected[item.Component] {
			return fmt.Errorf("duplicate required component %q", item.Component)
		}
		expected[item.Component] = true
		if !item.Executable {
			return fmt.Errorf("required component %s must be executable", item.Component)
		}
	}
	for component, present := range expected {
		if !present {
			return fmt.Errorf("component update manifest missing %s", component)
		}
	}
	if allowDevelopment && (manifest.TrustMode == "development-self-test" || manifest.TrustMode == "unsigned-development" || manifest.TrustMode == "adhoc-development") {
		return nil
	}
	switch platform {
	case "windows":
		if manifest.TrustMode != "authenticode-rfc3161" {
			return errors.New("production Windows component update requires authenticode-rfc3161 trustMode")
		}
		for _, item := range manifest.Components {
			if !windowsCertThumbprintRE0152.MatchString(item.SignerThumbprint) || !windowsCertThumbprintRE0152.MatchString(item.TimestampSignerThumbprint) {
				return fmt.Errorf("Windows component %s is missing signer/timestamp identity", item.Component)
			}
		}
	case "linux":
		if manifest.TrustMode != "sha256-delivery" {
			return errors.New("production Linux component update requires sha256-delivery trustMode")
		}
	case "macos":
		if manifest.TrustMode != "developer-id-notarized" {
			return errors.New("production macOS component update requires developer-id-notarized trustMode")
		}
	}
	return nil
}

func verifyComponentBinaries0157(manifest componentUpdateManifest0157, base string, installed bool, allowDevelopment bool) error {
	if allowDevelopment && (manifest.TrustMode == "development-self-test" || manifest.TrustMode == "unsigned-development" || manifest.TrustMode == "adhoc-development") {
		for _, item := range manifest.Components {
			path := filepath.Join(base, filepath.FromSlash(item.TargetPath))
			if !installed {
				path = filepath.Join(base, filepath.FromSlash(item.SourcePath))
			}
			if err := verifyUpdaterFile0156(path, item.Size, item.SHA256); err != nil {
				return err
			}
		}
		return nil
	}
	for _, item := range manifest.Components {
		rel := item.TargetPath
		if !installed {
			rel = item.SourcePath
		}
		path := filepath.Join(base, filepath.FromSlash(rel))
		if err := verifyUpdaterFile0156(path, item.Size, item.SHA256); err != nil {
			return fmt.Errorf("%s hash verification: %w", item.Component, err)
		}
		switch manifest.Platform {
		case "windows":
			pe, err := inspectWindowsPEFile0152(path)
			if err != nil || pe.Architecture != manifest.Architecture || !pe.HasSignature {
				return fmt.Errorf("%s Windows PE/AuthentiCode boundary failed: %v", item.Component, err)
			}
			if err := verifyWindowsAuthenticodeNative0152(path, item.SignerThumbprint, item.TimestampSignerThumbprint); err != nil {
				return fmt.Errorf("%s Authenticode verify: %w", item.Component, err)
			}
		case "linux":
			elf, err := inspectLinuxELFFile0153(path)
			if err != nil || elf.Architecture != manifest.Architecture {
				return fmt.Errorf("%s ELF architecture verify: %v", item.Component, err)
			}
		case "macos":
			macho, err := inspectMacOSMachOFile0154(path)
			if err != nil || macho.Architecture != manifest.Architecture || !macho.HasCodeSignature {
				return fmt.Errorf("%s Mach-O signature/architecture verify: %v", item.Component, err)
			}
		}
	}
	return nil
}

func hashPackagePin0157(packagePath, expected string, allowDevelopment bool) error {
	if stat, err := os.Stat(packagePath); err != nil {
		return err
	} else if stat.IsDir() {
		if !allowDevelopment {
			return errors.New("production component update requires a pinned archive, not an unpacked directory")
		}
		return nil
	}
	if !validSHA256Hex0157(expected) {
		if allowDevelopment && strings.TrimSpace(expected) == "" {
			return nil
		}
		return errors.New("component update requires --expected-sha256 with a 64-hex package digest")
	}
	actual, _, err := hashFile(packagePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("component update package SHA-256 mismatch: got=%s expected=%s", actual, strings.ToLower(expected))
	}
	return nil
}

func verifyPackageAgainstDelivery0157(deliveryPath, packagePath, expectedSHA string) error {
	if strings.TrimSpace(deliveryPath) == "" {
		return nil
	}
	dir := filepath.Dir(deliveryPath)
	if filepath.Base(deliveryPath) != deliveryManifestFile0151 {
		return errors.New("--delivery-manifest must point to DELIVERY_MANIFEST.json")
	}
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		return err
	}
	name := filepath.Base(packagePath)
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == name {
			if artifact.Component != "desktop-package" || !strings.EqualFold(artifact.SHA256, expectedSHA) {
				return errors.New("component update package is not bound to delivery manifest hash")
			}
			return nil
		}
	}
	return fmt.Errorf("component update package %s is absent from DELIVERY_MANIFEST.json", name)
}

func extractComponentPackage0157(packagePath, dst string) error {
	st, err := os.Stat(packagePath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return copyComponentTree0157(packagePath, dst)
	}
	lower := strings.ToLower(packagePath)
	if strings.HasSuffix(lower, ".zip") {
		if runtime.GOOS == "darwin" {
			cmd := exec.Command("/usr/bin/ditto", "-x", "-k", packagePath, dst)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("ditto extract failed: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		return extractComponentZip0157(packagePath, dst)
	}
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return extractComponentTarGz0157(packagePath, dst)
	}
	return fmt.Errorf("unsupported component package format: %s", filepath.Base(packagePath))
}

func safeExtractPath0157(root, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || filepath.IsAbs(name) || strings.Contains(name, "\\") {
		return "", fmt.Errorf("unsafe package entry %q", name)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
		return "", fmt.Errorf("unsafe package entry %q", name)
	}
	return filepath.Join(root, filepath.FromSlash(clean)), nil
}

func extractComponentZip0157(path, dst string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	var total int64
	for _, file := range r.File {
		name := strings.TrimSuffix(file.Name, "/")
		if name == "" {
			continue
		}
		target, err := safeExtractPath0157(dst, name)
		if err != nil {
			return err
		}
		mode := file.Mode()
		if mode&os.ModeSymlink != 0 || (!file.FileInfo().IsDir() && !mode.IsRegular()) {
			return fmt.Errorf("package entry must be regular file/directory: %s", name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(file.UncompressedSize64)
		if total > 8<<30 {
			return errors.New("component package exceeds 8 GiB extraction limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		perm := mode.Perm()
		if perm == 0 {
			perm = 0o644
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, int64(file.UncompressedSize64)+1))
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func extractComponentTarGz0157(path, dst string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" {
			continue
		}
		target, err := safeExtractPath0157(dst, name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			total += h.Size
			if h.Size < 0 || total > 8<<30 {
				return errors.New("component package exceeds 8 GiB extraction limit")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(h.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(out, tr, h.Size)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("package entry type is not allowed: %s", h.Name)
		}
	}
	return nil
}

func copyComponentTree0157(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("development component bundle contains symlink: %s", rel)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("development component bundle contains non-regular file: %s", rel)
		}
		return copyUpdaterSource0156(path, target, info.Mode().Perm())
	})
}

func findComponentManifest0157(root string) (string, error) {
	matches := []string{}
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 20000 {
			return errors.New("component package contains too many filesystem entries")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("component package contains symlink: %s", path)
		}
		if !d.IsDir() && d.Name() == componentUpdateManifestFile0157 {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("component package must contain exactly one %s, got %d", componentUpdateManifestFile0157, len(matches))
	}
	return matches[0], nil
}

func componentUpdateInstallRoot0157(currentDesktop, explicitRoot string, manifest componentUpdateManifest0157) (root, liveBundle string, err error) {
	currentDesktop = strings.TrimSpace(currentDesktop)
	if manifest.Layout == "macos-app-bundle" {
		if currentDesktop == "" {
			return "", "", errors.New("macOS component update requires --current-desktop")
		}
		abs, err := filepath.Abs(currentDesktop)
		if err != nil {
			return "", "", err
		}
		macosDir := filepath.Dir(abs)
		contents := filepath.Dir(macosDir)
		bundle := filepath.Dir(contents)
		if filepath.Base(macosDir) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(strings.ToLower(filepath.Base(bundle)), ".app") {
			return "", "", errors.New("current Desktop is not inside a macOS .app/Contents/MacOS bundle")
		}
		parent := filepath.Dir(bundle)
		if explicitRoot != "" {
			explicit, e := filepath.Abs(explicitRoot)
			if e != nil || filepath.Clean(explicit) != filepath.Clean(parent) {
				return "", "", errors.New("--root does not match current macOS app parent")
			}
		}
		return parent, filepath.Base(bundle), nil
	}
	if explicitRoot != "" {
		root, err := filepath.Abs(explicitRoot)
		return root, "", err
	}
	if currentDesktop == "" {
		return "", "", errors.New("component update requires --root or --current-desktop")
	}
	abs, err := filepath.Abs(currentDesktop)
	if err != nil {
		return "", "", err
	}
	return filepath.Dir(abs), "", nil
}

func currentComponentVersion0157(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157)))
	if err != nil {
		return ""
	}
	var state componentUpdateState0157
	if json.Unmarshal(raw, &state) == nil {
		return strings.TrimSpace(state.Version)
	}
	return ""
}

func componentStateBytes0157(manifest componentUpdateManifest0157) ([]byte, error) {
	state := componentUpdateState0157{
		SchemaVersion: "1.0", ToolVersion: version, Version: manifest.ProductVersion,
		Platform: manifest.Platform, Architecture: manifest.Architecture,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Components: manifest.Components,
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func waitForComponentParent0157(pid int, timeout time.Duration) error {
	if pid <= 0 {
		return nil
	}
	if pid == os.Getpid() {
		return errors.New("--wait-pid cannot be the updater process itself")
	}
	deadline := time.Now().Add(timeout)
	for updaterProcessAlive0156(pid) {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for Desktop pid=%d to exit", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// On Windows the process handle can disappear just before image mappings are fully released.
	if runtime.GOOS == "windows" {
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

func applyAdjacentComponentUpdate0157(manifest componentUpdateManifest0157, manifestDir, root, currentDesktop string, allowDevelopment bool) (map[string]any, error) {
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		return nil, err
	}
	files := []updaterFileSpec0156{}
	for _, item := range append(append([]componentUpdateArtifact0157{}, manifest.Components...), manifest.SupportFiles...) {
		files = append(files, updaterFileSpec0156{
			Path: item.TargetPath, Source: filepath.Join(manifestDir, filepath.FromSlash(item.SourcePath)),
			Size: item.Size, SHA256: item.SHA256, Executable: item.Executable,
		})
	}
	stateBytes, err := componentStateBytes0157(manifest)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(stateBytes)
	files = append(files, updaterFileSpec0156{Path: componentUpdateStateFile0157, Data: stateBytes, Size: int64(len(stateBytes)), SHA256: hex.EncodeToString(sum[:])})
	remove := []string{}
	if strings.TrimSpace(currentDesktop) != "" {
		abs, err := filepath.Abs(currentDesktop)
		if err != nil {
			return nil, err
		}
		rootAbs, _ := filepath.Abs(root)
		if filepath.Clean(filepath.Dir(abs)) == filepath.Clean(rootAbs) {
			desktopTarget := ""
			for _, item := range manifest.Components {
				if item.Component == "desktop" {
					desktopTarget = item.TargetPath
				}
			}
			oldRel := filepath.ToSlash(filepath.Base(abs))
			if desktopTarget != "" && !strings.EqualFold(oldRel, desktopTarget) {
				if err := validateComponentRelativePath0157(oldRel); err != nil {
					return nil, err
				}
				remove = append(remove, oldRel)
			}
		}
	}
	verify := func() error {
		if err := verifyComponentBinaries0157(manifest, root, true, allowDevelopment); err != nil {
			return err
		}
		for _, item := range manifest.SupportFiles {
			if err := verifyUpdaterFile0156(filepath.Join(root, filepath.FromSlash(item.TargetPath)), item.Size, item.SHA256); err != nil {
				return err
			}
		}
		return nil
	}
	report, err := updater.apply(updaterRequest0156{
		Root: root, Namespace: "desktop-guard-runtime", FromVersion: currentComponentVersion0157(root), ToVersion: manifest.ProductVersion,
		Files: files, Remove: remove, Verify: verify,
	})
	if err != nil {
		return nil, err
	}
	report["components"] = []string{"desktop", "guard", "runtime"}
	report["layout"] = manifest.Layout
	report["restartExecutable"] = filepath.Join(root, filepath.FromSlash(componentTargetPath0157(manifest, "desktop")))
	return report, nil
}

func componentTargetPath0157(manifest componentUpdateManifest0157, component string) string {
	for _, item := range manifest.Components {
		if item.Component == component {
			return item.TargetPath
		}
	}
	return ""
}

func componentTreeJournalDir0157(u *transactionalUpdater0156, id string) string {
	return filepath.Join(u.controlDir, "component-trees", id)
}

func componentTreeJournalPath0157(u *transactionalUpdater0156, id string) string {
	return filepath.Join(componentTreeJournalDir0157(u, id), "journal.json")
}

func writeComponentTreeJournal0157(u *transactionalUpdater0156, journal *componentTreeJournal0157) error {
	journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	path := componentTreeJournalPath0157(u, journal.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeUpdaterBytes0156(path+".tmp", append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := replaceFileAtomicPortable(path+".tmp", path); err != nil {
		return err
	}
	syncDirBestEffort0156(filepath.Dir(path))
	return nil
}

func readComponentTreeJournal0157(u *transactionalUpdater0156, id string) (*componentTreeJournal0157, error) {
	raw, err := os.ReadFile(componentTreeJournalPath0157(u, id))
	if err != nil {
		return nil, err
	}
	var journal componentTreeJournal0157
	if err := json.Unmarshal(raw, &journal); err != nil {
		return nil, err
	}
	if journal.SchemaVersion != componentTreeSchema0157 || journal.ID != id || filepath.Clean(journal.Root) != u.root {
		return nil, fmt.Errorf("invalid component tree journal %s", id)
	}
	return &journal, nil
}

func safeComponentTreePath0157(u *transactionalUpdater0156, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("unsafe component tree path %q", rel)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(strings.ToLower(clean), ".neverlauncher/") {
		return "", fmt.Errorf("unsafe component tree path %q", rel)
	}
	return filepath.Join(u.root, filepath.FromSlash(clean)), nil
}

func rollbackComponentTreeLocked0157(u *transactionalUpdater0156, journal *componentTreeJournal0157, cause error) error {
	journal.Phase = "rolling-back"
	if cause != nil {
		journal.Error = cause.Error()
	}
	_ = writeComponentTreeJournal0157(u, journal)
	live, err := safeComponentTreePath0157(u, journal.LiveRel)
	if err != nil {
		return err
	}
	if st, err := os.Lstat(live); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return errors.New("component tree rollback refuses non-directory live bundle")
		}
		_ = os.RemoveAll(journal.FailedPath)
		if err := os.Rename(live, journal.FailedPath); err != nil {
			return fmt.Errorf("preserve failed component bundle: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if st, err := os.Lstat(journal.BackupPath); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return errors.New("component tree backup is not a safe directory")
		}
		if err := os.Rename(journal.BackupPath, live); err != nil {
			return fmt.Errorf("restore component bundle backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDirBestEffort0156(u.root)
	journal.Phase = "rolled-back"
	return writeComponentTreeJournal0157(u, journal)
}

func (u *transactionalUpdater0156) recoverComponentTreesLocked0157() ([]string, error) {
	root := filepath.Join(u.controlDir, "component-trees")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	recovered := []string{}
	for _, id := range ids {
		journal, err := readComponentTreeJournal0157(u, id)
		if err != nil {
			return recovered, err
		}
		switch journal.Phase {
		case "committed", "rolled-back":
			continue
		case "prepared":
			journal.Phase = "rolled-back"
			journal.Error = "recovered prepared component tree transaction before live switch"
			if err := writeComponentTreeJournal0157(u, journal); err != nil {
				return recovered, err
			}
		case "old-moved", "new-moved", "verifying", "rolling-back":
			if err := rollbackComponentTreeLocked0157(u, journal, errors.New("crash recovery")); err != nil {
				return recovered, err
			}
		default:
			return recovered, fmt.Errorf("unknown component tree transaction phase %q", journal.Phase)
		}
		recovered = append(recovered, id)
	}
	return recovered, nil
}

func applyComponentTree0157(u *transactionalUpdater0156, liveRel, stagePath, fromVersion, toVersion string, verify func(string) error) (map[string]any, error) {
	if err := u.acquireLock(false); err != nil {
		return nil, err
	}
	defer u.releaseLock()
	fileRecovered, err := u.recoverIncompleteLocked()
	if err != nil {
		return nil, err
	}
	treeRecovered, err := u.recoverComponentTreesLocked0157()
	if err != nil {
		return nil, err
	}
	live, err := safeComponentTreePath0157(u, liveRel)
	if err != nil {
		return nil, err
	}
	stageAbs, err := filepath.Abs(stagePath)
	if err != nil {
		return nil, err
	}
	controlAbs, _ := filepath.Abs(u.controlDir)
	relControl, err := filepath.Rel(controlAbs, stageAbs)
	if err != nil || relControl == "." || relControl == ".." || strings.HasPrefix(relControl, ".."+string(filepath.Separator)) {
		return nil, errors.New("component tree staging must reside inside updater control directory on the live filesystem")
	}
	for label, path := range map[string]string{"live": live, "stage": stageAbs} {
		st, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("%s component tree: %w", label, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return nil, fmt.Errorf("%s component tree must be a non-symlink directory", label)
		}
	}
	id, err := newUpdaterTransactionID0156()
	if err != nil {
		return nil, err
	}
	txDir := componentTreeJournalDir0157(u, id)
	if err := os.MkdirAll(txDir, 0o700); err != nil {
		return nil, err
	}
	journal := &componentTreeJournal0157{
		SchemaVersion: componentTreeSchema0157, EngineVersion: version, ID: id, Root: u.root,
		LiveRel: liveRel, StagePath: stageAbs, BackupPath: filepath.Join(txDir, "backup"), FailedPath: filepath.Join(txDir, "failed"),
		FromVersion: fromVersion, ToVersion: toVersion, Phase: "prepared", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		return nil, err
	}
	if err := os.Rename(live, journal.BackupPath); err != nil {
		return nil, fmt.Errorf("move live component bundle to backup: %w", err)
	}
	syncDirBestEffort0156(u.root)
	journal.Phase = "old-moved"
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		_ = os.Rename(journal.BackupPath, live)
		return nil, err
	}
	if err := os.Rename(stageAbs, live); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("component tree switch failed: %v; rollback failed: %w", err, rb)
		}
		return nil, err
	}
	syncDirBestEffort0156(u.root)
	journal.Phase = "new-moved"
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("component tree journal failed after switch: %v; rollback failed: %w", err, rb)
		}
		return nil, err
	}
	journal.Phase = "verifying"
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("component tree verifying journal failed: %v; rollback failed: %w", err, rb)
		}
		return nil, err
	}
	if verify != nil {
		if err := verify(live); err != nil {
			rb := rollbackComponentTreeLocked0157(u, journal, err)
			if rb != nil {
				return nil, fmt.Errorf("component tree verify failed: %v; rollback failed: %w", err, rb)
			}
			return nil, fmt.Errorf("component tree transaction %s rolled back: %w", id, err)
		}
	}
	journal.Phase = "committed"
	journal.Error = ""
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("component tree commit journal failed: %v; rollback failed: %w", err, rb)
		}
		return nil, err
	}
	_ = os.RemoveAll(journal.BackupPath)
	_ = os.RemoveAll(journal.FailedPath)
	return map[string]any{
		"schemaVersion": componentTreeSchema0157, "toolVersion": version, "engine": "unified-transactional-updater",
		"transactionId": id, "namespace": "desktop-guard-runtime-app-bundle", "fromVersion": fromVersion, "toVersion": toVersion,
		"root": u.root, "layout": "macos-app-bundle", "recovered": append(fileRecovered, treeRecovered...), "status": "committed",
	}, nil
}

func verifyMacOSInstalledBundle0157(manifest componentUpdateManifest0157, appRoot string, allowDevelopment bool) error {
	if err := verifyComponentBinaries0157(manifest, appRoot, true, allowDevelopment); err != nil {
		return err
	}
	if allowDevelopment && manifest.TrustMode == "development-self-test" {
		return nil
	}
	for _, command := range [][]string{{"/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", appRoot}, {"/usr/bin/xcrun", "stapler", "validate", appRoot}, {"/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", appRoot}} {
		cmd := exec.Command(command[0], command[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("macOS post-update verification failed: %s: %w: %s", strings.Join(command, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func applyMacOSComponentUpdate0157(manifest componentUpdateManifest0157, manifestPath, root, liveBundle string, allowDevelopment bool) (map[string]any, error) {
	manifestDir := filepath.Dir(manifestPath)
	appSource := manifestDir
	for filepath.Base(appSource) != liveBundle {
		parent := filepath.Dir(appSource)
		if parent == appSource {
			return nil, fmt.Errorf("component manifest is not inside expected app bundle %s", liveBundle)
		}
		appSource = parent
	}
	if filepath.Base(appSource) != liveBundle {
		return nil, errors.New("component package app bundle identity mismatch")
	}
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		return nil, err
	}
	if err := verifyComponentBinaries0157(manifest, appSource, true, allowDevelopment); err != nil {
		return nil, fmt.Errorf("staged macOS component verify: %w", err)
	}
	fromVersion := ""
	statePath := filepath.Join(root, liveBundle, "Contents", "Resources", "COMPONENT_UPDATE_STATE.json")
	if raw, err := os.ReadFile(statePath); err == nil {
		var state componentUpdateState0157
		if json.Unmarshal(raw, &state) == nil {
			fromVersion = state.Version
		}
	}
	stateBytes, err := componentStateBytes0157(manifest)
	if err != nil {
		return nil, err
	}
	stateTarget := filepath.Join(appSource, "Contents", "Resources", "COMPONENT_UPDATE_STATE.json")
	if err := os.WriteFile(stateTarget, stateBytes, 0o644); err != nil {
		return nil, err
	}
	// Development self-tests use an unsigned synthetic tree. Production packages are already signed/notarized;
	// mutating them after extraction would invalidate the outer bundle signature, so production state is stored
	// outside the app bundle after commit.
	if !allowDevelopment || manifest.TrustMode != "development-self-test" {
		_ = os.Remove(stateTarget)
	}
	report, err := applyComponentTree0157(updater, liveBundle, appSource, fromVersion, manifest.ProductVersion, func(live string) error {
		return verifyMacOSInstalledBundle0157(manifest, live, allowDevelopment)
	})
	if err != nil {
		return nil, err
	}
	if !allowDevelopment || manifest.TrustMode != "development-self-test" {
		statePath = filepath.Join(updater.controlDir, "component-update-state.json")
		if err := writeUpdaterBytes0156(statePath, stateBytes, 0o600); err != nil {
			return nil, err
		}
	}
	report["components"] = []string{"desktop", "guard", "runtime"}
	report["restartExecutable"] = filepath.Join(root, liveBundle, filepath.FromSlash(componentTargetPath0157(manifest, "desktop")))
	return report, nil
}

func applyComponentPackage0157(packagePath, expectedSHA, deliveryPath, explicitRoot, currentDesktop string, waitPID int, restart, allowDevelopment bool) (map[string]any, error) {
	if strings.TrimSpace(packagePath) == "" {
		return nil, errors.New("update components requires --package")
	}
	if err := hashPackagePin0157(packagePath, expectedSHA, allowDevelopment); err != nil {
		return nil, err
	}
	if strings.TrimSpace(deliveryPath) != "" {
		if err := verifyPackageAgainstDelivery0157(deliveryPath, packagePath, expectedSHA); err != nil {
			return nil, err
		}
	}
	if waitPID > 0 {
		if err := waitForComponentParent0157(waitPID, 2*time.Minute); err != nil {
			return nil, err
		}
	}
	// Extract adjacent packages under the destination updater control directory so all subsequent staging/renames
	// stay on the same filesystem. macOS needs the final root before ditto extraction for the same reason.
	probeDir, err := os.MkdirTemp("", "neverlauncher-component-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(probeDir)
	if err := extractComponentPackage0157(packagePath, probeDir); err != nil {
		return nil, err
	}
	probeManifestPath, err := findComponentManifest0157(probeDir)
	if err != nil {
		return nil, err
	}
	manifest, err := readComponentUpdateManifest0157(probeManifestPath)
	if err != nil {
		return nil, err
	}
	if err := validateComponentUpdateManifest0157(manifest, filepath.Dir(probeManifestPath), allowDevelopment); err != nil {
		return nil, err
	}
	root, liveBundle, err := componentUpdateInstallRoot0157(currentDesktop, explicitRoot, manifest)
	if err != nil {
		return nil, err
	}
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		return nil, err
	}
	incomingRoot := filepath.Join(updater.controlDir, "component-incoming")
	if err := os.MkdirAll(incomingRoot, 0o700); err != nil {
		return nil, err
	}
	incoming, err := os.MkdirTemp(incomingRoot, "pkg-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(incoming) }()
	if err := extractComponentPackage0157(packagePath, incoming); err != nil {
		return nil, err
	}
	manifestPath, err := findComponentManifest0157(incoming)
	if err != nil {
		return nil, err
	}
	manifest, err = readComponentUpdateManifest0157(manifestPath)
	if err != nil {
		return nil, err
	}
	if err := validateComponentUpdateManifest0157(manifest, filepath.Dir(manifestPath), allowDevelopment); err != nil {
		return nil, err
	}
	if err := verifyComponentBinaries0157(manifest, filepath.Dir(manifestPath), false, allowDevelopment); err != nil && manifest.Layout == "adjacent-files" {
		return nil, fmt.Errorf("component package binary verification: %w", err)
	}
	var report map[string]any
	if manifest.Layout == "macos-app-bundle" {
		report, err = applyMacOSComponentUpdate0157(manifest, manifestPath, root, liveBundle, allowDevelopment)
	} else {
		report, err = applyAdjacentComponentUpdate0157(manifest, filepath.Dir(manifestPath), root, currentDesktop, allowDevelopment)
	}
	if err != nil {
		return nil, err
	}
	report["package"] = packagePath
	if expectedSHA != "" {
		report["packageSha256"] = strings.ToLower(expectedSHA)
	}
	if restart {
		executable, _ := report["restartExecutable"].(string)
		if strings.TrimSpace(executable) == "" {
			return nil, errors.New("component update committed but restart executable is unavailable")
		}
		cmd := exec.Command(executable)
		cmd.Dir = filepath.Dir(executable)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("component update committed but Desktop restart failed: %w", err)
		}
		report["restartedPid"] = cmd.Process.Pid
	}
	return report, nil
}

func runComponentUpdaterSelfTest0157() (map[string]any, error) {
	root, err := os.MkdirTemp("", "neverlauncher-component-selftest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	live := filepath.Join(root, "live")
	bundle := filepath.Join(root, "bundle")
	if err := os.MkdirAll(live, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"neverlauncher-desktop": "old-desktop", "neverguard": "old-guard", "neverruntime": "old-runtime"} {
		if err := os.WriteFile(filepath.Join(live, name), []byte(value), 0o755); err != nil {
			return nil, err
		}
	}
	components := []componentUpdateArtifact0157{}
	for _, row := range []struct{ component, name, data string }{{"desktop", "neverlauncher-desktop", "new-desktop"}, {"guard", "neverguard", "new-guard"}, {"runtime", "neverruntime", "new-runtime"}} {
		path := filepath.Join(bundle, row.name)
		if err := os.WriteFile(path, []byte(row.data), 0o755); err != nil {
			return nil, err
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		components = append(components, componentUpdateArtifact0157{Component: row.component, SourcePath: row.name, TargetPath: row.name, SHA256: sum, Size: size, Executable: true})
	}
	target, _ := currentDeliveryTarget()
	manifest := componentUpdateManifest0157{SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: version, Platform: target.Platform, Architecture: target.Architecture, Layout: "adjacent-files", TrustMode: "development-self-test", Components: components}
	if err := writeJSONFile(filepath.Join(bundle, componentUpdateManifestFile0157), manifest); err != nil {
		return nil, err
	}
	report, err := applyComponentPackage0157(bundle, "", "", live, filepath.Join(live, "neverlauncher-desktop"), 0, false, true)
	if err != nil {
		return nil, err
	}
	for _, item := range components {
		if err := verifyUpdaterFile0156(filepath.Join(live, item.TargetPath), item.Size, item.SHA256); err != nil {
			return nil, err
		}
	}

	// Exercise the whole-app swap rollback path on every CI host. The tree is synthetic,
	// but the journal/rename/recovery machinery is exactly what macOS production uses.
	treeRoot := filepath.Join(root, "tree-root")
	if err := os.MkdirAll(filepath.Join(treeRoot, "NeverLauncher.app", "Contents", "MacOS"), 0o755); err != nil {
		return nil, err
	}
	oldDesktop := filepath.Join(treeRoot, "NeverLauncher.app", "Contents", "MacOS", "neverlauncher-desktop")
	if err := os.WriteFile(oldDesktop, []byte("old-tree-desktop"), 0o755); err != nil {
		return nil, err
	}
	treeUpdater, err := newTransactionalUpdater0156(treeRoot)
	if err != nil {
		return nil, err
	}
	stage := filepath.Join(treeUpdater.controlDir, "self-test-incoming", "NeverLauncher.app")
	if err := os.MkdirAll(filepath.Join(stage, "Contents", "MacOS"), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(stage, "Contents", "MacOS", "neverlauncher-desktop"), []byte("new-tree-desktop"), 0o755); err != nil {
		return nil, err
	}
	if _, err := applyComponentTree0157(treeUpdater, "NeverLauncher.app", stage, "0.15.6", version, func(string) error {
		return errors.New("forced component tree post-verify failure")
	}); err == nil {
		return nil, errors.New("component tree self-test expected automatic rollback")
	}
	restored, err := os.ReadFile(oldDesktop)
	if err != nil || string(restored) != "old-tree-desktop" {
		return nil, fmt.Errorf("component tree rollback self-test did not restore live app: %w", err)
	}
	return map[string]any{"schemaVersion": "1.0", "toolVersion": version, "components": []string{"desktop", "guard", "runtime"}, "transaction": report, "macosTreeRollback": "ok", "status": "ok"}, nil
}

func parseWaitPID0157(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 0 {
		return 0, errors.New("--wait-pid must be a positive integer")
	}
	return pid, nil
}
