package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const managedJREManifestFile0155 = "MANAGED_JRE_MANIFEST.json"
const managedJREEvidenceFile0155 = "MANAGED_JRE_EVIDENCE.json"
const managedJREMajor0155 = 21
const maxManagedJREEntry0155 = int64(256 * 1024 * 1024)

type ManagedJRETarget0155 struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Distribution string `json:"distribution"`
	MajorVersion int    `json:"majorVersion"`
	ReleaseName  string `json:"releaseName"`
	Semver       string `json:"semver"`
	Archive      string `json:"archive"`
	Format       string `json:"format"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	JavaEntry    string `json:"javaEntry"`
	SourceURL    string `json:"sourceUrl"`
	SourceSHA256 string `json:"sourceSha256"`
	VendorOS     string `json:"vendorOs"`
	VendorArch   string `json:"vendorArch"`
}

type ManagedJREManifest0155 struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	Product        string                 `json:"product"`
	ProductVersion string                 `json:"productVersion"`
	Distribution   string                 `json:"distribution"`
	Vendor         string                 `json:"vendor"`
	MajorVersion   int                    `json:"majorVersion"`
	GeneratedAt    string                 `json:"generatedAt"`
	Targets        []ManagedJRETarget0155 `json:"targets"`
}

type ManagedJREEvidenceTarget0155 struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Archive      string `json:"archive"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	SourceURL    string `json:"sourceUrl"`
	SourceSHA256 string `json:"sourceSha256"`
}

type ManagedJREEvidence0155 struct {
	SchemaVersion  string                         `json:"schemaVersion"`
	Product        string                         `json:"product"`
	ProductVersion string                         `json:"productVersion"`
	Distribution   string                         `json:"distribution"`
	Vendor         string                         `json:"vendor"`
	IntegrityMode  string                         `json:"integrityMode"`
	Manifest       string                         `json:"manifest"`
	ManifestSHA256 string                         `json:"manifestSha256"`
	GeneratedAt    string                         `json:"generatedAt"`
	Targets        []ManagedJREEvidenceTarget0155 `json:"targets"`
}

func managedJREDistributionRequired0155(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 5)))
}

func managedJREArchiveName0155(ver, platform, arch string) string {
	ext := ".tar.gz"
	if platform == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("neverlauncher-jre-temurin%d-%s-%s-%s%s", managedJREMajor0155, platform, arch, ver, ext)
}

func managedJREArtifacts0155(ver string) []string {
	result := []string{managedJREManifestFile0155, managedJREEvidenceFile0155}
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"x64", "arm64"} {
			result = append(result, managedJREArchiveName0155(ver, platform, arch))
		}
	}
	return result
}

func expectedManagedJRETargets0155(ver string) map[string]string {
	result := map[string]string{}
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"x64", "arm64"} {
			result[platform+"/"+arch] = managedJREArchiveName0155(ver, platform, arch)
		}
	}
	return result
}

func validHTTPSURL0155(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func readManagedJREManifest0155(dir string) (ManagedJREManifest0155, string, error) {
	path := filepath.Join(dir, managedJREManifestFile0155)
	raw, err := os.ReadFile(path)
	if err != nil {
		return ManagedJREManifest0155{}, "", err
	}
	var manifest ManagedJREManifest0155
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ManagedJREManifest0155{}, "", fmt.Errorf("invalid %s: %w", managedJREManifestFile0155, err)
	}
	sum, _, err := hashFile(path)
	return manifest, sum, err
}

func readManagedJREEvidence0155(dir string) (ManagedJREEvidence0155, error) {
	raw, err := os.ReadFile(filepath.Join(dir, managedJREEvidenceFile0155))
	if err != nil {
		return ManagedJREEvidence0155{}, err
	}
	var evidence ManagedJREEvidence0155
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return ManagedJREEvidence0155{}, fmt.Errorf("invalid %s: %w", managedJREEvidenceFile0155, err)
	}
	return evidence, nil
}

func normalizeArchiveEntry0155(name string) (string, error) {
	normalized := strings.ReplaceAll(name, "\\", "/")
	normalized = strings.TrimSuffix(normalized, "/")
	if normalized == "" {
		return "", nil
	}
	if strings.HasPrefix(normalized, "/") || strings.Contains(normalized, "\x00") {
		return "", fmt.Errorf("unsafe JRE archive entry %q", name)
	}
	clean := filepath.ToSlash(filepath.Clean(normalized))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("unsafe JRE archive entry %q", name)
	}
	return clean, nil
}

func validateArchiveLink0155(entry, target string) error {
	if strings.TrimSpace(target) == "" {
		return errors.New("JRE archive contains empty symlink target")
	}
	target = strings.ReplaceAll(target, "\\", "/")
	if strings.HasPrefix(target, "/") || filepath.IsAbs(target) {
		return fmt.Errorf("JRE archive symlink %s has absolute target", entry)
	}
	base := filepath.ToSlash(filepath.Dir(entry))
	resolved := filepath.ToSlash(filepath.Clean(filepath.Join(base, target)))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("JRE archive symlink %s escapes archive root", entry)
	}
	return nil
}

func validateManagedJREBinary0155(platform, arch string, data []byte) error {
	switch platform {
	case "windows":
		info, err := inspectWindowsPEBytes0152(data)
		if err != nil {
			return fmt.Errorf("java.exe PE validation: %w", err)
		}
		if info.Architecture != arch {
			return fmt.Errorf("java.exe architecture=%s, expected %s", info.Architecture, arch)
		}
	case "linux":
		info, err := inspectLinuxELFBytes0153(data)
		if err != nil {
			return fmt.Errorf("bin/java ELF validation: %w", err)
		}
		if info.Architecture != arch {
			return fmt.Errorf("bin/java architecture=%s, expected %s", info.Architecture, arch)
		}
	case "macos":
		info, err := inspectMacOSMachOBytes0154(data)
		if err != nil {
			return fmt.Errorf("bin/java Mach-O validation: %w", err)
		}
		if info.Architecture != arch {
			return fmt.Errorf("bin/java architecture=%s, expected %s", info.Architecture, arch)
		}
	default:
		return fmt.Errorf("unsupported Managed JRE platform %q", platform)
	}
	return nil
}

func scanManagedJREZip0155(path, platform, arch string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(file, st.Size())
	if err != nil {
		return "", err
	}
	if len(zr.File) == 0 || len(zr.File) > 100000 {
		return "", fmt.Errorf("invalid JRE zip entry count %d", len(zr.File))
	}
	javaEntry := ""
	for _, zf := range zr.File {
		clean, err := normalizeArchiveEntry0155(zf.Name)
		if err != nil {
			return "", err
		}
		if clean == "" || zf.FileInfo().IsDir() {
			continue
		}
		if zf.Mode()&os.ModeSymlink != 0 {
			rc, err := zf.Open()
			if err != nil {
				return "", err
			}
			raw, err := io.ReadAll(io.LimitReader(rc, 4097))
			rc.Close()
			if err != nil || len(raw) > 4096 {
				return "", fmt.Errorf("invalid JRE zip symlink %s", clean)
			}
			if err := validateArchiveLink0155(clean, string(raw)); err != nil {
				return "", err
			}
			continue
		}
		if strings.HasSuffix(strings.ToLower(clean), "/bin/java.exe") {
			if javaEntry != "" {
				return "", errors.New("JRE archive contains multiple bin/java.exe entries")
			}
			if zf.UncompressedSize64 == 0 || zf.UncompressedSize64 > uint64(maxManagedJREEntry0155) {
				return "", errors.New("JRE java.exe has invalid size")
			}
			rc, err := zf.Open()
			if err != nil {
				return "", err
			}
			data, err := io.ReadAll(io.LimitReader(rc, maxManagedJREEntry0155+1))
			rc.Close()
			if err != nil || int64(len(data)) > maxManagedJREEntry0155 {
				return "", errors.New("JRE java.exe cannot be read safely")
			}
			if err := validateManagedJREBinary0155(platform, arch, data); err != nil {
				return "", err
			}
			javaEntry = clean
		}
	}
	if javaEntry == "" {
		return "", errors.New("JRE archive does not contain bin/java.exe")
	}
	return javaEntry, nil
}

func scanManagedJRETarGz0155(path, platform, arch string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	javaEntry := ""
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		entries++
		if entries > 100000 {
			return "", errors.New("JRE tar contains too many entries")
		}
		clean, err := normalizeArchiveEntry0155(hdr.Name)
		if err != nil {
			return "", err
		}
		if clean == "" {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeSymlink:
			if err := validateArchiveLink0155(clean, hdr.Linkname); err != nil {
				return "", err
			}
			continue
		case tar.TypeLink:
			linked, err := normalizeArchiveEntry0155(hdr.Linkname)
			if err != nil || linked == "" {
				return "", fmt.Errorf("unsafe JRE tar hardlink %s -> %q", clean, hdr.Linkname)
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return "", fmt.Errorf("unsupported JRE tar entry type %d for %s", hdr.Typeflag, clean)
		}
		if strings.HasSuffix(strings.ToLower(clean), "/bin/java") {
			if javaEntry != "" {
				return "", errors.New("JRE archive contains multiple bin/java entries")
			}
			if hdr.Size <= 0 || hdr.Size > maxManagedJREEntry0155 {
				return "", errors.New("JRE bin/java has invalid size")
			}
			data, err := io.ReadAll(io.LimitReader(tr, maxManagedJREEntry0155+1))
			if err != nil || int64(len(data)) != hdr.Size {
				return "", errors.New("JRE bin/java cannot be read safely")
			}
			if err := validateManagedJREBinary0155(platform, arch, data); err != nil {
				return "", err
			}
			javaEntry = clean
		}
	}
	if javaEntry == "" {
		return "", errors.New("JRE archive does not contain bin/java")
	}
	return javaEntry, nil
}

func verifyManagedJREArchive0155(dir string, target ManagedJRETarget0155) error {
	path, err := safeDeliveryArtifactPath(dir, target.Archive)
	if err != nil {
		return err
	}
	sum, size, err := hashFile(path)
	if err != nil {
		return err
	}
	if target.Size <= 0 || size != target.Size || !validDeliverySHA256(target.SHA256) || !strings.EqualFold(sum, target.SHA256) {
		return fmt.Errorf("Managed JRE %s/%s archive checksum/size mismatch", target.Platform, target.Architecture)
	}
	if !validDeliverySHA256(target.SourceSHA256) || !strings.EqualFold(target.SourceSHA256, target.SHA256) {
		return fmt.Errorf("Managed JRE %s/%s is not the exact vendor archive", target.Platform, target.Architecture)
	}
	if !validHTTPSURL0155(target.SourceURL) {
		return fmt.Errorf("Managed JRE %s/%s sourceUrl must be HTTPS", target.Platform, target.Architecture)
	}
	var javaEntry string
	if target.Platform == "windows" {
		if target.Format != "zip" || !strings.HasSuffix(strings.ToLower(target.Archive), ".zip") {
			return errors.New("Windows Managed JRE must use zip")
		}
		javaEntry, err = scanManagedJREZip0155(path, target.Platform, target.Architecture)
	} else {
		if target.Format != "tar.gz" || !strings.HasSuffix(strings.ToLower(target.Archive), ".tar.gz") {
			return fmt.Errorf("%s Managed JRE must use tar.gz", target.Platform)
		}
		javaEntry, err = scanManagedJRETarGz0155(path, target.Platform, target.Architecture)
	}
	if err != nil {
		return fmt.Errorf("Managed JRE %s/%s archive validation: %w", target.Platform, target.Architecture, err)
	}
	if target.JavaEntry != javaEntry {
		return fmt.Errorf("Managed JRE %s/%s javaEntry mismatch: manifest=%s archive=%s", target.Platform, target.Architecture, target.JavaEntry, javaEntry)
	}
	return nil
}

func verifyManagedJREDistribution0155(dir, ver string, requireDeliveryBinding bool) error {
	if !managedJREDistributionRequired0155(ver) {
		return nil
	}
	manifest, manifestHash, err := readManagedJREManifest0155(dir)
	if err != nil {
		return err
	}
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || manifest.ProductVersion != ver || manifest.Distribution != "temurin" || manifest.Vendor != "Eclipse Adoptium" || manifest.MajorVersion != managedJREMajor0155 || strings.TrimSpace(manifest.GeneratedAt) == "" {
		return errors.New("Managed JRE manifest identity/schema mismatch")
	}
	expected := expectedManagedJRETargets0155(ver)
	if len(manifest.Targets) != len(expected) {
		return fmt.Errorf("Managed JRE manifest must contain %d targets", len(expected))
	}
	targetByKey := map[string]ManagedJRETarget0155{}
	for _, target := range manifest.Targets {
		canonical, err := canonicalDeliveryTarget(target.Platform, target.Architecture)
		if err != nil || canonical.Platform == "any" || canonical.Architecture == "any" || canonical.Architecture == "universal" {
			return fmt.Errorf("Managed JRE target invalid: %s/%s", target.Platform, target.Architecture)
		}
		key := canonical.Platform + "/" + canonical.Architecture
		expectedArchive, ok := expected[key]
		if !ok || target.Archive != expectedArchive || target.Platform != canonical.Platform || target.Architecture != canonical.Architecture {
			return fmt.Errorf("unexpected Managed JRE target %s archive=%s", key, target.Archive)
		}
		if _, duplicate := targetByKey[key]; duplicate {
			return fmt.Errorf("duplicate Managed JRE target %s", key)
		}
		expectedVendorOS := map[string]string{"windows": "windows", "linux": "linux", "macos": "mac"}[target.Platform]
		expectedVendorArch := map[string]string{"x64": "x64", "arm64": "aarch64"}[target.Architecture]
		if target.Distribution != "temurin" || target.MajorVersion != managedJREMajor0155 || strings.TrimSpace(target.ReleaseName) == "" || strings.TrimSpace(target.Semver) == "" || target.VendorOS != expectedVendorOS || target.VendorArch != expectedVendorArch {
			return fmt.Errorf("Managed JRE %s metadata incomplete/mismatched", key)
		}
		if err := verifyManagedJREArchive0155(dir, target); err != nil {
			return err
		}
		targetByKey[key] = target
	}

	evidence, err := readManagedJREEvidence0155(dir)
	if err != nil {
		return err
	}
	if evidence.SchemaVersion != "1.0" || evidence.Product != "NeverLauncher" || evidence.ProductVersion != ver || evidence.Distribution != "temurin" || evidence.Vendor != "Eclipse Adoptium" || evidence.IntegrityMode != "exact-vendor-archive-sha256" || evidence.Manifest != managedJREManifestFile0155 || !validDeliverySHA256(evidence.ManifestSHA256) || !strings.EqualFold(evidence.ManifestSHA256, manifestHash) || strings.TrimSpace(evidence.GeneratedAt) == "" {
		return errors.New("Managed JRE evidence identity/manifest hash mismatch")
	}
	if len(evidence.Targets) != len(expected) {
		return errors.New("Managed JRE evidence target count mismatch")
	}
	seenEvidence := map[string]bool{}
	for _, item := range evidence.Targets {
		key := item.Platform + "/" + item.Architecture
		target, ok := targetByKey[key]
		if !ok || seenEvidence[key] {
			return fmt.Errorf("Managed JRE evidence unexpected/duplicate target %s", key)
		}
		seenEvidence[key] = true
		if item.Archive != target.Archive || item.Size != target.Size || !strings.EqualFold(item.SHA256, target.SHA256) || item.SourceURL != target.SourceURL || !strings.EqualFold(item.SourceSHA256, target.SourceSHA256) {
			return fmt.Errorf("Managed JRE evidence mismatch for %s", key)
		}
	}

	if requireDeliveryBinding {
		delivery, err := readDeliveryManifest0151(dir)
		if err != nil {
			return err
		}
		deliveryByName := map[string]DeliveryArtifact{}
		for _, artifact := range delivery.Artifacts {
			deliveryByName[artifact.Name] = artifact
		}
		for _, name := range managedJREArtifacts0155(ver) {
			path, err := safeDeliveryArtifactPath(dir, name)
			if err != nil {
				return err
			}
			sum, size, err := hashFile(path)
			if err != nil {
				return err
			}
			artifact, ok := deliveryByName[name]
			if !ok || artifact.Size != size || !strings.EqualFold(artifact.SHA256, sum) {
				return fmt.Errorf("Managed JRE artifact %s is not bound to DELIVERY_MANIFEST.json", name)
			}
			if strings.HasPrefix(name, "neverlauncher-jre-") && artifact.Component != "managed-jre" {
				return fmt.Errorf("Managed JRE artifact %s has delivery component %s", name, artifact.Component)
			}
		}
	}
	return nil
}

func sortedManagedJRETargets0155(targets []ManagedJRETarget0155) []ManagedJRETarget0155 {
	copyTargets := append([]ManagedJRETarget0155(nil), targets...)
	sort.Slice(copyTargets, func(i, j int) bool {
		return copyTargets[i].Platform+"/"+copyTargets[i].Architecture < copyTargets[j].Platform+"/"+copyTargets[j].Architecture
	})
	return copyTargets
}
