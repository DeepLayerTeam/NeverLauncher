package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const macOSNotarizationEvidenceFile0154 = "MACOS_NOTARIZATION_EVIDENCE.json"
const macOSDeliveryAllowlistFile0154 = "GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json"

var macOSTeamIDRE0154 = regexp.MustCompile(`^[A-Z0-9]{10}$`)
var macOSNotaryIDRE0154 = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type MacOSPackageArtifact0154 struct {
	Name            string `json:"name"`
	BundlePath      string `json:"bundlePath"`
	Component       string `json:"component"`
	Architecture    string `json:"architecture"`
	CPUType         string `json:"cpuType"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	CodeSigned      bool   `json:"codeSigned"`
	HardenedRuntime bool   `json:"hardenedRuntime"`
	TeamID          string `json:"teamId"`
}

type MacOSPackageManifest0154 struct {
	SchemaVersion        string                     `json:"schemaVersion"`
	Product              string                     `json:"product"`
	ProductVersion       string                     `json:"productVersion"`
	Platform             string                     `json:"platform"`
	Architecture         string                     `json:"architecture"`
	CPUType              string                     `json:"cpuType"`
	RustTarget           string                     `json:"rustTarget"`
	PackageFormat        string                     `json:"packageFormat"`
	PackageArtifact      string                     `json:"packageArtifact"`
	BundleIdentifier     string                     `json:"bundleIdentifier"`
	MinimumSystemVersion string                     `json:"minimumSystemVersion"`
	Artifacts            []MacOSPackageArtifact0154 `json:"artifacts"`
}

type MacOSNotarizedPackage0154 struct {
	Name                   string `json:"name"`
	SHA256                 string `json:"sha256"`
	Size                   int64  `json:"size"`
	Manifest               string `json:"manifest"`
	ManifestSHA256         string `json:"manifestSha256"`
	NotarySubmissionID     string `json:"notarySubmissionId,omitempty"`
	NotaryStatus           string `json:"notaryStatus"`
	Stapled                bool   `json:"stapled"`
	StaplerValidated       bool   `json:"staplerValidated"`
	GatekeeperAccepted     bool   `json:"gatekeeperAccepted"`
	BundleCodeSignVerified bool   `json:"bundleCodeSignVerified"`
}

type MacOSNotarizationTarget0154 struct {
	Architecture string                     `json:"architecture"`
	CPUType      string                     `json:"cpuType"`
	RustTarget   string                     `json:"rustTarget"`
	Package      MacOSNotarizedPackage0154  `json:"package"`
	Artifacts    []MacOSPackageArtifact0154 `json:"artifacts"`
}

type MacOSNotarizationEvidence0154 struct {
	SchemaVersion  string                        `json:"schemaVersion"`
	Product        string                        `json:"product"`
	ProductVersion string                        `json:"productVersion"`
	Platform       string                        `json:"platform"`
	SigningMode    string                        `json:"signingMode"`
	TeamID         string                        `json:"teamId"`
	GeneratedAt    string                        `json:"generatedAt"`
	Targets        []MacOSNotarizationTarget0154 `json:"targets"`
}

type macOSMachOInfo0154 struct {
	Architecture     string
	CPUType          uint32
	CPUTypeText      string
	HasCodeSignature bool
}

func macOSProductionRequired0154(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 4)))
}

func macOSTargetMetadata0154(arch string) (rustTarget string, cpuType uint32, cpuTypeText string, err error) {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x64":
		return "x86_64-apple-darwin", 0x01000007, "CPU_TYPE_X86_64", nil
	case "arm64":
		return "aarch64-apple-darwin", 0x0100000c, "CPU_TYPE_ARM64", nil
	default:
		return "", 0, "", fmt.Errorf("unsupported macOS architecture %q", arch)
	}
}

func expectedMacOSArtifacts0154(arch string) map[string]string {
	return map[string]string{
		"cli":              "neverlauncher-cli-macos-" + arch,
		"desktop-launcher": "neverlauncher-desktop-macos-" + arch,
		"guard":            "neverguard-macos-" + arch,
		"runtime":          "neverruntime-macos-" + arch,
	}
}

func expectedMacOSPackage0154(ver, arch string) (string, string) {
	return "neverlauncher-desktop-" + ver + "-macos-" + arch + ".zip", "MACOS_PACKAGE_MANIFEST_" + strings.ToUpper(arch) + ".json"
}

func inspectMacOSMachOBytes0154(data []byte) (macOSMachOInfo0154, error) {
	if len(data) < 32 {
		return macOSMachOInfo0154{}, errors.New("Mach-O header is truncated")
	}
	// 64-bit little-endian Mach-O magic (MH_MAGIC_64) appears as cf fa ed fe on disk.
	if !bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
		return macOSMachOInfo0154{}, fmt.Errorf("unsupported Mach-O magic %x; thin 64-bit little-endian image required", data[:4])
	}
	cpuType := binary.LittleEndian.Uint32(data[4:8])
	info := macOSMachOInfo0154{CPUType: cpuType}
	switch cpuType {
	case 0x01000007:
		info.Architecture = "x64"
		info.CPUTypeText = "CPU_TYPE_X86_64"
	case 0x0100000c:
		info.Architecture = "arm64"
		info.CPUTypeText = "CPU_TYPE_ARM64"
	default:
		return macOSMachOInfo0154{}, fmt.Errorf("unsupported Mach-O cputype=0x%08X", cpuType)
	}
	ncmds := int(binary.LittleEndian.Uint32(data[16:20]))
	sizeofcmds := int(binary.LittleEndian.Uint32(data[20:24]))
	if ncmds <= 0 || sizeofcmds <= 0 || 32+sizeofcmds > len(data) {
		return macOSMachOInfo0154{}, errors.New("invalid Mach-O load-command table")
	}
	offset := 32
	for i := 0; i < ncmds; i++ {
		if offset+8 > len(data) || offset+8 > 32+sizeofcmds {
			return macOSMachOInfo0154{}, errors.New("truncated Mach-O load command")
		}
		cmd := binary.LittleEndian.Uint32(data[offset : offset+4])
		cmdSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if cmdSize < 8 || offset+cmdSize > len(data) || offset+cmdSize > 32+sizeofcmds {
			return macOSMachOInfo0154{}, errors.New("invalid Mach-O load command size")
		}
		if cmd == 0x1d { // LC_CODE_SIGNATURE
			if cmdSize < 16 {
				return macOSMachOInfo0154{}, errors.New("LC_CODE_SIGNATURE is truncated")
			}
			dataOffset := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
			dataSize := int(binary.LittleEndian.Uint32(data[offset+12 : offset+16]))
			if dataOffset <= 0 || dataSize <= 0 || dataOffset+dataSize > len(data) {
				return macOSMachOInfo0154{}, errors.New("LC_CODE_SIGNATURE points outside Mach-O file")
			}
			info.HasCodeSignature = true
		}
		offset += cmdSize
	}
	return info, nil
}

func inspectMacOSMachOFile0154(path string) (macOSMachOInfo0154, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return macOSMachOInfo0154{}, err
	}
	return inspectMacOSMachOBytes0154(data)
}

func readMacOSPackageManifest0154(dir, arch string) (MacOSPackageManifest0154, string, error) {
	_, manifestName := expectedMacOSPackage0154("ignored", arch)
	path := filepath.Join(dir, manifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return MacOSPackageManifest0154{}, "", err
	}
	var manifest MacOSPackageManifest0154
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return MacOSPackageManifest0154{}, "", fmt.Errorf("invalid %s: %w", manifestName, err)
	}
	sum, _, err := hashFile(path)
	if err != nil {
		return MacOSPackageManifest0154{}, "", err
	}
	return manifest, sum, nil
}

func verifyMacOSPackageManifest0154(dir, ver, arch string, requireSigned bool, expectedTeamID string) (MacOSPackageManifest0154, string, error) {
	manifest, manifestHash, err := readMacOSPackageManifest0154(dir, arch)
	if err != nil {
		return MacOSPackageManifest0154{}, "", err
	}
	expectedPackage, _ := expectedMacOSPackage0154(ver, arch)
	rustTarget, _, cpuText, err := macOSTargetMetadata0154(arch)
	if err != nil {
		return MacOSPackageManifest0154{}, "", err
	}
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || manifest.ProductVersion != ver || manifest.Platform != "macos" || manifest.Architecture != arch || manifest.CPUType != cpuText || manifest.RustTarget != rustTarget || manifest.PackageFormat != "zip" || manifest.PackageArtifact != expectedPackage || manifest.BundleIdentifier != "ru.skif4er.neverlauncher" || strings.TrimSpace(manifest.MinimumSystemVersion) == "" {
		return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s package manifest identity/schema mismatch", arch)
	}
	expected := expectedMacOSArtifacts0154(arch)
	if len(manifest.Artifacts) != len(expected) {
		return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s package manifest must contain %d artifacts", arch, len(expected))
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		expectedName, ok := expected[artifact.Component]
		if !ok || artifact.Name != expectedName || artifact.Architecture != arch || artifact.CPUType != cpuText || !strings.HasPrefix(artifact.BundlePath, "NeverLauncher.app/Contents/MacOS/") || strings.Contains(artifact.BundlePath, "..") {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s package artifact identity mismatch: %s", arch, artifact.Name)
		}
		if seen[artifact.Component] {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s duplicate package component %s", arch, artifact.Component)
		}
		seen[artifact.Component] = true
		path, err := safeDeliveryArtifactPath(dir, artifact.Name)
		if err != nil {
			return MacOSPackageManifest0154{}, "", err
		}
		actualHash, actualSize, err := hashFile(path)
		if err != nil {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s artifact %s: %w", arch, artifact.Name, err)
		}
		if artifact.Size <= 0 || artifact.Size != actualSize || !validDeliverySHA256(artifact.SHA256) || !strings.EqualFold(artifact.SHA256, actualHash) {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s artifact %s checksum/size mismatch", arch, artifact.Name)
		}
		macho, err := inspectMacOSMachOFile0154(path)
		if err != nil || macho.Architecture != arch || macho.CPUTypeText != cpuText || !macho.HasCodeSignature {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s artifact %s Mach-O/code-signature validation failed: %v", arch, artifact.Name, err)
		}
		if !artifact.CodeSigned || !artifact.HardenedRuntime {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s artifact %s lacks signed+hardened-runtime evidence", arch, artifact.Name)
		}
		if requireSigned {
			if !macOSTeamIDRE0154.MatchString(artifact.TeamID) || !strings.EqualFold(artifact.TeamID, expectedTeamID) {
				return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s artifact %s Team ID mismatch", arch, artifact.Name)
			}
		} else if strings.TrimSpace(artifact.TeamID) == "" {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s artifact %s Team ID/mode marker missing", arch, artifact.Name)
		}
	}
	return manifest, manifestHash, nil
}

func readZipEntries0154(path string) (map[string][]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	entries := map[string][]byte{}
	for _, file := range zr.File {
		name := filepath.ToSlash(filepath.Clean(file.Name))
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(file.Name, "/") {
			return nil, fmt.Errorf("unsafe macOS package zip entry %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if _, duplicate := entries[name]; duplicate {
			return nil, fmt.Errorf("duplicate macOS package zip entry %s", name)
		}
		if file.UncompressedSize64 > 512*1024*1024 {
			return nil, fmt.Errorf("macOS package zip entry too large: %s", name)
		}
		r, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(r, 512*1024*1024+1))
		r.Close()
		if err != nil {
			return nil, err
		}
		if len(data) > 512*1024*1024 {
			return nil, fmt.Errorf("macOS package zip entry too large: %s", name)
		}
		entries[name] = data
	}
	return entries, nil
}

func verifyMacOSPackageArchive0154(dir, ver, arch string, manifest MacOSPackageManifest0154, manifestHash string, evidencePackage MacOSNotarizedPackage0154) error {
	packageName, manifestName := expectedMacOSPackage0154(ver, arch)
	if evidencePackage.Name != packageName || evidencePackage.Manifest != manifestName || !strings.EqualFold(evidencePackage.ManifestSHA256, manifestHash) {
		return fmt.Errorf("macOS %s package evidence identity mismatch", arch)
	}
	packagePath, err := safeDeliveryArtifactPath(dir, packageName)
	if err != nil {
		return err
	}
	actualHash, actualSize, err := hashFile(packagePath)
	if err != nil {
		return err
	}
	if evidencePackage.Size <= 0 || evidencePackage.Size != actualSize || !validDeliverySHA256(evidencePackage.SHA256) || !strings.EqualFold(evidencePackage.SHA256, actualHash) {
		return fmt.Errorf("macOS %s package checksum/size mismatch", arch)
	}
	entries, err := readZipEntries0154(packagePath)
	if err != nil {
		return fmt.Errorf("macOS %s package zip: %w", arch, err)
	}
	for _, artifact := range manifest.Artifacts {
		data, ok := entries[artifact.BundlePath]
		if !ok {
			return fmt.Errorf("macOS %s package missing %s", arch, artifact.BundlePath)
		}
		sum, size := hashBytes0154(data)
		if size != artifact.Size || !strings.EqualFold(sum, artifact.SHA256) {
			return fmt.Errorf("macOS %s package payload mismatch for %s", arch, artifact.BundlePath)
		}
		macho, err := inspectMacOSMachOBytes0154(data)
		if err != nil || macho.Architecture != arch || !macho.HasCodeSignature {
			return fmt.Errorf("macOS %s package payload Mach-O mismatch for %s", arch, artifact.BundlePath)
		}
	}
	manifestPath := "NeverLauncher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json"
	embedded, ok := entries[manifestPath]
	if !ok {
		return fmt.Errorf("macOS %s package missing embedded manifest", arch)
	}
	top, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(embedded), bytes.TrimSpace(top)) {
		return fmt.Errorf("macOS %s embedded package manifest mismatch", arch)
	}
	return nil
}

func hashBytes0154(data []byte) (string, int64) {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), int64(len(data))
}

func readMacOSNotarizationEvidence0154(dir string) (MacOSNotarizationEvidence0154, error) {
	raw, err := os.ReadFile(filepath.Join(dir, macOSNotarizationEvidenceFile0154))
	if err != nil {
		return MacOSNotarizationEvidence0154{}, err
	}
	var evidence MacOSNotarizationEvidence0154
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return MacOSNotarizationEvidence0154{}, fmt.Errorf("invalid %s: %w", macOSNotarizationEvidenceFile0154, err)
	}
	return evidence, nil
}

func verifyMacOSDeliveryAllowlist0154(dir, ver string, evidence MacOSNotarizationEvidence0154, production bool) error {
	raw, err := os.ReadFile(filepath.Join(dir, macOSDeliveryAllowlistFile0154))
	if err != nil {
		return err
	}
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Releases      map[string]struct {
			ProtocolVersion int `json:"protocolVersion"`
			Platforms       map[string]struct {
				SigningMode string `json:"signingMode"`
				Artifacts   []struct {
					Architecture   string `json:"architecture"`
					GuardSHA256    string `json:"guardSha256"`
					LauncherSHA256 string `json:"launcherSha256"`
					Notarized      bool   `json:"notarized"`
				} `json:"artifacts"`
			} `json:"platforms"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	release, ok := doc.Releases[ver]
	if doc.SchemaVersion != "3.0" || !ok || release.ProtocolVersion != 4 {
		return errors.New("macOS delivery allowlist identity/schema mismatch")
	}
	policy, ok := release.Platforms["macos"]
	expectedMode := evidence.SigningMode
	if !ok || policy.SigningMode != expectedMode || len(policy.Artifacts) != 2 {
		return errors.New("macOS delivery allowlist platform metadata mismatch")
	}
	expected := map[string]string{}
	for _, target := range evidence.Targets {
		var guard, launcher string
		for _, artifact := range target.Artifacts {
			if artifact.Component == "guard" {
				guard = artifact.SHA256
			}
			if artifact.Component == "desktop-launcher" {
				launcher = artifact.SHA256
			}
		}
		expected[target.Architecture] = strings.ToLower(guard + ":" + launcher)
	}
	seen := map[string]bool{}
	for _, row := range policy.Artifacts {
		key := strings.ToLower(row.GuardSHA256 + ":" + row.LauncherSHA256)
		if (row.Architecture != "x64" && row.Architecture != "arm64") || !validDeliverySHA256(row.GuardSHA256) || !validDeliverySHA256(row.LauncherSHA256) || expected[row.Architecture] != key || seen[row.Architecture] || row.Notarized != production {
			return errors.New("macOS delivery allowlist contains unexpected/duplicate artifact pair")
		}
		seen[row.Architecture] = true
	}
	if !seen["x64"] || !seen["arm64"] {
		return errors.New("macOS delivery allowlist must cover x64 and arm64")
	}
	return nil
}

func verifyMacOSNativePackage0154(packagePath, expectedTeamID string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		return errors.New("codesign is required for native macOS verification")
	}
	xcrun, err := exec.LookPath("xcrun")
	if err != nil {
		return errors.New("xcrun is required for stapler verification")
	}
	ditto, err := exec.LookPath("ditto")
	if err != nil {
		return errors.New("ditto is required to preserve notarization ticket metadata")
	}
	spctl := "/usr/sbin/spctl"
	if _, err := os.Stat(spctl); err != nil {
		return errors.New("spctl is required for Gatekeeper verification")
	}
	tmp, err := os.MkdirTemp("", "neverlauncher-macos-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// Cross-platform verification has already validated every ZIP path and its
	// embedded bytes. Native verification intentionally uses ditto so AppleDouble
	// data, extended attributes and the stapled notarization ticket survive
	// extraction before stapler/Gatekeeper inspect the .app bundle.
	if output, err := exec.Command(ditto, "-x", "-k", packagePath, tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("ditto package extraction failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	app := filepath.Join(tmp, "NeverLauncher.app")
	if output, err := exec.Command(codesign, "--verify", "--deep", "--strict", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("codesign verify failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command(xcrun, "stapler", "validate", app).CombinedOutput(); err != nil {
		return fmt.Errorf("stapler validate failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command(spctl, "--assess", "--type", "execute", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("Gatekeeper assessment failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command(codesign, "-dv", "--verbose=4", app).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign display failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), "TeamIdentifier="+expectedTeamID) || !strings.Contains(string(output), "runtime") {
		return errors.New("native macOS package Team ID/Hardened Runtime mismatch")
	}
	return nil
}

func verifyMacOSNotarizationEvidence0154(dir, ver string, requireNotarized bool) error {
	evidence, err := readMacOSNotarizationEvidence0154(dir)
	if err != nil {
		return err
	}
	if evidence.SchemaVersion != "1.0" || evidence.Product != "NeverLauncher" || evidence.ProductVersion != ver || evidence.Platform != "macos" {
		return errors.New("macOS notarization evidence identity/schema mismatch")
	}
	production := evidence.SigningMode == "developer-id-notarized"
	development := evidence.SigningMode == "adhoc-development"
	if !production && !development {
		return fmt.Errorf("unsupported macOS signing mode %q", evidence.SigningMode)
	}
	if requireNotarized && !production {
		return errors.New("production publish requires Developer ID + Apple notarization for macOS x64 and ARM64")
	}
	if production {
		if !macOSTeamIDRE0154.MatchString(evidence.TeamID) {
			return errors.New("production macOS evidence contains invalid Team ID")
		}
	} else if evidence.TeamID != "ADHOC-CI" {
		return errors.New("ad-hoc macOS evidence must use Team ID marker ADHOC-CI")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.GeneratedAt); err != nil {
		if _, fallbackErr := time.Parse(time.RFC3339, evidence.GeneratedAt); fallbackErr != nil {
			return errors.New("macOS notarization evidence generatedAt is invalid")
		}
	}
	if len(evidence.Targets) != 2 {
		return fmt.Errorf("macOS notarization evidence must contain exactly x64+arm64 targets, got %d", len(evidence.Targets))
	}
	delivery, err := readDeliveryManifest0151(dir)
	if err != nil {
		return fmt.Errorf("macOS notarization evidence requires delivery manifest: %w", err)
	}
	deliveryByName := map[string]DeliveryArtifact{}
	for _, artifact := range delivery.Artifacts {
		deliveryByName[artifact.Name] = artifact
	}
	seen := map[string]bool{}
	for _, target := range evidence.Targets {
		if target.Architecture != "x64" && target.Architecture != "arm64" {
			return fmt.Errorf("unsupported macOS evidence architecture %s", target.Architecture)
		}
		if seen[target.Architecture] {
			return fmt.Errorf("duplicate macOS evidence target %s", target.Architecture)
		}
		seen[target.Architecture] = true
		rustTarget, _, cpuText, err := macOSTargetMetadata0154(target.Architecture)
		if err != nil {
			return err
		}
		if target.RustTarget != rustTarget || target.CPUType != cpuText {
			return fmt.Errorf("macOS %s target metadata mismatch", target.Architecture)
		}
		manifest, manifestHash, err := verifyMacOSPackageManifest0154(dir, ver, target.Architecture, production, evidence.TeamID)
		if err != nil {
			return err
		}
		if len(target.Artifacts) != len(manifest.Artifacts) {
			return fmt.Errorf("macOS %s evidence artifact count mismatch", target.Architecture)
		}
		expectedArtifacts := map[string]MacOSPackageArtifact0154{}
		for _, artifact := range manifest.Artifacts {
			expectedArtifacts[artifact.Component] = artifact
		}
		for _, artifact := range target.Artifacts {
			expected, ok := expectedArtifacts[artifact.Component]
			if !ok || artifact != expected {
				return fmt.Errorf("macOS %s evidence artifact mismatch: %s", target.Architecture, artifact.Name)
			}
			deliveryArtifact, ok := deliveryByName[artifact.Name]
			if !ok || deliveryArtifact.Platform != "macos" || deliveryArtifact.Architecture != target.Architecture || deliveryArtifact.Size != artifact.Size || !strings.EqualFold(deliveryArtifact.SHA256, artifact.SHA256) {
				return fmt.Errorf("macOS production artifact %s is not bound to DELIVERY_MANIFEST.json", artifact.Name)
			}
		}
		if err := verifyMacOSPackageArchive0154(dir, ver, target.Architecture, manifest, manifestHash, target.Package); err != nil {
			return err
		}
		packageDelivery, ok := deliveryByName[target.Package.Name]
		if !ok || packageDelivery.Platform != "macos" || packageDelivery.Architecture != target.Architecture || packageDelivery.Size != target.Package.Size || !strings.EqualFold(packageDelivery.SHA256, target.Package.SHA256) {
			return fmt.Errorf("macOS package %s delivery binding mismatch", target.Package.Name)
		}
		manifestDelivery, ok := deliveryByName[target.Package.Manifest]
		if !ok {
			return fmt.Errorf("macOS package manifest %s is not bound to DELIVERY_MANIFEST.json", target.Package.Manifest)
		}
		_ = manifestDelivery
		if production {
			if !macOSNotaryIDRE0154.MatchString(target.Package.NotarySubmissionID) || target.Package.NotaryStatus != "Accepted" || !target.Package.Stapled || !target.Package.StaplerValidated || !target.Package.GatekeeperAccepted || !target.Package.BundleCodeSignVerified {
				return fmt.Errorf("macOS %s package lacks accepted notarization/stapling/Gatekeeper evidence", target.Architecture)
			}
			if err := verifyMacOSNativePackage0154(filepath.Join(dir, target.Package.Name), evidence.TeamID); err != nil {
				return fmt.Errorf("macOS %s native verification: %w", target.Architecture, err)
			}
		} else {
			if target.Package.NotarySubmissionID != "" || target.Package.NotaryStatus != "not-requested" || target.Package.Stapled || target.Package.StaplerValidated || target.Package.GatekeeperAccepted || !target.Package.BundleCodeSignVerified {
				return fmt.Errorf("ad-hoc macOS %s evidence overclaims notarization state", target.Architecture)
			}
		}
	}
	if !seen["x64"] || !seen["arm64"] {
		return errors.New("macOS notarization evidence must cover both x64 and arm64")
	}
	if err := verifyMacOSDeliveryAllowlist0154(dir, ver, evidence, production); err != nil {
		return fmt.Errorf("macOS delivery Guard allowlist: %w", err)
	}
	return nil
}

func macOSProductionArtifacts0154(ver string) []string {
	names := []string{macOSNotarizationEvidenceFile0154, macOSDeliveryAllowlistFile0154}
	for _, arch := range []string{"x64", "arm64"} {
		for _, name := range expectedMacOSArtifacts0154(arch) {
			names = append(names, name)
		}
		pkg, manifest := expectedMacOSPackage0154(ver, arch)
		names = append(names, pkg, manifest)
	}
	sort.Strings(names)
	return names
}
