package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const linuxProductionEvidenceFile0153 = "LINUX_PRODUCTION_EVIDENCE.json"
const linuxDeliveryAllowlistFile0153 = "GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json"

type LinuxPackageArtifact0153 struct {
	Name         string `json:"name"`
	PackagePath  string `json:"packagePath"`
	Component    string `json:"component"`
	Architecture string `json:"architecture"`
	ELFMachine   string `json:"elfMachine"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Mode         string `json:"mode"`
}

type LinuxPackageManifest0153 struct {
	SchemaVersion   string                     `json:"schemaVersion"`
	Product         string                     `json:"product"`
	ProductVersion  string                     `json:"productVersion"`
	Platform        string                     `json:"platform"`
	Architecture    string                     `json:"architecture"`
	ELFMachine      string                     `json:"elfMachine"`
	PackageFormat   string                     `json:"packageFormat"`
	PackageArtifact string                     `json:"packageArtifact"`
	Artifacts       []LinuxPackageArtifact0153 `json:"artifacts"`
}

type LinuxProductionPackage0153 struct {
	Name           string `json:"name"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	Manifest       string `json:"manifest"`
	ManifestSHA256 string `json:"manifestSha256"`
}

type LinuxProductionTarget0153 struct {
	Architecture string                     `json:"architecture"`
	ELFMachine   string                     `json:"elfMachine"`
	Package      LinuxProductionPackage0153 `json:"package"`
	Artifacts    []LinuxPackageArtifact0153 `json:"artifacts"`
}

type LinuxProductionEvidence0153 struct {
	SchemaVersion  string                      `json:"schemaVersion"`
	Product        string                      `json:"product"`
	ProductVersion string                      `json:"productVersion"`
	Platform       string                      `json:"platform"`
	IntegrityMode  string                      `json:"integrityMode"`
	GeneratedAt    string                      `json:"generatedAt"`
	Targets        []LinuxProductionTarget0153 `json:"targets"`
}

type linuxELFInfo0153 struct {
	Architecture string
	Machine      uint16
	MachineText  string
	Type         uint16
}

func linuxProductionRequired0153(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 3)))
}

func linuxTargetMetadata0153(arch string) (machine uint16, machineText string, err error) {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x64":
		return 62, "EM_X86_64", nil
	case "arm64":
		return 183, "EM_AARCH64", nil
	default:
		return 0, "", fmt.Errorf("unsupported Linux architecture %q", arch)
	}
}

func expectedLinuxArtifacts0153(arch string) map[string]string {
	return map[string]string{
		"cli":              "neverlauncher-cli-linux-" + arch,
		"api":              "neverlauncher-api-linux-" + arch,
		"desktop-launcher": "neverlauncher-desktop-linux-" + arch,
		"guard":            "neverguard-linux-" + arch,
		"runtime":          "neverruntime-linux-" + arch,
	}
}

func expectedLinuxPackage0153(ver, arch string) (string, string) {
	return "neverlauncher-linux-" + arch + "-" + ver + ".tar.gz", "LINUX_PACKAGE_MANIFEST_" + strings.ToUpper(arch) + ".json"
}

func inspectLinuxELFBytes0153(data []byte) (linuxELFInfo0153, error) {
	if len(data) < 64 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return linuxELFInfo0153{}, errors.New("not an ELF file")
	}
	if data[4] != 2 {
		return linuxELFInfo0153{}, fmt.Errorf("unsupported ELF class %d; 64-bit required", data[4])
	}
	if data[5] != 1 {
		return linuxELFInfo0153{}, fmt.Errorf("unsupported ELF endianness %d; little-endian required", data[5])
	}
	elfType := binary.LittleEndian.Uint16(data[16:18])
	if elfType != 2 && elfType != 3 {
		return linuxELFInfo0153{}, fmt.Errorf("unsupported ELF type %d; executable/PIE required", elfType)
	}
	machine := binary.LittleEndian.Uint16(data[18:20])
	info := linuxELFInfo0153{Machine: machine, Type: elfType}
	switch machine {
	case 62:
		info.Architecture = "x64"
		info.MachineText = "EM_X86_64"
	case 183:
		info.Architecture = "arm64"
		info.MachineText = "EM_AARCH64"
	default:
		return linuxELFInfo0153{}, fmt.Errorf("unsupported ELF e_machine=%d", machine)
	}
	return info, nil
}

func inspectLinuxELFFile0153(path string) (linuxELFInfo0153, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return linuxELFInfo0153{}, err
	}
	return inspectLinuxELFBytes0153(data)
}

func readLinuxPackageManifest0153(dir, arch string) (LinuxPackageManifest0153, string, error) {
	_, manifestName := expectedLinuxPackage0153("ignored", arch)
	path := filepath.Join(dir, manifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return LinuxPackageManifest0153{}, "", err
	}
	var manifest LinuxPackageManifest0153
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return LinuxPackageManifest0153{}, "", fmt.Errorf("invalid %s: %w", manifestName, err)
	}
	sum, _, err := hashFile(path)
	if err != nil {
		return LinuxPackageManifest0153{}, "", err
	}
	return manifest, sum, nil
}

func verifyLinuxPackageManifest0153(dir, ver, arch string) (LinuxPackageManifest0153, string, error) {
	manifest, manifestHash, err := readLinuxPackageManifest0153(dir, arch)
	if err != nil {
		return LinuxPackageManifest0153{}, "", err
	}
	expectedPackage, _ := expectedLinuxPackage0153(ver, arch)
	_, expectedMachine, err := linuxTargetMetadata0153(arch)
	if err != nil {
		return LinuxPackageManifest0153{}, "", err
	}
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || manifest.ProductVersion != ver || manifest.Platform != "linux" || manifest.Architecture != arch || manifest.ELFMachine != expectedMachine || manifest.PackageFormat != "tar.gz" || manifest.PackageArtifact != expectedPackage {
		return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s package manifest identity/schema mismatch", arch)
	}
	expected := expectedLinuxArtifacts0153(arch)
	if len(manifest.Artifacts) != len(expected) {
		return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s package manifest must contain %d artifacts", arch, len(expected))
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		expectedName, ok := expected[artifact.Component]
		if !ok || artifact.Name != expectedName || artifact.Architecture != arch || artifact.ELFMachine != expectedMachine || artifact.Mode != "0755" {
			return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s package artifact identity mismatch: %s", arch, artifact.Name)
		}
		if seen[artifact.Component] {
			return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s duplicate package component %s", arch, artifact.Component)
		}
		seen[artifact.Component] = true
		if !strings.HasPrefix(artifact.PackagePath, "neverlauncher/") || strings.Contains(artifact.PackagePath, "..") {
			return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s unsafe package path %s", arch, artifact.PackagePath)
		}
		path, err := safeDeliveryArtifactPath(dir, artifact.Name)
		if err != nil {
			return LinuxPackageManifest0153{}, "", err
		}
		actualHash, actualSize, err := hashFile(path)
		if err != nil {
			return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s artifact %s: %w", arch, artifact.Name, err)
		}
		if artifact.Size <= 0 || artifact.Size != actualSize || !validDeliverySHA256(artifact.SHA256) || !strings.EqualFold(artifact.SHA256, actualHash) {
			return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s artifact %s checksum/size mismatch", arch, artifact.Name)
		}
		elf, err := inspectLinuxELFFile0153(path)
		if err != nil || elf.Architecture != arch || elf.MachineText != expectedMachine {
			return LinuxPackageManifest0153{}, "", fmt.Errorf("Linux %s artifact %s ELF validation failed: %v", arch, artifact.Name, err)
		}
	}
	return manifest, manifestHash, nil
}

func readTarGz0153(path string) (map[string][]byte, map[string]int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	modes := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		clean := filepath.ToSlash(filepath.Clean(hdr.Name))
		if strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(hdr.Name, "/") {
			return nil, nil, fmt.Errorf("unsafe tar entry %q", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, nil, fmt.Errorf("unsupported tar entry type for %s", hdr.Name)
		}
		if _, duplicate := files[clean]; duplicate {
			return nil, nil, fmt.Errorf("duplicate tar entry %s", clean)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 512*1024*1024+1))
		if err != nil {
			return nil, nil, err
		}
		if len(data) > 512*1024*1024 {
			return nil, nil, fmt.Errorf("tar entry too large: %s", clean)
		}
		files[clean] = data
		modes[clean] = hdr.Mode & 0o777
	}
	return files, modes, nil
}

func verifyLinuxPackageArchive0153(dir, ver, arch string, manifest LinuxPackageManifest0153, manifestHash string) (LinuxProductionPackage0153, error) {
	packageName, manifestName := expectedLinuxPackage0153(ver, arch)
	packagePath, err := safeDeliveryArtifactPath(dir, packageName)
	if err != nil {
		return LinuxProductionPackage0153{}, err
	}
	packageHash, packageSize, err := hashFile(packagePath)
	if err != nil {
		return LinuxProductionPackage0153{}, err
	}
	if packageSize <= 0 {
		return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package is empty", arch)
	}
	files, modes, err := readTarGz0153(packagePath)
	if err != nil {
		return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package read failed: %w", arch, err)
	}
	expectedFileCount := len(manifest.Artifacts) + 1
	if componentTransactionalUpdateRequired0157(ver) {
		expectedFileCount++
	}
	if len(files) != expectedFileCount {
		return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package contains unexpected file count", arch)
	}
	embeddedManifest, ok := files["neverlauncher/LINUX_PACKAGE_MANIFEST.json"]
	if !ok {
		return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package lacks embedded manifest", arch)
	}
	topLevelManifest, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return LinuxProductionPackage0153{}, err
	}
	if string(embeddedManifest) != string(topLevelManifest) || modes["neverlauncher/LINUX_PACKAGE_MANIFEST.json"] != 0o644 {
		return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s embedded manifest mismatch/mode", arch)
	}
	if componentTransactionalUpdateRequired0157(ver) {
		updateRaw, ok := files["neverlauncher/COMPONENT_UPDATE_MANIFEST.json"]
		if !ok || modes["neverlauncher/COMPONENT_UPDATE_MANIFEST.json"] != 0o644 {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package lacks component update manifest", arch)
		}
		var update componentUpdateManifest0157
		if err := json.Unmarshal(updateRaw, &update); err != nil {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s component update manifest invalid: %w", arch, err)
		}
		if update.SchemaVersion != "1.0" || update.Product != "NeverLauncher" || update.ProductVersion != ver || update.Platform != "linux" || update.Architecture != arch || update.Layout != "adjacent-files" || update.TrustMode != "sha256-delivery" || len(update.Components) != 3 {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s component update manifest identity mismatch", arch)
		}
		mainByComponent := map[string]LinuxPackageArtifact0153{}
		for _, row := range manifest.Artifacts {
			mainByComponent[row.Component] = row
		}
		aliases := map[string]string{"desktop": "desktop-launcher", "guard": "guard", "runtime": "runtime"}
		for _, row := range update.Components {
			mainName, ok := aliases[row.Component]
			main, exists := mainByComponent[mainName]
			if !ok || !exists || row.SourcePath != strings.TrimPrefix(main.PackagePath, "neverlauncher/") || row.TargetPath != row.SourcePath || row.Size != main.Size || !strings.EqualFold(row.SHA256, main.SHA256) || !row.Executable {
				return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s component update binding mismatch for %s", arch, row.Component)
			}
		}
	}
	for _, artifact := range manifest.Artifacts {
		data, ok := files[artifact.PackagePath]
		if !ok {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package missing %s", arch, artifact.PackagePath)
		}
		if modes[artifact.PackagePath] != 0o755 {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package executable mode mismatch for %s", arch, artifact.PackagePath)
		}
		sumBytes := sha256.Sum256(data)
		sum := fmt.Sprintf("%x", sumBytes)
		if int64(len(data)) != artifact.Size || !strings.EqualFold(sum, artifact.SHA256) {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package payload mismatch for %s", arch, artifact.PackagePath)
		}
		elf, err := inspectLinuxELFBytes0153(data)
		if err != nil || elf.Architecture != arch {
			return LinuxProductionPackage0153{}, fmt.Errorf("Linux %s package payload ELF mismatch for %s", arch, artifact.PackagePath)
		}
	}
	return LinuxProductionPackage0153{Name: packageName, SHA256: packageHash, Size: packageSize, Manifest: manifestName, ManifestSHA256: manifestHash}, nil
}

func buildLinuxProductionTarget0153(dir, ver, arch string) (LinuxProductionTarget0153, error) {
	manifest, manifestHash, err := verifyLinuxPackageManifest0153(dir, ver, arch)
	if err != nil {
		return LinuxProductionTarget0153{}, err
	}
	pkg, err := verifyLinuxPackageArchive0153(dir, ver, arch, manifest, manifestHash)
	if err != nil {
		return LinuxProductionTarget0153{}, err
	}
	return LinuxProductionTarget0153{Architecture: arch, ELFMachine: manifest.ELFMachine, Package: pkg, Artifacts: manifest.Artifacts}, nil
}

func writeLinuxProductionEvidence0153(dir, ver string) error {
	evidence := LinuxProductionEvidence0153{
		SchemaVersion:  "1.0",
		Product:        "NeverLauncher",
		ProductVersion: ver,
		Platform:       "linux",
		IntegrityMode:  "sha256+signed-release-bundle",
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	for _, arch := range []string{"x64", "arm64"} {
		target, err := buildLinuxProductionTarget0153(dir, ver, arch)
		if err != nil {
			return err
		}
		evidence.Targets = append(evidence.Targets, target)
	}
	if err := writeJSONFile(filepath.Join(dir, linuxProductionEvidenceFile0153), evidence); err != nil {
		return err
	}

	pairs := []map[string]any{}
	for _, target := range evidence.Targets {
		byComponent := map[string]LinuxPackageArtifact0153{}
		for _, artifact := range target.Artifacts {
			byComponent[artifact.Component] = artifact
		}
		pairs = append(pairs, map[string]any{
			"architecture":   target.Architecture,
			"guardSha256":    byComponent["guard"].SHA256,
			"launcherSha256": byComponent["desktop-launcher"].SHA256,
		})
	}
	allowlist := map[string]any{
		"schemaVersion": "3.0",
		"releases": map[string]any{
			ver: map[string]any{
				"protocolVersion": 4,
				"platforms": map[string]any{
					"linux": map[string]any{
						"signingMode": "release-ed25519-sha256",
						"artifacts":   pairs,
					},
				},
			},
		},
	}
	return writeJSONFile(filepath.Join(dir, linuxDeliveryAllowlistFile0153), allowlist)
}

func readLinuxProductionEvidence0153(dir string) (LinuxProductionEvidence0153, error) {
	raw, err := os.ReadFile(filepath.Join(dir, linuxProductionEvidenceFile0153))
	if err != nil {
		return LinuxProductionEvidence0153{}, err
	}
	var evidence LinuxProductionEvidence0153
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return LinuxProductionEvidence0153{}, fmt.Errorf("invalid %s: %w", linuxProductionEvidenceFile0153, err)
	}
	return evidence, nil
}

func verifyLinuxDeliveryAllowlist0153(dir, ver string, evidence LinuxProductionEvidence0153) error {
	raw, err := os.ReadFile(filepath.Join(dir, linuxDeliveryAllowlistFile0153))
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
				} `json:"artifacts"`
			} `json:"platforms"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	release, ok := doc.Releases[ver]
	if doc.SchemaVersion != "3.0" || !ok || release.ProtocolVersion != 4 {
		return errors.New("Linux delivery allowlist identity/schema mismatch")
	}
	linux, ok := release.Platforms["linux"]
	if !ok || linux.SigningMode != "release-ed25519-sha256" || len(linux.Artifacts) != 2 {
		return errors.New("Linux delivery allowlist platform metadata mismatch")
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
	for _, row := range linux.Artifacts {
		key := strings.ToLower(row.GuardSHA256 + ":" + row.LauncherSHA256)
		if row.Architecture == "" || !validDeliverySHA256(row.GuardSHA256) || !validDeliverySHA256(row.LauncherSHA256) || expected[row.Architecture] != key || seen[row.Architecture] {
			return errors.New("Linux delivery allowlist contains unexpected/duplicate artifact pair")
		}
		seen[row.Architecture] = true
	}
	if !seen["x64"] || !seen["arm64"] {
		return errors.New("Linux delivery allowlist must cover x64 and arm64")
	}
	return nil
}

func verifyLinuxProductionEvidence0153(dir, ver string, bindDelivery bool) error {
	evidence, err := readLinuxProductionEvidence0153(dir)
	if err != nil {
		return err
	}
	if evidence.SchemaVersion != "1.0" || evidence.Product != "NeverLauncher" || evidence.ProductVersion != ver || evidence.Platform != "linux" || evidence.IntegrityMode != "sha256+signed-release-bundle" {
		return errors.New("Linux production evidence identity/schema mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.GeneratedAt); err != nil {
		if _, fallbackErr := time.Parse(time.RFC3339, evidence.GeneratedAt); fallbackErr != nil {
			return errors.New("Linux production evidence generatedAt is invalid")
		}
	}
	if len(evidence.Targets) != 2 {
		return fmt.Errorf("Linux production evidence must contain exactly x64+arm64 targets, got %d", len(evidence.Targets))
	}
	var deliveryByName map[string]DeliveryArtifact
	if bindDelivery {
		delivery, err := readDeliveryManifest0151(dir)
		if err != nil {
			return fmt.Errorf("Linux production evidence requires delivery manifest: %w", err)
		}
		deliveryByName = map[string]DeliveryArtifact{}
		for _, artifact := range delivery.Artifacts {
			deliveryByName[artifact.Name] = artifact
		}
	}
	seen := map[string]bool{}
	for _, target := range evidence.Targets {
		if target.Architecture != "x64" && target.Architecture != "arm64" {
			return fmt.Errorf("unsupported Linux evidence architecture %s", target.Architecture)
		}
		if seen[target.Architecture] {
			return fmt.Errorf("duplicate Linux evidence target %s", target.Architecture)
		}
		seen[target.Architecture] = true
		actualTarget, err := buildLinuxProductionTarget0153(dir, ver, target.Architecture)
		if err != nil {
			return err
		}
		if target.ELFMachine != actualTarget.ELFMachine || target.Package != actualTarget.Package || len(target.Artifacts) != len(actualTarget.Artifacts) {
			return fmt.Errorf("Linux %s production evidence drift", target.Architecture)
		}
		expectedArtifacts := map[string]LinuxPackageArtifact0153{}
		for _, artifact := range actualTarget.Artifacts {
			expectedArtifacts[artifact.Component] = artifact
		}
		for _, artifact := range target.Artifacts {
			expected, ok := expectedArtifacts[artifact.Component]
			if !ok || artifact != expected {
				return fmt.Errorf("Linux %s evidence artifact mismatch: %s", target.Architecture, artifact.Name)
			}
			if bindDelivery {
				deliveryArtifact, ok := deliveryByName[artifact.Name]
				if !ok || deliveryArtifact.Platform != "linux" || deliveryArtifact.Architecture != target.Architecture || deliveryArtifact.Size != artifact.Size || !strings.EqualFold(deliveryArtifact.SHA256, artifact.SHA256) {
					return fmt.Errorf("Linux production artifact %s is not bound to DELIVERY_MANIFEST.json", artifact.Name)
				}
			}
		}
		if bindDelivery {
			for _, name := range []string{target.Package.Name, target.Package.Manifest} {
				artifact, ok := deliveryByName[name]
				if !ok {
					return fmt.Errorf("Linux production metadata/package %s is not bound to DELIVERY_MANIFEST.json", name)
				}
				if name == target.Package.Name && (artifact.Platform != "linux" || artifact.Architecture != target.Architecture || artifact.Size != target.Package.Size || !strings.EqualFold(artifact.SHA256, target.Package.SHA256)) {
					return fmt.Errorf("Linux package %s delivery binding mismatch", name)
				}
			}
		}
	}
	if !seen["x64"] || !seen["arm64"] {
		return errors.New("Linux production evidence must cover both x64 and arm64")
	}
	if err := verifyLinuxDeliveryAllowlist0153(dir, ver, evidence); err != nil {
		return fmt.Errorf("Linux delivery Guard allowlist: %w", err)
	}
	return nil
}

func linuxProductionArtifacts0153(ver string) []string {
	names := []string{linuxProductionEvidenceFile0153, linuxDeliveryAllowlistFile0153}
	for _, arch := range []string{"x64", "arm64"} {
		for _, name := range expectedLinuxArtifacts0153(arch) {
			names = append(names, name)
		}
		pkg, manifest := expectedLinuxPackage0153(ver, arch)
		names = append(names, pkg, manifest)
	}
	sort.Strings(names)
	return names
}
