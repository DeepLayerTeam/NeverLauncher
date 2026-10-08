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
	HashBindingMode      string                     `json:"hashBindingMode"`
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
		return "", 0, "", fmt.Errorf("неподдерживаемый macOS архитектура %q", arch)
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

func expectedMacOSBundlePaths0154() map[string]string {
	return map[string]string{
		"cli":              "NeverLauncher.app/Contents/Helpers/neverlauncher-cli",
		"desktop-launcher": "NeverLauncher.app/Contents/MacOS/neverlauncher-desktop",
		"guard":            "NeverLauncher.app/Contents/Helpers/neverguard",
		"runtime":          "NeverLauncher.app/Contents/Helpers/neverruntime",
	}
}

func expectedMacOSPackage0154(ver, arch string) (string, string) {
	return "neverlauncher-desktop-" + ver + "-macos-" + arch + ".zip", "MACOS_PACKAGE_MANIFEST_" + strings.ToUpper(arch) + ".json"
}

func inspectMacOSMachOBytes0154(data []byte) (macOSMachOInfo0154, error) {
	if len(data) < 32 {
		return macOSMachOInfo0154{}, errors.New("Mach-O header является truncated")
	}
	// 64-бит little-endian Mach-O magic (MH_MAGIC_64) appears как cf fa ed fe на диск.
	if !bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
		return macOSMachOInfo0154{}, fmt.Errorf("неподдерживаемый Mach-O magic %x; облегчённый 64-бит little-endian образ обязательный", data[:4])
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
		return macOSMachOInfo0154{}, fmt.Errorf("неподдерживаемый Mach-O cputype=0x%08X", cpuType)
	}
	ncmds := int(binary.LittleEndian.Uint32(data[16:20]))
	sizeofcmds := int(binary.LittleEndian.Uint32(data[20:24]))
	if ncmds <= 0 || sizeofcmds <= 0 || 32+sizeofcmds > len(data) {
		return macOSMachOInfo0154{}, errors.New("недопустимый Mach-O загрузка-команда таблица")
	}
	offset := 32
	for i := 0; i < ncmds; i++ {
		if offset+8 > len(data) || offset+8 > 32+sizeofcmds {
			return macOSMachOInfo0154{}, errors.New("truncated Mach-O загрузка команда")
		}
		cmd := binary.LittleEndian.Uint32(data[offset : offset+4])
		cmdSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if cmdSize < 8 || offset+cmdSize > len(data) || offset+cmdSize > 32+sizeofcmds {
			return macOSMachOInfo0154{}, errors.New("недопустимый Mach-O загрузка команда размер")
		}
		if cmd == 0x1d { // LC_CODE_SIGNATURE
			if cmdSize < 16 {
				return macOSMachOInfo0154{}, errors.New("LC_CODE_SIGNATURE является truncated")
			}
			dataOffset := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
			dataSize := int(binary.LittleEndian.Uint32(data[offset+12 : offset+16]))
			if dataOffset <= 0 || dataSize <= 0 || dataOffset+dataSize > len(data) {
				return macOSMachOInfo0154{}, errors.New("LC_CODE_SIGNATURE точки вне Mach-O файл")
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
		return MacOSPackageManifest0154{}, "", fmt.Errorf("недопустимый %s: %w", manifestName, err)
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
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || manifest.ProductVersion != ver || manifest.Platform != "macos" || manifest.Architecture != arch || manifest.CPUType != cpuText || manifest.RustTarget != rustTarget || manifest.PackageFormat != "zip" || manifest.PackageArtifact != expectedPackage || manifest.BundleIdentifier != "ru.skif4er.neverlauncher" || strings.TrimSpace(manifest.MinimumSystemVersion) == "" || manifest.HashBindingMode != "final-artifact-sha256" {
		return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s пакет манифест identity/schema несоответствие", arch)
	}
	expected := expectedMacOSArtifacts0154(arch)
	expectedBundlePaths := expectedMacOSBundlePaths0154()
	if len(manifest.Artifacts) != len(expected) {
		return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s пакет манифест должен contain %d артефакты", arch, len(expected))
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		expectedName, ok := expected[artifact.Component]
		expectedBundlePath := expectedBundlePaths[artifact.Component]
		if !ok || artifact.Name != expectedName || artifact.BundlePath != expectedBundlePath || artifact.Architecture != arch || artifact.CPUType != cpuText || strings.Contains(artifact.BundlePath, "..") {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s пакет артефакт идентичность несоответствие: %s", arch, artifact.Name)
		}
		if seen[artifact.Component] {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s дубликат пакет компонент %s", arch, artifact.Component)
		}
		seen[artifact.Component] = true
		path, err := safeDeliveryArtifactPath(dir, artifact.Name)
		if err != nil {
			return MacOSPackageManifest0154{}, "", err
		}
		actualHash, actualSize, err := hashFile(path)
		if err != nil {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s артефакт %s: %w", arch, artifact.Name, err)
		}
		if artifact.Size <= 0 || artifact.Size != actualSize || !validDeliverySHA256(artifact.SHA256) || !strings.EqualFold(artifact.SHA256, actualHash) {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s артефакт %s checksum/size несоответствие", arch, artifact.Name)
		}
		macho, err := inspectMacOSMachOFile0154(path)
		if err != nil || macho.Architecture != arch || macho.CPUTypeText != cpuText || !macho.HasCodeSignature {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s артефакт %s Mach-O/code-signature валидация ошибка: %v", arch, artifact.Name, err)
		}
		if !artifact.CodeSigned || !artifact.HardenedRuntime {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s артефакт %s lacks подписанный+hardened-свидетельство реального запуска", arch, artifact.Name)
		}
		if requireSigned {
			if !macOSTeamIDRE0154.MatchString(artifact.TeamID) || !strings.EqualFold(artifact.TeamID, expectedTeamID) {
				return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s артефакт %s Команда ID несоответствие", arch, artifact.Name)
			}
		} else if strings.TrimSpace(artifact.TeamID) == "" {
			return MacOSPackageManifest0154{}, "", fmt.Errorf("macOS %s артефакт %s Команда ID/mode маркер отсутствующий", arch, artifact.Name)
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
			return nil, fmt.Errorf("unsafe macOS пакет zip запись %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if _, duplicate := entries[name]; duplicate {
			return nil, fmt.Errorf("дубликат macOS пакет zip запись %s", name)
		}
		if file.UncompressedSize64 > 512*1024*1024 {
			return nil, fmt.Errorf("macOS пакет zip запись слишком large: %s", name)
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
			return nil, fmt.Errorf("macOS пакет zip запись слишком large: %s", name)
		}
		entries[name] = data
	}
	return entries, nil
}

func verifyEmbeddedMacOSPackageManifest0154(raw []byte, external MacOSPackageManifest0154, arch string) (MacOSPackageManifest0154, error) {
	var embedded MacOSPackageManifest0154
	if err := json.Unmarshal(raw, &embedded); err != nil {
		return MacOSPackageManifest0154{}, fmt.Errorf("macOS %s встроенный пакет манифест недопустимый: %w", arch, err)
	}
	if embedded.SchemaVersion != external.SchemaVersion ||
		embedded.Product != external.Product ||
		embedded.ProductVersion != external.ProductVersion ||
		embedded.Platform != external.Platform ||
		embedded.Architecture != external.Architecture ||
		embedded.CPUType != external.CPUType ||
		embedded.RustTarget != external.RustTarget ||
		embedded.PackageFormat != external.PackageFormat ||
		embedded.PackageArtifact != external.PackageArtifact ||
		embedded.BundleIdentifier != external.BundleIdentifier ||
		embedded.MinimumSystemVersion != external.MinimumSystemVersion ||
		embedded.HashBindingMode != "codesign+external-release-policy" ||
		len(embedded.Artifacts) != len(external.Artifacts) {
		return MacOSPackageManifest0154{}, fmt.Errorf("macOS %s встроенный пакет манифест identity/schema несоответствие", arch)
	}

	externalByComponent := make(map[string]MacOSPackageArtifact0154, len(external.Artifacts))
	for _, artifact := range external.Artifacts {
		externalByComponent[artifact.Component] = artifact
	}
	seen := make(map[string]bool, len(embedded.Artifacts))
	for _, artifact := range embedded.Artifacts {
		externalArtifact, ok := externalByComponent[artifact.Component]
		if !ok || seen[artifact.Component] ||
			artifact.Name != externalArtifact.Name ||
			artifact.BundlePath != externalArtifact.BundlePath ||
			artifact.Architecture != externalArtifact.Architecture ||
			artifact.CPUType != externalArtifact.CPUType ||
			artifact.CodeSigned != externalArtifact.CodeSigned ||
			artifact.HardenedRuntime != externalArtifact.HardenedRuntime ||
			artifact.TeamID != externalArtifact.TeamID ||
			artifact.Size <= 0 || !validDeliverySHA256(artifact.SHA256) {
			return MacOSPackageManifest0154{}, fmt.Errorf("macOS %s встроенный пакет артефакт идентичность несоответствие для %s", arch, artifact.Component)
		}
		seen[artifact.Component] = true
	}
	return embedded, nil
}

func verifyMacOSPackageArchive0154(dir, ver, arch string, manifest MacOSPackageManifest0154, manifestHash string, evidencePackage MacOSNotarizedPackage0154) error {
	packageName, manifestName := expectedMacOSPackage0154(ver, arch)
	if evidencePackage.Name != packageName || evidencePackage.Manifest != manifestName || !strings.EqualFold(evidencePackage.ManifestSHA256, manifestHash) {
		return fmt.Errorf("macOS %s пакет свидетельство идентичность несоответствие", arch)
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
		return fmt.Errorf("macOS %s пакет checksum/size несоответствие", arch)
	}
	entries, err := readZipEntries0154(packagePath)
	if err != nil {
		return fmt.Errorf("macOS %s пакет zip: %w", arch, err)
	}
	for _, artifact := range manifest.Artifacts {
		data, ok := entries[artifact.BundlePath]
		if !ok {
			return fmt.Errorf("macOS %s пакет отсутствующий %s", arch, artifact.BundlePath)
		}
		sum, size := hashBytes0154(data)
		if size != artifact.Size || !strings.EqualFold(sum, artifact.SHA256) {
			return fmt.Errorf("macOS %s пакет полезная нагрузка несоответствие для %s", arch, artifact.BundlePath)
		}
		macho, err := inspectMacOSMachOBytes0154(data)
		if err != nil || macho.Architecture != arch || !macho.HasCodeSignature {
			return fmt.Errorf("macOS %s пакет полезная нагрузка Mach-O несоответствие для %s", arch, artifact.BundlePath)
		}
	}
	manifestPath := "NeverLauncher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json"
	embeddedRaw, ok := entries[manifestPath]
	if !ok {
		return fmt.Errorf("macOS %s пакет отсутствующий встроенный манифест", arch)
	}
	embeddedManifest, err := verifyEmbeddedMacOSPackageManifest0154(embeddedRaw, manifest, arch)
	if err != nil {
		return err
	}
	if componentTransactionalUpdateRequired0157(ver) {
		updatePath := "NeverLauncher.app/Contents/Resources/" + componentUpdateManifestFile0157
		updateRaw, ok := entries[updatePath]
		if !ok {
			return fmt.Errorf("macOS %s пакет отсутствующий %s", arch, updatePath)
		}
		var update componentUpdateManifest0157
		if err := json.Unmarshal(updateRaw, &update); err != nil {
			return fmt.Errorf("macOS %s компонент обновление манифест недопустимый: %w", arch, err)
		}
		expectedTrust := "adhoc-development"
		if evidencePackage.NotaryStatus == "Accepted" && evidencePackage.Stapled && evidencePackage.StaplerValidated && evidencePackage.GatekeeperAccepted {
			expectedTrust = "developer-id-notarized"
		}
		if update.SchemaVersion != "1.0" || update.Product != "NeverLauncher" || update.ProductVersion != ver || update.Platform != "macos" || update.Architecture != arch || update.Layout != "macos-app-bundle" || update.BundleName != "NeverLauncher.app" || update.TrustMode != expectedTrust || len(update.Components) != 3 {
			return fmt.Errorf("macOS %s компонент обновление манифест идентичность несоответствие", arch)
		}
		byComponent := map[string]MacOSPackageArtifact0154{}
		for _, row := range embeddedManifest.Artifacts {
			byComponent[row.Component] = row
		}
		aliases := map[string]string{"desktop": "desktop-launcher", "guard": "guard", "runtime": "runtime"}
		expectedPath := map[string]string{"desktop": "Contents/MacOS/neverlauncher-desktop", "guard": "Contents/Helpers/neverguard", "runtime": "Contents/Helpers/neverruntime"}
		seen := map[string]bool{}
		for _, row := range update.Components {
			sourceComponent, known := aliases[row.Component]
			artifact, exists := byComponent[sourceComponent]
			if !known || !exists || seen[row.Component] || row.SourcePath != expectedPath[row.Component] || row.TargetPath != row.SourcePath || !row.Executable || row.Size != artifact.Size || !strings.EqualFold(row.SHA256, artifact.SHA256) || artifact.BundlePath != "NeverLauncher.app/"+row.SourcePath {
				return fmt.Errorf("macOS %s компонент обновление привязка несоответствие для %s", arch, row.Component)
			}
			seen[row.Component] = true
		}
		if !seen["desktop"] || !seen["guard"] || !seen["runtime"] {
			return fmt.Errorf("macOS %s компонент обновление манифест должен привязывать Desktop/Guard/Runtime", arch)
		}
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
		return MacOSNotarizationEvidence0154{}, fmt.Errorf("недопустимый %s: %w", macOSNotarizationEvidenceFile0154, err)
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
		return errors.New("macOS доставка список разрешений identity/schema несоответствие")
	}
	policy, ok := release.Platforms["macos"]
	expectedMode := evidence.SigningMode
	if !ok || policy.SigningMode != expectedMode || len(policy.Artifacts) != 2 {
		return errors.New("macOS доставка список разрешений платформа метаданные несоответствие")
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
			return errors.New("macOS доставка список разрешений содержит unexpected/duplicate артефакт пара")
		}
		seen[row.Architecture] = true
	}
	if !seen["x64"] || !seen["arm64"] {
		return errors.New("macOS доставка список разрешений должен cover x64 и arm64")
	}
	return nil
}

func verifyMacOSNativePackage0154(packagePath, expectedTeamID string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		return errors.New("codesign является обязательный для нативный macOS проверка")
	}
	xcrun, err := exec.LookPath("xcrun")
	if err != nil {
		return errors.New("xcrun является обязательный для stapler проверка")
	}
	ditto, err := exec.LookPath("ditto")
	if err != nil {
		return errors.New("ditto является обязательный к preserve notarization билет метаданные")
	}
	spctl := "/usr/sbin/spctl"
	if _, err := os.Stat(spctl); err != nil {
		return errors.New("spctl является обязательный для Gatekeeper проверка")
	}
	tmp, err := os.MkdirTemp("", "neverlauncher-macos-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// Кроссплатформенный проверка имеет уже проверен каждый ZIP путь и его
	// встроенный байты. Нативный проверка намеренно использует ditto так AppleDouble
	// данные, extended attributes и stapled notarization билет переживать
	// извлечение до stapler/Gatekeeper inspect.app комплект.
	if output, err := exec.Command(ditto, "-x", "-k", packagePath, tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("ditto пакет извлечение ошибка: %w: %s", err, strings.TrimSpace(string(output)))
	}
	app := filepath.Join(tmp, "NeverLauncher.app")
	if output, err := exec.Command(codesign, "--verify", "--deep", "--strict", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("codesign проверять ошибка: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command(xcrun, "stapler", "validate", app).CombinedOutput(); err != nil {
		return fmt.Errorf("stapler проверять ошибка: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command(spctl, "--assess", "--type", "execute", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("Gatekeeper assessment ошибка: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command(codesign, "-dv", "--verbose=4", app).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign отображать ошибка: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), "TeamIdentifier="+expectedTeamID) || !strings.Contains(string(output), "runtime") {
		return errors.New("нативный macOS пакет Команда ID/Hardened Среда выполнения несоответствие")
	}
	return nil
}

func verifyMacOSNotarizationEvidence0154(dir, ver string, requireNotarized bool) error {
	evidence, err := readMacOSNotarizationEvidence0154(dir)
	if err != nil {
		return err
	}
	if evidence.SchemaVersion != "1.0" || evidence.Product != "NeverLauncher" || evidence.ProductVersion != ver || evidence.Platform != "macos" {
		return errors.New("macOS notarization свидетельство identity/schema несоответствие")
	}
	production := evidence.SigningMode == "developer-id-notarized"
	development := evidence.SigningMode == "adhoc-development"
	if !production && !development {
		return fmt.Errorf("неподдерживаемый macOS подписание режим %q", evidence.SigningMode)
	}
	if requireNotarized && !production {
		return errors.New("рабочий публикация требует Разработчик ID + Apple notarization для macOS x64 и ARM64")
	}
	if production {
		if !macOSTeamIDRE0154.MatchString(evidence.TeamID) {
			return errors.New("рабочий macOS свидетельство содержит недопустимый Команда ID")
		}
	} else if evidence.TeamID != "ADHOC-CI" {
		return errors.New("специальный macOS свидетельство должен использовать Команда ID маркер ADHOC-CI")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.GeneratedAt); err != nil {
		if _, fallbackErr := time.Parse(time.RFC3339, evidence.GeneratedAt); fallbackErr != nil {
			return errors.New("macOS notarization свидетельство generatedAt является недопустимый")
		}
	}
	if len(evidence.Targets) != 2 {
		return fmt.Errorf("macOS notarization свидетельство должен contain точно x64+arm64 цели, получил %d", len(evidence.Targets))
	}
	delivery, err := readDeliveryManifest0151(dir)
	if err != nil {
		return fmt.Errorf("macOS notarization свидетельство требует доставка манифест: %w", err)
	}
	deliveryByName := map[string]DeliveryArtifact{}
	for _, artifact := range delivery.Artifacts {
		deliveryByName[artifact.Name] = artifact
	}
	seen := map[string]bool{}
	for _, target := range evidence.Targets {
		if target.Architecture != "x64" && target.Architecture != "arm64" {
			return fmt.Errorf("неподдерживаемый macOS свидетельство архитектура %s", target.Architecture)
		}
		if seen[target.Architecture] {
			return fmt.Errorf("дубликат macOS свидетельство цель %s", target.Architecture)
		}
		seen[target.Architecture] = true
		rustTarget, _, cpuText, err := macOSTargetMetadata0154(target.Architecture)
		if err != nil {
			return err
		}
		if target.RustTarget != rustTarget || target.CPUType != cpuText {
			return fmt.Errorf("macOS %s цель метаданные несоответствие", target.Architecture)
		}
		manifest, manifestHash, err := verifyMacOSPackageManifest0154(dir, ver, target.Architecture, production, evidence.TeamID)
		if err != nil {
			return err
		}
		if len(target.Artifacts) != len(manifest.Artifacts) {
			return fmt.Errorf("macOS %s свидетельство артефакт счётчик несоответствие", target.Architecture)
		}
		expectedArtifacts := map[string]MacOSPackageArtifact0154{}
		for _, artifact := range manifest.Artifacts {
			expectedArtifacts[artifact.Component] = artifact
		}
		for _, artifact := range target.Artifacts {
			expected, ok := expectedArtifacts[artifact.Component]
			if !ok || artifact != expected {
				return fmt.Errorf("macOS %s свидетельство артефакт несоответствие: %s", target.Architecture, artifact.Name)
			}
			deliveryArtifact, ok := deliveryByName[artifact.Name]
			if !ok || deliveryArtifact.Platform != "macos" || deliveryArtifact.Architecture != target.Architecture || deliveryArtifact.Size != artifact.Size || !strings.EqualFold(deliveryArtifact.SHA256, artifact.SHA256) {
				return fmt.Errorf("macOS рабочий артефакт %s является не привязанный к DELIVERY_MANIFEST.JSON", artifact.Name)
			}
		}
		if err := verifyMacOSPackageArchive0154(dir, ver, target.Architecture, manifest, manifestHash, target.Package); err != nil {
			return err
		}
		packageDelivery, ok := deliveryByName[target.Package.Name]
		if !ok || packageDelivery.Platform != "macos" || packageDelivery.Architecture != target.Architecture || packageDelivery.Size != target.Package.Size || !strings.EqualFold(packageDelivery.SHA256, target.Package.SHA256) {
			return fmt.Errorf("macOS пакет %s доставка привязка несоответствие", target.Package.Name)
		}
		manifestDelivery, ok := deliveryByName[target.Package.Manifest]
		if !ok {
			return fmt.Errorf("macOS пакет манифест %s является не привязанный к DELIVERY_MANIFEST.JSON", target.Package.Manifest)
		}
		_ = manifestDelivery
		if production {
			if !macOSNotaryIDRE0154.MatchString(target.Package.NotarySubmissionID) || target.Package.NotaryStatus != "Accepted" || !target.Package.Stapled || !target.Package.StaplerValidated || !target.Package.GatekeeperAccepted || !target.Package.BundleCodeSignVerified {
				return fmt.Errorf("macOS %s пакет lacks принят notarization/stapling/Gatekeeper свидетельство", target.Architecture)
			}
			if err := verifyMacOSNativePackage0154(filepath.Join(dir, target.Package.Name), evidence.TeamID); err != nil {
				return fmt.Errorf("macOS %s нативный проверка: %w", target.Architecture, err)
			}
		} else {
			if target.Package.NotarySubmissionID != "" || target.Package.NotaryStatus != "not-requested" || target.Package.Stapled || target.Package.StaplerValidated || target.Package.GatekeeperAccepted || !target.Package.BundleCodeSignVerified {
				return fmt.Errorf("специальный macOS %s свидетельство overclaims notarization состояние", target.Architecture)
			}
		}
	}
	if !seen["x64"] || !seen["arm64"] {
		return errors.New("macOS notarization свидетельство должен cover оба x64 и arm64")
	}
	if err := verifyMacOSDeliveryAllowlist0154(dir, ver, evidence, production); err != nil {
		return fmt.Errorf("macOS доставка Защита список разрешений: %w", err)
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
