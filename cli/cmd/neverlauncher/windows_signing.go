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

const windowsSigningEvidenceFile0152 = "WINDOWS_SIGNING_EVIDENCE.json"
const windowsDeliveryAllowlistFile0152 = "GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json"

var windowsCertThumbprintRE0152 = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)

type WindowsSigner0152 struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	Thumbprint   string `json:"thumbprint"`
	SerialNumber string `json:"serialNumber"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
}

type WindowsSignedArtifact0152 struct {
	Name                      string `json:"name"`
	Component                 string `json:"component"`
	Architecture              string `json:"architecture"`
	PEMachine                 string `json:"peMachine"`
	SHA256                    string `json:"sha256"`
	Size                      int64  `json:"size"`
	AuthenticodeStatus        string `json:"authenticodeStatus"`
	Timestamped               bool   `json:"timestamped"`
	SigntoolVerified          bool   `json:"signtoolVerified"`
	SignerThumbprint          string `json:"signerThumbprint,omitempty"`
	TimestampSignerThumbprint string `json:"timestampSignerThumbprint,omitempty"`
}

type WindowsSignedPackage0152 struct {
	Name           string `json:"name"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	Manifest       string `json:"manifest"`
	ManifestSHA256 string `json:"manifestSha256"`
}

type WindowsSigningTarget0152 struct {
	Architecture string                      `json:"architecture"`
	RustTarget   string                      `json:"rustTarget"`
	PEMachine    string                      `json:"peMachine"`
	Package      WindowsSignedPackage0152    `json:"package"`
	Artifacts    []WindowsSignedArtifact0152 `json:"artifacts"`
}

type WindowsSigningEvidence0152 struct {
	SchemaVersion   string                     `json:"schemaVersion"`
	Product         string                     `json:"product"`
	ProductVersion  string                     `json:"productVersion"`
	Platform        string                     `json:"platform"`
	SigningMode     string                     `json:"signingMode"`
	TimestampServer string                     `json:"timestampServer,omitempty"`
	GeneratedAt     string                     `json:"generatedAt"`
	Signer          *WindowsSigner0152         `json:"signer,omitempty"`
	Targets         []WindowsSigningTarget0152 `json:"targets"`
}

type windowsPEInfo0152 struct {
	Architecture string
	Machine      uint16
	MachineText  string
	HasSignature bool
}

func windowsSigningRequired0152(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 2)))
}

func neverguardSensorRequired0182(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 18 || (minor == 18 && patch >= 2)))
}

func windowsTargetMetadata0152(arch string) (rustTarget string, machine uint16, machineText string, err error) {
	switch arch {
	case "x64":
		return "x86_64-pc-windows-msvc", 0x8664, "0x8664", nil
	case "arm64":
		return "aarch64-pc-windows-msvc", 0xaa64, "0xAA64", nil
	default:
		return "", 0, "", fmt.Errorf("неподдерживаемый Windows архитектура %q", arch)
	}
}

func expectedWindowsSignedArtifacts0152(arch string) map[string]string {
	return map[string]string{
		"cli":              "neverlauncher-cli-windows-" + arch + ".exe",
		"desktop-launcher": "neverlauncher-desktop-windows-" + arch + ".exe",
		"guard":            "neverguard-windows-" + arch + ".exe",
	}
}

func expectedWindowsSignedArtifactsForVersion0157(ver, arch string) map[string]string {
	artifacts := expectedWindowsSignedArtifacts0152(arch)
	if componentTransactionalUpdateRequired0157(ver) {
		artifacts["runtime"] = "neverruntime-windows-" + arch + ".exe"
	}
	if neverguardSensorRequired0182(ver) {
		artifacts["sensor"] = "neverguard-sensor-windows-" + arch + ".dll"
	}
	return artifacts
}

func expectedWindowsPackage0152(ver, arch string) (string, string) {
	manifest := "WINDOWS_PACKAGE_MANIFEST_" + strings.ToUpper(arch) + ".json"
	return "neverlauncher-desktop-" + ver + "-windows-" + arch + ".zip", manifest
}

func inspectWindowsPEBytes0152(data []byte) (windowsPEInfo0152, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return windowsPEInfo0152{}, errors.New("не PE файл: DOS header является отсутствующий")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if peOffset < 0x40 || peOffset+24 > len(data) {
		return windowsPEInfo0152{}, errors.New("недопустимый PE header offset")
	}
	if !bytes.Equal(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return windowsPEInfo0152{}, errors.New("недопустимый PE подпись")
	}
	machine := binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6])
	arch := ""
	machineText := fmt.Sprintf("0x%04X", machine)
	switch machine {
	case 0x8664:
		arch = "x64"
	case 0xaa64:
		arch = "arm64"
	default:
		return windowsPEInfo0152{}, fmt.Errorf("неподдерживаемый PE machine %s", machineText)
	}

	optionalSize := int(binary.LittleEndian.Uint16(data[peOffset+20 : peOffset+22]))
	optionalOffset := peOffset + 24
	if optionalSize < 2 || optionalOffset+optionalSize > len(data) {
		return windowsPEInfo0152{}, errors.New("недопустимый PE необязательный header")
	}
	magic := binary.LittleEndian.Uint16(data[optionalOffset : optionalOffset+2])
	dataDirectoryOffset := 0
	switch magic {
	case 0x20b: // PE32+
		dataDirectoryOffset = optionalOffset + 112
	case 0x10b: // PE32
		dataDirectoryOffset = optionalOffset + 96
	default:
		return windowsPEInfo0152{}, fmt.Errorf("неподдерживаемый PE необязательный header magic 0x%04X", magic)
	}
	securityEntry := dataDirectoryOffset + 4*8
	if securityEntry+8 > optionalOffset+optionalSize || securityEntry+8 > len(data) {
		return windowsPEInfo0152{}, errors.New("PE безопасность каталог является вне необязательный header")
	}
	certOffset := int(binary.LittleEndian.Uint32(data[securityEntry : securityEntry+4]))
	certSize := int(binary.LittleEndian.Uint32(data[securityEntry+4 : securityEntry+8]))
	hasSignature := false
	if certOffset != 0 || certSize != 0 {
		if certOffset <= 0 || certSize < 8 || certOffset+certSize > len(data) {
			return windowsPEInfo0152{}, errors.New("недопустимый PE сертификат таблица привязанный")
		}
		certLength := int(binary.LittleEndian.Uint32(data[certOffset : certOffset+4]))
		certType := binary.LittleEndian.Uint16(data[certOffset+6 : certOffset+8])
		if certLength < 8 || certLength > certSize || certOffset+certLength > len(data) {
			return windowsPEInfo0152{}, errors.New("недопустимый WIN_CERTIFICATE length")
		}
		if certType != 0x0002 {
			return windowsPEInfo0152{}, fmt.Errorf("неподдерживаемый WIN_CERTIFICATE type 0x%04X", certType)
		}
		hasSignature = true
	}
	return windowsPEInfo0152{Architecture: arch, Machine: machine, MachineText: machineText, HasSignature: hasSignature}, nil
}

func inspectWindowsPEFile0152(path string) (windowsPEInfo0152, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return windowsPEInfo0152{}, err
	}
	return inspectWindowsPEBytes0152(data)
}

func findSignTool0152() (string, error) {
	if path, err := exec.LookPath("signtool.exe"); err == nil {
		return path, nil
	}
	programFilesX86 := strings.TrimSpace(os.Getenv("ProgramFiles(x86)"))
	if programFilesX86 == "" {
		return "", errors.New("ProgramFiles(x86) является недоступный пока locating signtool.EXE")
	}
	candidates, err := filepath.Glob(filepath.Join(programFilesX86, "Windows Kits", "10", "bin", "*", "x64", "signtool.exe"))
	if err != nil {
		return "", err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(candidates)))
	for _, candidate := range candidates {
		if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("signtool.EXE был не found в PATH или Windows SDK")
}

func verifyWindowsAuthenticodeNative0152(path, signerThumbprint, timestampThumbprint string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	signTool, err := findSignTool0152()
	if err != nil {
		return err
	}
	cmd := exec.Command(signTool, "verify", "/pa", "/all", "/v", path)
	if output, runErr := cmd.CombinedOutput(); runErr != nil {
		return fmt.Errorf("signtool проверять ошибка для %s: %w: %s", filepath.Base(path), runErr, strings.TrimSpace(string(output)))
	}

	powerShell, err := exec.LookPath("powershell.exe")
	if err != nil {
		return errors.New("powershell.EXE является обязательный для Authenticode метка времени проверка")
	}
	const script = `$s = Get-AuthenticodeSignature -LiteralPath $env:NL_AUTHENTICODE_PATH; if ($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate -or $null -eq $s.TimeStamperCertificate) { exit 23 }; [Console]::Out.Write($s.SignerCertificate.Thumbprint + '|' + $s.TimeStamperCertificate.Thumbprint)`
	ps := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command", script)
	ps.Env = append(os.Environ(), "NL_AUTHENTICODE_PATH="+path)
	out, runErr := ps.CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("Получить-AuthenticodeSignature ошибка для %s: %w: %s", filepath.Base(path), runErr, strings.TrimSpace(string(out)))
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), signerThumbprint) || !strings.EqualFold(strings.TrimSpace(parts[1]), timestampThumbprint) {
		return fmt.Errorf("нативный Authenticode signer/timestamp несоответствие для %s", filepath.Base(path))
	}
	return nil
}

func readWindowsSigningEvidence0152(dir string) (WindowsSigningEvidence0152, error) {
	raw, err := os.ReadFile(filepath.Join(dir, windowsSigningEvidenceFile0152))
	if err != nil {
		return WindowsSigningEvidence0152{}, err
	}
	var evidence WindowsSigningEvidence0152
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return WindowsSigningEvidence0152{}, fmt.Errorf("недопустимый %s: %w", windowsSigningEvidenceFile0152, err)
	}
	return evidence, nil
}

func verifyWindowsPackage0152(dir, ver, arch string, target WindowsSigningTarget0152, artifactByComponent map[string]WindowsSignedArtifact0152, requireSigned bool) error {
	expectedPackage, expectedManifest := expectedWindowsPackage0152(ver, arch)
	if target.Package.Name != expectedPackage || target.Package.Manifest != expectedManifest {
		return fmt.Errorf("Windows %s пакет идентичность несоответствие", arch)
	}
	packagePath, err := safeDeliveryArtifactPath(dir, target.Package.Name)
	if err != nil {
		return err
	}
	actualPackageHash, actualPackageSize, err := hashFile(packagePath)
	if err != nil {
		return fmt.Errorf("Windows %s пакет: %w", arch, err)
	}
	if target.Package.Size != actualPackageSize || !strings.EqualFold(target.Package.SHA256, actualPackageHash) {
		return fmt.Errorf("Windows %s пакет checksum/size несоответствие", arch)
	}
	manifestPath, err := safeDeliveryArtifactPath(dir, target.Package.Manifest)
	if err != nil {
		return err
	}
	actualManifestHash, _, err := hashFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Windows %s пакет манифест: %w", arch, err)
	}
	if !strings.EqualFold(target.Package.ManifestSHA256, actualManifestHash) {
		return fmt.Errorf("Windows %s пакет манифест контрольная сумма несоответствие", arch)
	}
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest struct {
		SchemaVersion        string `json:"schemaVersion"`
		ProductVersion       string `json:"productVersion"`
		Platform             string `json:"platform"`
		Architecture         string `json:"architecture"`
		AuthenticodeRequired bool   `json:"authenticodeRequired"`
		SigningMode          string `json:"signingMode"`
		Artifacts            []struct {
			Name         string `json:"name"`
			Component    string `json:"component"`
			Architecture string `json:"architecture"`
			SHA256       string `json:"sha256"`
			Size         int64  `json:"size"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return fmt.Errorf("Windows %s пакет манифест недопустимый: %w", arch, err)
	}
	if manifest.SchemaVersion != "1.1" || manifest.ProductVersion != ver || manifest.Platform != "windows-"+arch || manifest.Architecture != arch {
		return fmt.Errorf("Windows %s пакет манифест идентичность несоответствие", arch)
	}
	if requireSigned && (!manifest.AuthenticodeRequired || manifest.SigningMode != "authenticode-rfc3161") {
		return fmt.Errorf("Windows %s пакет манифест делает не требовать рабочий Authenticode", arch)
	}

	manifestRows := map[string]struct {
		SHA256 string
		Size   int64
	}{}
	for _, row := range manifest.Artifacts {
		if row.Name == "" || row.Architecture != arch {
			return fmt.Errorf("Windows %s пакет манифест содержит недопустимый артефакт метаданные", arch)
		}
		if _, exists := manifestRows[row.Component]; exists {
			return fmt.Errorf("Windows %s пакет манифест содержит дубликат компонент %s", arch, row.Component)
		}
		manifestRows[row.Component] = struct {
			SHA256 string
			Size   int64
		}{row.SHA256, row.Size}
	}
	packageComponents := []string{"desktop-launcher", "guard"}
	if componentTransactionalUpdateRequired0157(ver) {
		packageComponents = []string{"cli", "desktop-launcher", "guard", "runtime"}
	}
	if neverguardSensorRequired0182(ver) {
		packageComponents = append(packageComponents, "sensor")
	}
	for _, component := range packageComponents {
		evidenceArtifact, ok := artifactByComponent[component]
		if !ok {
			return fmt.Errorf("Windows %s свидетельство отсутствующий %s", arch, component)
		}
		row, ok := manifestRows[component]
		if !ok || row.Size != evidenceArtifact.Size || !strings.EqualFold(row.SHA256, evidenceArtifact.SHA256) {
			return fmt.Errorf("Windows %s пакет манифест делает не привязывать %s", arch, component)
		}
	}

	zf, err := zip.OpenReader(packagePath)
	if err != nil {
		return fmt.Errorf("Windows %s пакет zip недопустимый: %w", arch, err)
	}
	defer zf.Close()
	zipFiles := map[string][]byte{}
	for _, entry := range zf.File {
		name := filepath.ToSlash(entry.Name)
		clean := filepath.ToSlash(filepath.Clean(name))
		if name == "" || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(name, "/") {
			return fmt.Errorf("Windows %s пакет содержит unsafe путь %q", arch, name)
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if _, exists := zipFiles[clean]; exists {
			return fmt.Errorf("Windows %s пакет содержит дубликат запись %s", arch, clean)
		}
		r, err := entry.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(r, 256*1024*1024))
		closeErr := r.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		zipFiles[clean] = data
	}
	zipManifest, ok := zipFiles["WINDOWS_PACKAGE_MANIFEST.json"]
	if !ok || !bytes.Equal(bytes.TrimSpace(zipManifest), bytes.TrimSpace(manifestRaw)) {
		return fmt.Errorf("Windows %s пакет встроенный манифест differs из релиз манифест", arch)
	}
	packageEntries := map[string]string{
		"desktop-launcher": "neverlauncher-desktop-" + ver + "-windows-" + arch + ".exe",
		"guard":            "neverguard.exe",
	}
	if componentTransactionalUpdateRequired0157(ver) {
		packageEntries = map[string]string{
			"cli":              "neverlauncher-cli.exe",
			"desktop-launcher": "neverlauncher-desktop.exe",
			"guard":            "neverguard.exe",
			"runtime":          "neverruntime.exe",
		}
	}
	if neverguardSensorRequired0182(ver) {
		packageEntries["sensor"] = "neverguard-sensor.dll"
	}
	for component, entryName := range packageEntries {
		data, ok := zipFiles[entryName]
		if !ok {
			return fmt.Errorf("Windows %s пакет отсутствующий %s", arch, entryName)
		}
		evidenceArtifact := artifactByComponent[component]
		sum := sha256Bytes0152(data)
		if int64(len(data)) != evidenceArtifact.Size || !strings.EqualFold(sum, evidenceArtifact.SHA256) {
			return fmt.Errorf("Windows %s пакет встроенный %s differs из подписанный артефакт релиза", arch, component)
		}
		pe, err := inspectWindowsPEBytes0152(data)
		if err != nil || pe.Architecture != arch {
			return fmt.Errorf("Windows %s пакет встроенный %s имеет недопустимый PE архитектура: %v", arch, component, err)
		}
		if requireSigned && !pe.HasSignature {
			return fmt.Errorf("Windows %s пакет встроенный %s lacks Authenticode сертификат таблица", arch, component)
		}
	}
	if componentTransactionalUpdateRequired0157(ver) {
		updateRaw, ok := zipFiles[componentUpdateManifestFile0157]
		if !ok {
			return fmt.Errorf("Windows %s пакет lacks %s", arch, componentUpdateManifestFile0157)
		}
		var update componentUpdateManifest0157
		if err := json.Unmarshal(updateRaw, &update); err != nil {
			return fmt.Errorf("Windows %s компонент обновление манифест недопустимый: %w", arch, err)
		}
		expectedTrust := "unsigned-development"
		if requireSigned {
			expectedTrust = "authenticode-rfc3161"
		}
		expectedComponentCount := 3
		if neverguardSensorRequired0182(ver) {
			expectedComponentCount = 4
		}
		if update.SchemaVersion != "1.0" || update.Product != "NeverLauncher" || update.ProductVersion != ver || update.Platform != "windows" || update.Architecture != arch || update.Layout != "adjacent-files" || update.TrustMode != expectedTrust || len(update.Components) != expectedComponentCount {
			return fmt.Errorf("Windows %s компонент обновление манифест идентичность несоответствие", arch)
		}
		aliases := map[string]string{"desktop": "desktop-launcher", "guard": "guard", "runtime": "runtime"}
		expectedEntry := map[string]string{"desktop": "neverlauncher-desktop.exe", "guard": "neverguard.exe", "runtime": "neverruntime.exe"}
		if neverguardSensorRequired0182(ver) {
			aliases["sensor"] = "sensor"
			expectedEntry["sensor"] = "neverguard-sensor.dll"
		}
		for _, row := range update.Components {
			component, ok := aliases[row.Component]
			evidenceArtifact, exists := artifactByComponent[component]
			if !ok || !exists || row.SourcePath != expectedEntry[row.Component] || row.TargetPath != row.SourcePath || row.Size != evidenceArtifact.Size || !strings.EqualFold(row.SHA256, evidenceArtifact.SHA256) || !row.Executable {
				return fmt.Errorf("Windows %s компонент обновление привязка несоответствие для %s", arch, row.Component)
			}
		}
	}
	return nil
}

func sha256Bytes0152(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func verifyWindowsDeliveryAllowlist0152(dir, ver string, evidence WindowsSigningEvidence0152, productionSigned bool) error {
	raw, err := os.ReadFile(filepath.Join(dir, windowsDeliveryAllowlistFile0152))
	if err != nil {
		return err
	}
	var root struct {
		SchemaVersion string `json:"schemaVersion"`
		Releases      map[string]struct {
			ProtocolVersion int `json:"protocolVersion"`
			Platforms       map[string]struct {
				SigningMode string `json:"signingMode"`
				Artifacts   []struct {
					GuardSHA256         string `json:"guardSha256"`
					LauncherSHA256      string `json:"launcherSha256"`
					RequireAuthenticode bool   `json:"requireAuthenticode"`
				} `json:"artifacts"`
			} `json:"platforms"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("недопустимый %s: %w", windowsDeliveryAllowlistFile0152, err)
	}
	release, ok := root.Releases[ver]
	if root.SchemaVersion != "2.0" || !ok || release.ProtocolVersion != 4 {
		return errors.New("Windows доставка список разрешений schema/release несоответствие")
	}
	policy, ok := release.Platforms["windows"]
	if !ok {
		return errors.New("Windows доставка список разрешений является отсутствующий Windows политика")
	}
	expectedMode := "unsigned-development"
	if productionSigned {
		expectedMode = "authenticode"
	}
	if policy.SigningMode != expectedMode || len(policy.Artifacts) != 2 {
		return errors.New("Windows доставка список разрешений подписание mode/artifact счётчик несоответствие")
	}
	expectedPairs := map[string]bool{}
	for _, target := range evidence.Targets {
		byComponent := map[string]WindowsSignedArtifact0152{}
		for _, artifact := range target.Artifacts {
			byComponent[artifact.Component] = artifact
		}
		desktop, desktopOK := byComponent["desktop-launcher"]
		guard, guardOK := byComponent["guard"]
		if !desktopOK || !guardOK {
			return fmt.Errorf("Windows %s свидетельство отсутствующий Guard/Desktop пара", target.Architecture)
		}
		expectedPairs[strings.ToLower(guard.SHA256)+":"+strings.ToLower(desktop.SHA256)] = true
	}
	seen := map[string]bool{}
	for _, row := range policy.Artifacts {
		key := strings.ToLower(row.GuardSHA256) + ":" + strings.ToLower(row.LauncherSHA256)
		if !validDeliverySHA256(row.GuardSHA256) || !validDeliverySHA256(row.LauncherSHA256) || !expectedPairs[key] || seen[key] {
			return errors.New("Windows доставка список разрешений содержит unexpected/duplicate артефакт пара")
		}
		if row.RequireAuthenticode != productionSigned {
			return errors.New("Windows доставка список разрешений requireAuthenticode несоответствие")
		}
		seen[key] = true
	}
	if len(seen) != len(expectedPairs) {
		return errors.New("Windows доставка список разрешений делает не cover оба x64/ARM64 пары")
	}
	return nil
}

func verifyWindowsSigningEvidence0152(dir, ver string, requireSigned bool) error {
	evidence, err := readWindowsSigningEvidence0152(dir)
	if err != nil {
		return err
	}
	if evidence.SchemaVersion != "1.0" || evidence.Product != "NeverLauncher" || evidence.ProductVersion != ver || evidence.Platform != "windows" {
		return errors.New("Windows подписание свидетельство identity/schema несоответствие")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.GeneratedAt); err != nil {
		if _, fallbackErr := time.Parse(time.RFC3339, evidence.GeneratedAt); fallbackErr != nil {
			return errors.New("Windows подписание свидетельство generatedAt является недопустимый")
		}
	}
	productionSigned := evidence.SigningMode == "authenticode-rfc3161"
	if evidence.SigningMode != "authenticode-rfc3161" && evidence.SigningMode != "unsigned-development" {
		return fmt.Errorf("неподдерживаемый Windows подписание режим %q", evidence.SigningMode)
	}
	if requireSigned && !productionSigned {
		return errors.New("рабочий публикация требует Authenticode+RFC3161 Windows подписание")
	}
	if productionSigned {
		if evidence.Signer == nil || !windowsCertThumbprintRE0152.MatchString(evidence.Signer.Thumbprint) || strings.TrimSpace(evidence.TimestampServer) == "" {
			return errors.New("рабочий Windows подписание свидетельство является отсутствующий signer/timestamp идентичность")
		}
		generatedAt, _ := time.Parse(time.RFC3339Nano, evidence.GeneratedAt)
		if generatedAt.IsZero() {
			generatedAt, _ = time.Parse(time.RFC3339, evidence.GeneratedAt)
		}
		notBefore, err1 := time.Parse(time.RFC3339, evidence.Signer.NotBefore)
		notAfter, err2 := time.Parse(time.RFC3339, evidence.Signer.NotAfter)
		if err1 != nil || err2 != nil || generatedAt.Before(notBefore) || generatedAt.After(notAfter) {
			return errors.New("Windows подписание сертификат validity делает не cover свидетельство генерация время")
		}
	}

	delivery, err := readDeliveryManifest0151(dir)
	if err != nil {
		return fmt.Errorf("Windows подписание требует доставка манифест: %w", err)
	}
	deliveryByName := map[string]DeliveryArtifact{}
	for _, artifact := range delivery.Artifacts {
		deliveryByName[artifact.Name] = artifact
	}

	if len(evidence.Targets) != 2 {
		return fmt.Errorf("Windows подписание свидетельство должен contain точно x64+arm64 цели, получил %d", len(evidence.Targets))
	}
	seenTargets := map[string]bool{}
	for _, target := range evidence.Targets {
		arch := target.Architecture
		rustTarget, expectedMachine, expectedMachineText, err := windowsTargetMetadata0152(arch)
		if err != nil {
			return err
		}
		if seenTargets[arch] {
			return fmt.Errorf("дубликат Windows подписание цель %s", arch)
		}
		seenTargets[arch] = true
		if target.RustTarget != rustTarget || !strings.EqualFold(target.PEMachine, expectedMachineText) {
			return fmt.Errorf("Windows %s цель метаданные несоответствие", arch)
		}
		expectedNames := expectedWindowsSignedArtifactsForVersion0157(ver, arch)
		if len(target.Artifacts) != len(expectedNames) {
			return fmt.Errorf("Windows %s цель имеет недопустимый подписанный артефакт задать для %s", arch, ver)
		}
		artifactByComponent := map[string]WindowsSignedArtifact0152{}
		for _, artifact := range target.Artifacts {
			expectedName, known := expectedNames[artifact.Component]
			if !known || artifact.Name != expectedName || artifact.Architecture != arch || !strings.EqualFold(artifact.PEMachine, expectedMachineText) {
				return fmt.Errorf("Windows %s подписанный артефакт идентичность несоответствие: %s", arch, artifact.Name)
			}
			if _, exists := artifactByComponent[artifact.Component]; exists {
				return fmt.Errorf("Windows %s дубликат подписанный компонент %s", arch, artifact.Component)
			}
			artifactByComponent[artifact.Component] = artifact
			path, err := safeDeliveryArtifactPath(dir, artifact.Name)
			if err != nil {
				return err
			}
			actualHash, actualSize, err := hashFile(path)
			if err != nil {
				return fmt.Errorf("Windows подписанный артефакт %s: %w", artifact.Name, err)
			}
			if artifact.Size <= 0 || artifact.Size != actualSize || !validDeliverySHA256(artifact.SHA256) || !strings.EqualFold(artifact.SHA256, actualHash) {
				return fmt.Errorf("Windows подписанный артефакт %s checksum/size несоответствие", artifact.Name)
			}
			deliveryArtifact, ok := deliveryByName[artifact.Name]
			if !ok || deliveryArtifact.Platform != "windows" || deliveryArtifact.Architecture != arch || deliveryArtifact.Size != actualSize || !strings.EqualFold(deliveryArtifact.SHA256, actualHash) {
				return fmt.Errorf("Windows подписанный артефакт %s является не привязанный к DELIVERY_MANIFEST.JSON", artifact.Name)
			}
			pe, err := inspectWindowsPEFile0152(path)
			if err != nil || pe.Architecture != arch || pe.Machine != expectedMachine {
				return fmt.Errorf("Windows подписанный артефакт %s PE валидация ошибка: %v", artifact.Name, err)
			}
			if productionSigned {
				if artifact.AuthenticodeStatus != "Valid" || !artifact.Timestamped || !artifact.SigntoolVerified || !pe.HasSignature {
					return fmt.Errorf("Windows подписанный артефакт %s lacks проверен Authenticode+метка времени свидетельство", artifact.Name)
				}
				if !strings.EqualFold(artifact.SignerThumbprint, evidence.Signer.Thumbprint) || !windowsCertThumbprintRE0152.MatchString(artifact.TimestampSignerThumbprint) {
					return fmt.Errorf("Windows подписанный артефакт %s signer/timestamp идентичность несоответствие", artifact.Name)
				}
				if err := verifyWindowsAuthenticodeNative0152(path, artifact.SignerThumbprint, artifact.TimestampSignerThumbprint); err != nil {
					return fmt.Errorf("Windows подписанный артефакт %s нативный Authenticode проверка ошибка: %w", artifact.Name, err)
				}
			} else if artifact.AuthenticodeStatus == "Valid" || artifact.Timestamped || artifact.SigntoolVerified {
				return fmt.Errorf("неподписанный-разработка Windows свидетельство overclaims подпись состояние для %s", artifact.Name)
			}
		}
		if err := verifyWindowsPackage0152(dir, ver, arch, target, artifactByComponent, requireSigned || productionSigned); err != nil {
			return err
		}
	}
	if !seenTargets["x64"] || !seenTargets["arm64"] {
		return errors.New("Windows подписание свидетельство должен cover оба x64 и arm64")
	}
	if err := verifyWindowsDeliveryAllowlist0152(dir, ver, evidence, productionSigned); err != nil {
		return fmt.Errorf("Windows доставка Защита список разрешений: %w", err)
	}

	// Стабильный ordering является не доверие primitive, но детерминированный свидетельство avoids accidental пересборка расхождение.
	architectures := make([]string, 0, len(seenTargets))
	for arch := range seenTargets {
		architectures = append(architectures, arch)
	}
	sort.Strings(architectures)
	if strings.Join(architectures, ",") != "arm64,x64" {
		return errors.New("Windows подписание свидетельство цель задать является недопустимый")
	}
	return nil
}
