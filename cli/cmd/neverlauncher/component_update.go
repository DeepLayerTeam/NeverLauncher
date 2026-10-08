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
		return fmt.Errorf("компонент путь конфликты с обновлятор управление каталог: %s", value)
	}
	return nil
}

func readComponentUpdateManifest0157(path string) (componentUpdateManifest0157, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return componentUpdateManifest0157{}, err
	}
	if len(raw) == 0 || len(raw) > 512*1024 {
		return componentUpdateManifest0157{}, errors.New("компонент обновление манифест размер является недопустимый")
	}
	var manifest componentUpdateManifest0157
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return componentUpdateManifest0157{}, fmt.Errorf("недопустимый %s: %w", componentUpdateManifestFile0157, err)
	}
	return manifest, nil
}

func validateComponentUpdateManifest0157(manifest componentUpdateManifest0157, manifestDir string, allowDevelopment bool) error {
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || strings.TrimSpace(manifest.ProductVersion) == "" {
		return errors.New("компонент обновление манифест identity/schema несоответствие")
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
		return fmt.Errorf("компонент пакет цель несоответствие: пакет=%s/%s хост=%s/%s", platform, arch, target.Platform, target.Architecture)
	}
	if manifest.Platform != platform || manifest.Architecture != arch {
		return errors.New("компонент пакет цель должен использовать канонический platform/architecture")
	}
	if manifest.Layout != "adjacent-files" && manifest.Layout != "macos-app-bundle" {
		return fmt.Errorf("неподдерживаемый компонент обновление структура %q", manifest.Layout)
	}
	if manifest.Layout == "macos-app-bundle" && platform != "macos" {
		return errors.New("macOS-app-комплект структура является действительный только на macOS")
	}
	expected := map[string]bool{"desktop": false, "guard": false, "runtime": false}
	if platform == "windows" && neverguardSensorRequired0182(manifest.ProductVersion) {
		expected["sensor"] = false
	}
	if len(manifest.Components) != len(expected) {
		return fmt.Errorf("компонент обновление манифест имеет %d обязательный компонент, ожидаемый %d", len(manifest.Components), len(expected))
	}
	seenTargets := map[string]bool{}
	sourceBase := manifestDir
	if manifest.Layout == "macos-app-bundle" && filepath.Base(manifestDir) == "Resources" {
		contents := filepath.Dir(manifestDir)
		sourceBase = filepath.Dir(contents)
	}
	for _, item := range append(append([]componentUpdateArtifact0157{}, manifest.Components...), manifest.SupportFiles...) {
		if err := validateComponentRelativePath0157(item.SourcePath); err != nil {
			return fmt.Errorf("unsafe компонент исходник путь %q: %w", item.SourcePath, err)
		}
		if err := validateComponentRelativePath0157(item.TargetPath); err != nil {
			return fmt.Errorf("unsafe компонент цель путь %q: %w", item.TargetPath, err)
		}
		if item.Size <= 0 || !validSHA256Hex0157(item.SHA256) {
			return fmt.Errorf("недопустимый компонент метаданные для %s", item.Component)
		}
		key := strings.ToLower(item.TargetPath)
		if runtime.GOOS != "windows" {
			key = item.TargetPath
		}
		if seenTargets[key] {
			return fmt.Errorf("дубликат компонент цель путь %s", item.TargetPath)
		}
		seenTargets[key] = true
		source := filepath.Join(sourceBase, filepath.FromSlash(item.SourcePath))
		if err := verifyUpdaterFile0156(source, item.Size, item.SHA256); err != nil {
			return fmt.Errorf("компонент пакет исходник проверять %s: %w", item.SourcePath, err)
		}
	}
	for _, item := range manifest.Components {
		if _, ok := expected[item.Component]; !ok {
			return fmt.Errorf("неизвестный обязательный компонент %q", item.Component)
		}
		if expected[item.Component] {
			return fmt.Errorf("дубликат обязательный компонент %q", item.Component)
		}
		expected[item.Component] = true
		if !item.Executable {
			return fmt.Errorf("обязательный компонент %s должен быть исполняемый", item.Component)
		}
	}
	for component, present := range expected {
		if !present {
			return fmt.Errorf("компонент обновление манифест отсутствующий %s", component)
		}
	}
	if allowDevelopment && (manifest.TrustMode == "development-self-test" || manifest.TrustMode == "unsigned-development" || manifest.TrustMode == "adhoc-development") {
		return nil
	}
	switch platform {
	case "windows":
		if manifest.TrustMode != "authenticode-rfc3161" {
			return errors.New("рабочий Windows компонент обновление требует authenticode-rfc3161 trustMode")
		}
		for _, item := range manifest.Components {
			if !windowsCertThumbprintRE0152.MatchString(item.SignerThumbprint) || !windowsCertThumbprintRE0152.MatchString(item.TimestampSignerThumbprint) {
				return fmt.Errorf("Windows компонент %s является отсутствующий signer/timestamp идентичность", item.Component)
			}
		}
	case "linux":
		if manifest.TrustMode != "sha256-delivery" {
			return errors.New("рабочий Linux компонент обновление требует sha256-доставка trustMode")
		}
	case "macos":
		if manifest.TrustMode != "developer-id-notarized" {
			return errors.New("рабочий macOS компонент обновление требует разработчик-ID-нотариально заверенный trustMode")
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
			return fmt.Errorf("%s хеш проверка: %w", item.Component, err)
		}
		switch manifest.Platform {
		case "windows":
			pe, err := inspectWindowsPEFile0152(path)
			if err != nil || pe.Architecture != manifest.Architecture || !pe.HasSignature {
				return fmt.Errorf("%s Windows PE/AuthentiCode граница ошибка: %v", item.Component, err)
			}
			if err := verifyWindowsAuthenticodeNative0152(path, item.SignerThumbprint, item.TimestampSignerThumbprint); err != nil {
				return fmt.Errorf("%s Authenticode проверять: %w", item.Component, err)
			}
		case "linux":
			elf, err := inspectLinuxELFFile0153(path)
			if err != nil || elf.Architecture != manifest.Architecture {
				return fmt.Errorf("%s ELF архитектура проверять: %v", item.Component, err)
			}
		case "macos":
			macho, err := inspectMacOSMachOFile0154(path)
			if err != nil || macho.Architecture != manifest.Architecture || !macho.HasCodeSignature {
				return fmt.Errorf("%s Mach-O signature/architecture проверять: %v", item.Component, err)
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
			return errors.New("рабочий компонент обновление требует закреплённый архив, не unpacked каталог")
		}
		return nil
	}
	if !validSHA256Hex0157(expected) {
		if allowDevelopment && strings.TrimSpace(expected) == "" {
			return nil
		}
		return errors.New("компонент обновление требует --expected-sha256 с 64-hex пакет хеш")
	}
	actual, _, err := hashFile(packagePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("компонент обновление пакет SHA-256 несоответствие: получил=%s ожидаемый=%s", actual, strings.ToLower(expected))
	}
	return nil
}

func verifyPackageAgainstDelivery0157(deliveryPath, packagePath, expectedSHA string) error {
	if strings.TrimSpace(deliveryPath) == "" {
		return nil
	}
	dir := filepath.Dir(deliveryPath)
	if filepath.Base(deliveryPath) != deliveryManifestFile0151 {
		return errors.New("--доставка-манифест должен точка к DELIVERY_MANIFEST.JSON")
	}
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		return err
	}
	name := filepath.Base(packagePath)
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == name {
			if artifact.Component != "desktop-package" || !strings.EqualFold(artifact.SHA256, expectedSHA) {
				return errors.New("компонент обновление пакет является не привязанный к доставка манифест хеш")
			}
			return nil
		}
	}
	return fmt.Errorf("компонент обновление пакет %s является отсутствующий из DELIVERY_MANIFEST.JSON", name)
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
				return fmt.Errorf("ditto extract ошибка: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		return extractComponentZip0157(packagePath, dst)
	}
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return extractComponentTarGz0157(packagePath, dst)
	}
	return fmt.Errorf("неподдерживаемый компонент пакет формат: %s", filepath.Base(packagePath))
}

func safeExtractPath0157(root, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || filepath.IsAbs(name) || strings.Contains(name, "\\") {
		return "", fmt.Errorf("unsafe пакет запись %q", name)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
		return "", fmt.Errorf("unsafe пакет запись %q", name)
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
			return fmt.Errorf("пакет запись должен быть regular file/directory: %s", name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(file.UncompressedSize64)
		if total > 8<<30 {
			return errors.New("компонент пакет exceeds 8 GiB извлечение ограничение")
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
				return errors.New("компонент пакет exceeds 8 GiB извлечение ограничение")
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
			return fmt.Errorf("пакет запись type является не разрешён: %s", h.Name)
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
			return fmt.Errorf("разработка компонент комплект содержит символическая ссылка: %s", rel)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("разработка компонент комплект содержит non-regular файл: %s", rel)
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
			return errors.New("компонент пакет содержит слишком многие файловая система записи")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("компонент пакет содержит символическая ссылка: %s", path)
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
		return "", fmt.Errorf("компонент пакет должен contain точно один %s, получил %d", componentUpdateManifestFile0157, len(matches))
	}
	return matches[0], nil
}

func componentUpdateInstallRoot0157(currentDesktop, explicitRoot string, manifest componentUpdateManifest0157) (root, liveBundle string, err error) {
	currentDesktop = strings.TrimSpace(currentDesktop)
	if manifest.Layout == "macos-app-bundle" {
		if currentDesktop == "" {
			return "", "", errors.New("macOS компонент обновление требует --текущий-настольное приложение")
		}
		abs, err := filepath.Abs(currentDesktop)
		if err != nil {
			return "", "", err
		}
		macosDir := filepath.Dir(abs)
		contents := filepath.Dir(macosDir)
		bundle := filepath.Dir(contents)
		if filepath.Base(macosDir) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(strings.ToLower(filepath.Base(bundle)), ".app") {
			return "", "", errors.New("текущий Настольное приложение является не внутри macOS.app/Contents/MacOS комплект")
		}
		parent := filepath.Dir(bundle)
		if explicitRoot != "" {
			explicit, e := filepath.Abs(explicitRoot)
			if e != nil || filepath.Clean(explicit) != filepath.Clean(parent) {
				return "", "", errors.New("--корень делает не соответствовать текущий macOS app родительский")
			}
		}
		return parent, filepath.Base(bundle), nil
	}
	if explicitRoot != "" {
		root, err := filepath.Abs(explicitRoot)
		return root, "", err
	}
	if currentDesktop == "" {
		return "", "", errors.New("компонент обновление требует --корень или --текущий-настольное приложение")
	}
	abs, err := filepath.Abs(currentDesktop)
	if err != nil {
		return "", "", err
	}
	return filepath.Dir(abs), "", nil
}

func currentComponentVersion0157(root string) string {
	_, _ = migrateComponentUpdateState01510(root)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157)))
	if err != nil {
		return ""
	}
	var state componentUpdateState0157
	if json.Unmarshal(raw, &state) == nil && validateComponentUpdateState01510(state) == nil {
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
		return errors.New("--wait-PID не может быть обновлятор процесс сам")
	}
	deadline := time.Now().Add(timeout)
	for updaterProcessAlive0156(pid) {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed из waiting для Настольное приложение PID=%d к выход", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// На Windows процесс дескриптор может disappear just до образ сопоставление являются fully релиз.
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
	if _, err := migrateComponentUpdateState01510(root); err != nil {
		return nil, fmt.Errorf("мигрировать компонент обновление состояние: %w", err)
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
	components := make([]string, 0, len(manifest.Components))
	for _, item := range manifest.Components {
		components = append(components, item.Component)
	}
	report["components"] = components
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
		return nil, fmt.Errorf("недопустимый компонент дерево журнал %s", id)
	}
	return &journal, nil
}

func safeComponentTreePath0157(u *transactionalUpdater0156, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("unsafe компонент дерево путь %q", rel)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(strings.ToLower(clean), ".neverlauncher/") {
		return "", fmt.Errorf("unsafe компонент дерево путь %q", rel)
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
			return errors.New("компонент дерево откат refuses non-каталог актуальный комплект")
		}
		_ = os.RemoveAll(journal.FailedPath)
		if err := os.Rename(live, journal.FailedPath); err != nil {
			return fmt.Errorf("preserve ошибка компонент комплект: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if st, err := os.Lstat(journal.BackupPath); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return errors.New("компонент дерево резервное копирование является не безопасный каталог")
		}
		if err := os.Rename(journal.BackupPath, live); err != nil {
			return fmt.Errorf("восстановление компонент комплект резервное копирование: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDirBestEffort0156(u.root)
	journal.Phase = "rolled-back"
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		return err
	}
	if err := removeSafeComponentTreePayload01510(u, journal); err != nil {
		return fmt.Errorf("очистка rolled-back компонент дерево полезная нагрузка: %w", err)
	}
	return nil
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
			if err := removeSafeComponentTreePayload01510(u, journal); err != nil {
				return recovered, err
			}
		case "old-moved", "new-moved", "verifying", "rolling-back":
			if err := rollbackComponentTreeLocked0157(u, journal, errors.New("восстановление после сбоя")); err != nil {
				return recovered, err
			}
		default:
			return recovered, fmt.Errorf("неизвестный компонент дерево транзакция phase %q", journal.Phase)
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
		return nil, errors.New("компонент дерево подготовка должен reside внутри обновлятор управление каталог на актуальный файловая система")
	}
	for label, path := range map[string]string{"live": live, "stage": stageAbs} {
		st, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("%s компонент дерево: %w", label, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return nil, fmt.Errorf("%s компонент дерево должен быть non-символическая ссылка каталог", label)
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
		return nil, fmt.Errorf("переносить актуальный компонент комплект к резервное копирование: %w", err)
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
			return nil, fmt.Errorf("компонент дерево переключение ошибка: %v; откат ошибка: %w", err, rb)
		}
		return nil, err
	}
	syncDirBestEffort0156(u.root)
	journal.Phase = "new-moved"
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("компонент дерево журнал ошибка после переключение: %v; откат ошибка: %w", err, rb)
		}
		return nil, err
	}
	journal.Phase = "verifying"
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("компонент дерево проверять журнал ошибка: %v; откат ошибка: %w", err, rb)
		}
		return nil, err
	}
	if verify != nil {
		if err := verify(live); err != nil {
			rb := rollbackComponentTreeLocked0157(u, journal, err)
			if rb != nil {
				return nil, fmt.Errorf("компонент дерево проверять ошибка: %v; откат ошибка: %w", err, rb)
			}
			return nil, fmt.Errorf("компонент дерево транзакция %s rolled back: %w", id, err)
		}
	}
	journal.Phase = "committed"
	journal.Error = ""
	if err := writeComponentTreeJournal0157(u, journal); err != nil {
		rb := rollbackComponentTreeLocked0157(u, journal, err)
		if rb != nil {
			return nil, fmt.Errorf("компонент дерево фиксация журнал ошибка: %v; откат ошибка: %w", err, rb)
		}
		return nil, err
	}
	if err := removeSafeComponentTreePayload01510(u, journal); err != nil {
		return nil, fmt.Errorf("очистка committed компонент дерево полезная нагрузка: %w", err)
	}
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
			return fmt.Errorf("macOS post-обновление проверка ошибка: %s: %w: %s", strings.Join(command, " "), err, strings.TrimSpace(string(out)))
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
			return nil, fmt.Errorf("компонент манифест является не внутри ожидаемый app комплект %s", liveBundle)
		}
		appSource = parent
	}
	if filepath.Base(appSource) != liveBundle {
		return nil, errors.New("компонент пакет app комплект идентичность несоответствие")
	}
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		return nil, err
	}
	if err := verifyComponentBinaries0157(manifest, appSource, true, allowDevelopment); err != nil {
		return nil, fmt.Errorf("подготовленный macOS компонент проверять: %w", err)
	}
	if _, err := migrateComponentUpdateState01510(root); err != nil {
		return nil, fmt.Errorf("компонент состояние миграция: %w", err)
	}
	fromVersion := currentComponentVersion0157(root)
	statePath := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	if fromVersion == "" {
		// 0.15.7-0.15.9 разработка комплекты может contain состояние внутри app.
		legacyEmbedded := filepath.Join(root, liveBundle, "Contents", "Resources", "COMPONENT_UPDATE_STATE.json")
		if raw, err := os.ReadFile(legacyEmbedded); err == nil {
			var state componentUpdateState0157
			if json.Unmarshal(raw, &state) == nil && validateComponentUpdateState01510(state) == nil {
				fromVersion = state.Version
			}
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
	// Разработка self-тесты использовать неподписанный synthetic дерево. Рабочий пакеты являются уже signed/notarized;
	// изменяющий их после извлечение будет invalidate outer комплект подпись, так рабочий состояние является сохранённый
	// вне app комплект после фиксация.
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
		var state componentUpdateState0157
		if err := json.Unmarshal(stateBytes, &state); err != nil {
			return nil, err
		}
		if err := writeJSONFileAtomicMode(statePath, state, 0o600); err != nil {
			return nil, fmt.Errorf("сохранять канонический компонент обновление состояние: %w", err)
		}
	}
	report["components"] = []string{"desktop", "guard", "runtime"}
	report["restartExecutable"] = filepath.Join(root, liveBundle, filepath.FromSlash(componentTargetPath0157(manifest, "desktop")))
	return report, nil
}

func applyComponentPackage0157(packagePath, expectedSHA, deliveryPath, explicitRoot, currentDesktop string, waitPID int, restart, allowDevelopment bool) (map[string]any, error) {
	if strings.TrimSpace(packagePath) == "" {
		return nil, errors.New("обновление компонент требует --пакет")
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
	// Extract adjacent пакеты под назначение обновлятор управление каталог так все subsequent staging/renames
	// оставаться на одинаковый файловая система. macOS needs итоговый корень до ditto извлечение для одинаковый reason.
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
		return nil, fmt.Errorf("компонент пакет бинарный файл проверка: %w", err)
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
			return nil, errors.New("компонент обновление committed но перезапуск исполняемый является недоступный")
		}
		cmd := exec.Command(executable)
		cmd.Dir = filepath.Dir(executable)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("компонент обновление committed но Настольное приложение перезапуск ошибка: %w", err)
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

	// Exercise whole-app swap откат путь на каждый CI хост. дерево является synthetic,
	// но journal/rename/recovery machinery является точно что macOS рабочий использует.
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
		return errors.New("forced компонент дерево post-проверять ошибка")
	}); err == nil {
		return nil, errors.New("компонент дерево self-тест ожидаемый автоматический откат")
	}
	restored, err := os.ReadFile(oldDesktop)
	if err != nil || string(restored) != "old-tree-desktop" {
		return nil, fmt.Errorf("компонент дерево откат self-тест сделал не восстановление актуальный app: %w", err)
	}
	return map[string]any{"schemaVersion": "1.0", "toolVersion": version, "components": []string{"desktop", "guard", "runtime"}, "transaction": report, "macosTreeRollback": "ok", "status": "ok"}, nil
}

func parseWaitPID0157(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 0 {
		return 0, errors.New("--wait-PID должен быть positive integer")
	}
	return pid, nil
}
