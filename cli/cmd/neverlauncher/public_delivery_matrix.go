package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	publicProductionDeliveryMatrixFile0159 = "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json"
	publicProductionDeliverySchema0159     = "1.0"
	publicProductionDeliveryChannel0159    = "stable"
)

type PublicDeliveryAsset0159 struct {
	Name         string `json:"name"`
	Component    string `json:"component"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	URL          string `json:"url"`
	Executable   bool   `json:"executable,omitempty"`
}

type PublicDeliveryControl0159 struct {
	Name string `json:"name"`
	Role string `json:"role"`
	URL  string `json:"url"`
}

type PublicDeliveryTarget0159 struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	CLI          string `json:"cli"`
	Desktop      string `json:"desktop"`
	Guard        string `json:"guard"`
	Runtime      string `json:"runtime"`
	Package      string `json:"package"`
	ManagedJRE   string `json:"managedJre"`
	API          string `json:"api,omitempty"`
}

type PublicProductionDeliveryMatrix0159 struct {
	SchemaVersion          string                      `json:"schemaVersion"`
	Product                string                      `json:"product"`
	Version                string                      `json:"version"`
	Channel                string                      `json:"channel"`
	GeneratedAt            string                      `json:"generatedAt"`
	BaseURL                string                      `json:"baseUrl"`
	DeliveryManifestSHA256 string                      `json:"deliveryManifestSha256"`
	Controls               []PublicDeliveryControl0159 `json:"controls"`
	Targets                []PublicDeliveryTarget0159  `json:"targets"`
	Assets                 []PublicDeliveryAsset0159   `json:"assets"`
}

type PublicDeliveryE2EReport0159 struct {
	SchemaVersion                     string           `json:"schemaVersion"`
	Product                           string           `json:"product"`
	Version                           string           `json:"version"`
	MatrixURL                         string           `json:"matrixUrl"`
	BaseURL                           string           `json:"baseUrl"`
	StartedAt                         string           `json:"startedAt"`
	FinishedAt                        string           `json:"finishedAt"`
	Downloaded                        int              `json:"downloadedFiles"`
	DownloadedBytes                   int64            `json:"downloadedBytes"`
	Targets                           []DeliveryTarget `json:"verifiedTargets"`
	ProductionDeliveryReleaseVerified bool             `json:"productionDeliveryReleaseVerified,omitempty"`
	Status                            string           `json:"status"`
}

func publicProductionDeliveryRequired0159(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 9)))
}

func defaultPublicReleaseBaseURL0159(ver string) string {
	return "https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v" + strings.TrimSpace(ver)
}

func normalizePublicBaseURL0159(raw string, allowHTTP bool) (string, error) {
	raw = strings.TrimSpace(strings.TrimRight(raw, "/"))
	if raw == "" {
		return "", errors.New("публичный доставка основа URL является пустой")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("недопустимый публичный доставка основа URL %q", raw)
	}
	if u.Scheme != "https" {
		if !(allowHTTP && u.Scheme == "http" && isLoopbackHost0159(u.Hostname())) {
			return "", errors.New("публичный доставка основа URL должен использовать HTTPS")
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isLoopbackHost0159(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func publicAssetURL0159(baseURL, name string) string {
	return strings.TrimRight(baseURL, "/") + "/" + url.PathEscape(name)
}

func expectedPublicTarget0159(ver, platform, arch string) (PublicDeliveryTarget0159, error) {
	jre := managedJREArchiveName0155(ver, platform, arch)
	switch platform {
	case "windows":
		artifacts := expectedWindowsSignedArtifactsForVersion0157(ver, arch)
		pkg, _ := expectedWindowsPackage0152(ver, arch)
		return PublicDeliveryTarget0159{
			Platform: platform, Architecture: arch, CLI: artifacts["cli"], Desktop: artifacts["desktop-launcher"],
			Guard: artifacts["guard"], Runtime: artifacts["runtime"], Package: pkg, ManagedJRE: jre,
		}, nil
	case "linux":
		artifacts := expectedLinuxArtifacts0153(arch)
		pkg, _ := expectedLinuxPackage0153(ver, arch)
		return PublicDeliveryTarget0159{
			Platform: platform, Architecture: arch, CLI: artifacts["cli"], Desktop: artifacts["desktop-launcher"],
			Guard: artifacts["guard"], Runtime: artifacts["runtime"], Package: pkg, ManagedJRE: jre, API: artifacts["api"],
		}, nil
	case "macos":
		artifacts := expectedMacOSArtifacts0154(arch)
		pkg, _ := expectedMacOSPackage0154(ver, arch)
		return PublicDeliveryTarget0159{
			Platform: platform, Architecture: arch, CLI: artifacts["cli"], Desktop: artifacts["desktop-launcher"],
			Guard: artifacts["guard"], Runtime: artifacts["runtime"], Package: pkg, ManagedJRE: jre,
		}, nil
	default:
		return PublicDeliveryTarget0159{}, fmt.Errorf("неподдерживаемый публичный цель платформа %q", platform)
	}
}

func publicTargetAssetNames0159(target PublicDeliveryTarget0159) []string {
	out := []string{target.CLI, target.Desktop, target.Guard, target.Runtime, target.Package, target.ManagedJRE}
	if target.API != "" {
		out = append(out, target.API)
	}
	return out
}

func buildPublicProductionDeliveryMatrix0159(dir, ver, rawBaseURL string, allowHTTP bool) (PublicProductionDeliveryMatrix0159, error) {
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		return PublicProductionDeliveryMatrix0159{}, err
	}
	baseURL, err := normalizePublicBaseURL0159(rawBaseURL, allowHTTP)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, err
	}
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, err
	}
	manifestSHA, _, err := hashFile(filepath.Join(dir, deliveryManifestFile0151))
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, err
	}
	matrix := PublicProductionDeliveryMatrix0159{
		SchemaVersion:          publicProductionDeliverySchema0159,
		Product:                "NeverLauncher",
		Version:                strings.TrimSpace(ver),
		Channel:                publicProductionDeliveryChannel0159,
		GeneratedAt:            time.Now().UTC().Format(time.RFC3339Nano),
		BaseURL:                baseURL,
		DeliveryManifestSHA256: manifestSHA,
	}
	controls := [][2]string{
		{deliveryManifestFile0151, "delivery-manifest"},
		{publicProductionDeliveryMatrixFile0159, "public-delivery-matrix"},
		{"RELEASE_MANIFEST.json", "release-manifest"},
		{"SHA256SUMS", "checksums"},
		{"SHA256SUMS.sig", "release-signature"},
		{"PROVENANCE.json.sig", "provenance-signature"},
	}
	if productionReleaseCandidateRequired01511(ver) {
		controls = append(controls, [2]string{productionReleaseCandidateFile01511, "production-release-candidate"})
	}
	if productionDeliveryReleaseRequired0160(ver) {
		controls = append(controls, [2]string{productionDeliveryReleaseFile0160, "production-delivery-release"})
	}
	for _, nameRole := range controls {
		matrix.Controls = append(matrix.Controls, PublicDeliveryControl0159{Name: nameRole[0], Role: nameRole[1], URL: publicAssetURL0159(baseURL, nameRole[0])})
	}
	for _, artifact := range manifest.Artifacts {
		matrix.Assets = append(matrix.Assets, PublicDeliveryAsset0159{
			Name: artifact.Name, Component: artifact.Component, Platform: artifact.Platform, Architecture: artifact.Architecture,
			Format: artifact.Format, SHA256: artifact.SHA256, Size: artifact.Size,
			URL: publicAssetURL0159(baseURL, artifact.Name), Executable: artifact.Executable,
		})
	}
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"x64", "arm64"} {
			target, err := expectedPublicTarget0159(ver, platform, arch)
			if err != nil {
				return PublicProductionDeliveryMatrix0159{}, err
			}
			matrix.Targets = append(matrix.Targets, target)
		}
	}
	sort.Slice(matrix.Assets, func(i, j int) bool { return matrix.Assets[i].Name < matrix.Assets[j].Name })
	return matrix, validatePublicProductionDeliveryMatrix0159(dir, matrix, ver, allowHTTP)
}

func writePublicProductionDeliveryMatrix0159(dir, ver, baseURL string) error {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_PUBLIC_RELEASE_BASE_URL"))
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultPublicReleaseBaseURL0159(ver)
	}
	matrix, err := buildPublicProductionDeliveryMatrix0159(dir, ver, baseURL, false)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(dir, publicProductionDeliveryMatrixFile0159), matrix)
}

func readPublicProductionDeliveryMatrix0159(path string) (PublicProductionDeliveryMatrix0159, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, err
	}
	var matrix PublicProductionDeliveryMatrix0159
	if err := json.Unmarshal(raw, &matrix); err != nil {
		return matrix, fmt.Errorf("публичный доставка матрица JSON: %w", err)
	}
	return matrix, nil
}

func validatePublicProductionDeliveryMatrix0159(dir string, matrix PublicProductionDeliveryMatrix0159, expectedVersion string, allowHTTP bool) error {
	if matrix.SchemaVersion != publicProductionDeliverySchema0159 || matrix.Product != "NeverLauncher" || matrix.Channel != publicProductionDeliveryChannel0159 {
		return errors.New("публичный рабочий доставка матрица header является недопустимый")
	}
	if strings.TrimSpace(expectedVersion) != "" && matrix.Version != strings.TrimSpace(expectedVersion) {
		return fmt.Errorf("публичная матрица версия несоответствие: матрица=%s ожидаемый=%s", matrix.Version, expectedVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, matrix.GeneratedAt); err != nil {
		return errors.New("публичная матрица generatedAt является недопустимый")
	}
	baseURL, err := normalizePublicBaseURL0159(matrix.BaseURL, allowHTTP)
	if err != nil || baseURL != matrix.BaseURL {
		return errors.New("публичная матрица baseUrl является не канонический")
	}
	actualManifestSHA, _, err := hashFile(filepath.Join(dir, deliveryManifestFile0151))
	if err != nil {
		return err
	}
	if !strings.EqualFold(actualManifestSHA, matrix.DeliveryManifestSHA256) || !validDeliverySHA256(matrix.DeliveryManifestSHA256) {
		return errors.New("публичная матрица deliveryManifestSha256 несоответствие")
	}
	delivery, err := readDeliveryManifest0151(dir)
	if err != nil {
		return err
	}
	manifestAssets := map[string]DeliveryArtifact{}
	for _, asset := range delivery.Artifacts {
		manifestAssets[asset.Name] = asset
	}
	matrixAssets := map[string]PublicDeliveryAsset0159{}
	for _, asset := range matrix.Assets {
		if _, duplicate := matrixAssets[asset.Name]; duplicate {
			return fmt.Errorf("дубликат публичный ресурс %s", asset.Name)
		}
		expected, ok := manifestAssets[asset.Name]
		if !ok {
			return fmt.Errorf("публичный ресурс %s является отсутствующий из DELIVERY_MANIFEST.JSON", asset.Name)
		}
		if asset.Component != expected.Component || asset.Platform != expected.Platform || asset.Architecture != expected.Architecture || asset.Format != expected.Format || asset.Size != expected.Size || !strings.EqualFold(asset.SHA256, expected.SHA256) || asset.Executable != expected.Executable {
			return fmt.Errorf("публичный ресурс метаданные несоответствие для %s", asset.Name)
		}
		if asset.URL != publicAssetURL0159(baseURL, asset.Name) {
			return fmt.Errorf("публичный ресурс URL несоответствие для %s", asset.Name)
		}
		matrixAssets[asset.Name] = asset
	}
	if len(matrixAssets) != len(manifestAssets) {
		return fmt.Errorf("публичный ресурс инвентарь несоответствие: матрица=%d доставка=%d", len(matrixAssets), len(manifestAssets))
	}
	for name := range manifestAssets {
		if _, ok := matrixAssets[name]; !ok {
			return fmt.Errorf("публичная матрица является отсутствующий доставка артефакт %s", name)
		}
	}

	expectedControls := map[string]string{
		deliveryManifestFile0151:               "delivery-manifest",
		publicProductionDeliveryMatrixFile0159: "public-delivery-matrix",
		"RELEASE_MANIFEST.json":                "release-manifest",
		"SHA256SUMS":                           "checksums",
		"SHA256SUMS.sig":                       "release-signature",
		"PROVENANCE.json.sig":                  "provenance-signature",
	}
	if productionReleaseCandidateRequired01511(matrix.Version) {
		expectedControls[productionReleaseCandidateFile01511] = "production-release-candidate"
	}
	if productionDeliveryReleaseRequired0160(matrix.Version) {
		expectedControls[productionDeliveryReleaseFile0160] = "production-delivery-release"
	}
	seenControls := map[string]bool{}
	for _, control := range matrix.Controls {
		role, ok := expectedControls[control.Name]
		if !ok || role != control.Role || seenControls[control.Name] || control.URL != publicAssetURL0159(baseURL, control.Name) {
			return fmt.Errorf("публичный управление запись недопустимый: %s", control.Name)
		}
		seenControls[control.Name] = true
	}
	if len(seenControls) != len(expectedControls) {
		return errors.New("публичная матрица управление инвентарь является неполный")
	}

	if len(matrix.Targets) != 6 {
		return fmt.Errorf("публичный рабочий матрица должен предоставлять точно six OS/architecture цели, получил %d", len(matrix.Targets))
	}
	seenTargets := map[string]bool{}
	for _, target := range matrix.Targets {
		canonical, err := canonicalDeliveryTarget(target.Platform, target.Architecture)
		if err != nil || canonical.Platform != target.Platform || canonical.Architecture != target.Architecture || target.Architecture == "universal" {
			return fmt.Errorf("публичный цель является недопустимый: %s/%s", target.Platform, target.Architecture)
		}
		key := target.Platform + "/" + target.Architecture
		if seenTargets[key] {
			return fmt.Errorf("дубликат публичный цель %s", key)
		}
		expectedTarget, err := expectedPublicTarget0159(matrix.Version, target.Platform, target.Architecture)
		if err != nil {
			return err
		}
		if target != expectedTarget {
			return fmt.Errorf("публичный цель %s делает не соответствовать канонический рабочий артефакт задать", key)
		}
		for _, name := range publicTargetAssetNames0159(target) {
			asset, ok := matrixAssets[name]
			if !ok {
				return fmt.Errorf("публичный цель %s требует отсутствующий ресурс %s", key, name)
			}
			if asset.Platform != target.Platform || asset.Architecture != target.Architecture {
				return fmt.Errorf("публичный цель %s ресурс %s имеет цель %s/%s", key, name, asset.Platform, asset.Architecture)
			}
		}
		seenTargets[key] = true
	}
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"x64", "arm64"} {
			if !seenTargets[platform+"/"+arch] {
				return fmt.Errorf("публичный цель матрица является отсутствующий %s/%s", platform, arch)
			}
		}
	}
	return nil
}

func verifyPublicProductionDeliveryMatrix0159(dir, ver string) error {
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		return err
	}
	matrix, err := readPublicProductionDeliveryMatrix0159(filepath.Join(dir, publicProductionDeliveryMatrixFile0159))
	if err != nil {
		return err
	}
	return validatePublicProductionDeliveryMatrix0159(dir, matrix, ver, false)
}

func publicRedirectHostAllowed0159(baseHost, targetHost string) bool {
	baseHost = strings.ToLower(strings.TrimSpace(baseHost))
	targetHost = strings.ToLower(strings.TrimSpace(targetHost))
	if baseHost == targetHost {
		return true
	}
	if baseHost == "github.com" {
		switch targetHost {
		case "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
			return true
		}
	}
	return false
}

func publicHTTPClient0159(baseURL string, allowHTTP bool) (*http.Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("слишком многие публичный доставка перенаправления")
			}
			if !publicRedirectHostAllowed0159(base.Hostname(), req.URL.Hostname()) {
				return errors.New("публичный доставка redirect изменён к недоверенный хост")
			}
			if req.URL.Scheme != "https" && !(allowHTTP && req.URL.Scheme == "http" && isLoopbackHost0159(req.URL.Hostname())) {
				return errors.New("публичный доставка redirect понижение версии транспорт")
			}
			return nil
		},
	}, nil
}

func downloadPublicAsset0159(ctx context.Context, client *http.Client, rawURL, dest, expectedSHA string, expectedSize int64) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "NeverLauncher-public-delivery-e2e/0.15.9")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s возвращён HTTP %d", rawURL, resp.StatusCode)
	}
	if expectedSize > 0 && resp.ContentLength >= 0 && resp.ContentLength != expectedSize {
		return 0, fmt.Errorf("Content-Length несоответствие для %s", rawURL)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, err
	}
	tmp := dest + ".part"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	limit := int64(64 << 20)
	if expectedSize > 0 {
		limit = expectedSize + 1
	}
	written, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return written, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return written, closeErr
	}
	if expectedSize > 0 && written != expectedSize {
		_ = os.Remove(tmp)
		return written, fmt.Errorf("загрузка размер несоответствие для %s: получил=%d ожидаемый=%d", rawURL, written, expectedSize)
	}
	if expectedSize == 0 && written > limit-1 {
		_ = os.Remove(tmp)
		return written, fmt.Errorf("управление загрузка exceeds ограничение: %s", rawURL)
	}
	actualSHA := hex.EncodeToString(h.Sum(nil))
	if strings.TrimSpace(expectedSHA) != "" && !strings.EqualFold(actualSHA, expectedSHA) {
		_ = os.Remove(tmp)
		return written, fmt.Errorf("загрузка sha256 несоответствие для %s", rawURL)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return written, err
	}
	return written, nil
}

func fetchPublicMatrix0159(ctx context.Context, matrixURL, downloadDir string, allowHTTP bool) (PublicProductionDeliveryMatrix0159, int64, error) {
	u, err := url.Parse(strings.TrimSpace(matrixURL))
	if err != nil || u.Host == "" {
		return PublicProductionDeliveryMatrix0159{}, 0, errors.New("публичный E2E требует absolute --матрица-URL")
	}
	baseGuess := strings.TrimSuffix(matrixURL, "/"+url.PathEscape(publicProductionDeliveryMatrixFile0159))
	baseGuess, err = normalizePublicBaseURL0159(baseGuess, allowHTTP)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, 0, err
	}
	client, err := publicHTTPClient0159(baseGuess, allowHTTP)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, 0, err
	}
	path := filepath.Join(downloadDir, publicProductionDeliveryMatrixFile0159)
	bytes, err := downloadPublicAsset0159(ctx, client, matrixURL, path, "", 0)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, bytes, err
	}
	matrix, err := readPublicProductionDeliveryMatrix0159(path)
	if err != nil {
		return PublicProductionDeliveryMatrix0159{}, bytes, err
	}
	base, err := normalizePublicBaseURL0159(matrix.BaseURL, allowHTTP)
	if err != nil || base != baseGuess {
		return PublicProductionDeliveryMatrix0159{}, bytes, errors.New("матрица URL и встроенный baseUrl делать не соответствовать")
	}
	return matrix, bytes, nil
}

func runPublicProductionDeliveryE2E0159(ctx context.Context, matrixURL, rootPublicKey, currentTrustPolicy, trustState, downloadDir string, allowHTTP bool) (PublicDeliveryE2EReport0159, error) {
	start := time.Now().UTC()
	report := PublicDeliveryE2EReport0159{SchemaVersion: "1.0", Product: "NeverLauncher", MatrixURL: matrixURL, StartedAt: start.Format(time.RFC3339Nano), Status: "failed"}
	if strings.TrimSpace(downloadDir) == "" {
		return report, errors.New("публичный E2E требует --загрузка-dir")
	}
	if st, err := os.Stat(downloadDir); err == nil && st.IsDir() {
		items, _ := os.ReadDir(downloadDir)
		if len(items) != 0 {
			return report, errors.New("публичный E2E загрузка каталог должен быть пустой")
		}
	} else if err := os.MkdirAll(downloadDir, 0o755); err != nil {
		return report, err
	}
	matrix, matrixBytes, err := fetchPublicMatrix0159(ctx, matrixURL, downloadDir, allowHTTP)
	report.DownloadedBytes += matrixBytes
	if err != nil {
		return report, err
	}
	report.Downloaded++
	report.Version, report.BaseURL = matrix.Version, matrix.BaseURL
	client, err := publicHTTPClient0159(matrix.BaseURL, allowHTTP)
	if err != nil {
		return report, err
	}
	for _, asset := range matrix.Assets {
		bytes, err := downloadPublicAsset0159(ctx, client, asset.URL, filepath.Join(downloadDir, asset.Name), asset.SHA256, asset.Size)
		report.DownloadedBytes += bytes
		if err != nil {
			return report, err
		}
		report.Downloaded++
	}
	for _, control := range matrix.Controls {
		if control.Name == publicProductionDeliveryMatrixFile0159 {
			continue
		}
		expectedSHA := ""
		expectedSize := int64(0)
		if control.Name == deliveryManifestFile0151 {
			expectedSHA = matrix.DeliveryManifestSHA256
		}
		bytes, err := downloadPublicAsset0159(ctx, client, control.URL, filepath.Join(downloadDir, control.Name), expectedSHA, expectedSize)
		report.DownloadedBytes += bytes
		if err != nil {
			return report, err
		}
		report.Downloaded++
	}
	if err := validatePublicProductionDeliveryMatrix0159(downloadDir, matrix, matrix.Version, allowHTTP); err != nil {
		return report, err
	}
	absDownload, err := filepath.Abs(downloadDir)
	if err != nil {
		return report, err
	}
	for label, candidate := range map[string]string{"root public key": rootPublicKey, "current trust policy": currentTrustPolicy, "trust state": trustState} {
		if strings.TrimSpace(candidate) == "" {
			return report, fmt.Errorf("публичный E2E требует внешний %s", label)
		}
		absCandidate, err := filepath.Abs(candidate)
		if err == nil && (absCandidate == absDownload || strings.HasPrefix(absCandidate, absDownload+string(os.PathSeparator))) {
			return report, fmt.Errorf("публичный E2E %s должен быть вне загрузка комплект", label)
		}
	}
	if err := verifyReleaseBundleWithTrust(downloadDir, rootPublicKey, trustState, currentTrustPolicy); err != nil {
		return report, fmt.Errorf("загрузка публичный релиз проверка: %w", err)
	}
	if productionDeliveryReleaseRequired0160(matrix.Version) {
		if err := verifyProductionDeliveryRelease0160(downloadDir, matrix.Version, true); err != nil {
			return report, fmt.Errorf("загрузка Рабочий Доставка Сертификация релиза: %w", err)
		}
		report.ProductionDeliveryReleaseVerified = true
	}
	for _, target := range matrix.Targets {
		report.Targets = append(report.Targets, DeliveryTarget{Platform: target.Platform, Architecture: target.Architecture})
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.Status = "ok"
	return report, nil
}
