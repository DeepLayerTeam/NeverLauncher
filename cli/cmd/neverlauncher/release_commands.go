package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func handleRelease(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные release-подкоманды: doctor, plan, build, package, verify, sign, publish-plan, publish-check")
	}
	switch args[0] {
	case "doctor":
		return releaseDoctor()
	case "plan":
		ver := flagValue(args, "--version", version)
		out := flagValue(args, "--output", "")
		plan := releasePlan(ver)
		if out != "" {
			return writeJSONFile(out, plan)
		}
		printJSON(plan)
		return nil
	case "build", "package":
		ver := flagValue(args, "--version", version)
		out := flagValue(args, "--out", filepath.Join("dist", "release-"+ver))
		if err := buildReleaseBundle(
			ver, out, flagValue(args, "--source-root", "."),
			flagValue(args, "--compatibility-matrix", ""),
			flagValue(args, "--compatibility-targets", "compatibility/targets.json"),
			flagValue(args, "--device-trust-matrix", ""),
			flagValue(args, "--device-trust-targets", "device-trust/targets.json"),
			flagValue(args, "--guard-ci-matrix", ""),
			flagValue(args, "--guard-ci-targets", "guard-ci/targets.json"),
			flagValue(args, "--source-commit", ""),
		); err != nil {
			return err
		}
		fmt.Printf("Каталог release bundle подготовлен: %s\n", out)
		return nil
	case "verify", "publish-check":
		if len(args) < 2 {
			return errors.New("нужно указать каталог релиза")
		}
		publicKey := flagValue(args, "--public-key", "")
		if err := verifyReleaseBundle(args[1], publicKey); err != nil {
			return err
		}
		if err := ensurePublicKeyNotRevoked(flagValue(args, "--registry-dir", ""), publicKey); err != nil {
			return err
		}
		if args[0] == "publish-check" {
			manifestVersion, err := releaseBundleVersion(args[1])
			if err != nil {
				return err
			}
			if compatibilityCertificationRequired(manifestVersion) {
				if err := verifyCompatibilityCertificationInBundle(args[1], manifestVersion); err != nil {
					return fmt.Errorf("Minecraft compatibility certification: %w", err)
				}
			}
			if deviceTrustCertificationRequired(manifestVersion) {
				if err := verifyDeviceTrustCertificationInBundle(args[1], manifestVersion); err != nil {
					return fmt.Errorf("Device Trust certification: %w", err)
				}
			}
			if guardCICertificationRequired(manifestVersion) {
				if err := verifyGuardCICertificationInBundle(args[1], manifestVersion); err != nil {
					return fmt.Errorf("Cross-platform Guard CI certification: %w", err)
				}
			}
			fmt.Println("Release publish-check пройден: bundle cryptography + Minecraft compatibility + Device Trust + cross-platform Guard CI certification")
			return nil
		}
		fmt.Println("Release bundle полностью проверен: required artifacts, SHA-256, Ed25519 release signature и provenance attestation")
		return nil
	case "sign":
		if len(args) < 2 {
			return errors.New("release sign требует путь к каталогу релиза")
		}
		if err := signReleaseBundle(args[1], flagValue(args, "--private-key", "")); err != nil {
			return err
		}
		fmt.Println("SHA256SUMS.sig создан с Ed25519")
		return nil
	case "publish-plan":
		ver := flagValue(args, "--version", version)
		out := flagValue(args, "--output", "")
		artifacts := append([]string{}, releaseArtifacts(ver)...)
		if compatibilityCertificationRequired(ver) {
			artifacts = append(artifacts, compatibilityTargetsReleaseFile, compatibilityMatrixReleaseFile, compatibilityCertificationReleaseFile)
		}
		if deviceTrustCertificationRequired(ver) {
			artifacts = append(artifacts, deviceTrustTargetsReleaseFile, deviceTrustMatrixReleaseFile, deviceTrustCertificationReleaseFile)
		}
		if guardCICertificationRequired(ver) {
			artifacts = append(artifacts, guardCITargetsReleaseFile, guardCIMatrixReleaseFile, guardCICertificationReleaseFile)
		}
		plan := map[string]any{
			"schemaVersion": "1.0",
			"version":       ver,
			"platform":      "release artifacts",
			"steps": []string{
				"проверить VERSION, CHANGELOG.md и README.md",
				"запустить release doctor",
				"собрать release bundle",
				"проверить RELEASE_MANIFEST.json и SHA256SUMS",
				"создать SHA256SUMS.sig",
				"загрузить артефакты в release bundle",
			},
			"artifacts": artifacts,
		}
		if out != "" {
			return writeJSONFile(out, plan)
		}
		printJSON(plan)
		return nil
	default:
		return fmt.Errorf("неизвестная release-подкоманда: %s", args[0])
	}
}

func releaseDoctor() error {
	checks := map[string]string{}
	required := []string{
		"VERSION",
		"schemas/openapi.yaml",
		"scripts/contracts/validate-openapi.py",
		"scripts/release/preflight.sh",
		"scripts/smoke/offline/repository-policy.py",
		"scripts/release/build-release.sh",
		"scripts/release/source-package.py",
		"scripts/release/secret-scan.py",
		"scripts/release/zip-dir.py",
		"scripts/smoke/release-required/release-bundle.sh",
		"deploy/production/docker-compose.yml",
		"deploy/production/TLS.md",
		"apps/admin/Dockerfile",
		"runtime/neverruntime/Cargo.toml",
		"e2e/scripts/run-minecraft-e2e.sh",
		"compatibility/targets.json",
		"scripts/compatibility/matrix.py",
		".github/workflows/compatibility.yml",
		"guard-ci/targets.json",
		"scripts/guard_ci/matrix.py",
		"scripts/guard_ci/stage_release.py",
		"scripts/smoke/offline/guard-migration-compatibility-stabilization-01310.py",
		"scripts/smoke/offline/neverguard-release-0140.py",
		"scripts/smoke/offline/serverbridge-crypto-node-identities-0142.py",
		"scripts/release/merge-guard-release-policy.py",
		"e2e/scripts/run-guard-migration-e2e.sh",
	}
	failed := false
	for _, path := range required {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			checks[path] = "ok"
		} else {
			checks[path] = "missing"
			failed = true
		}
	}
	canonicalVersion := ""
	if data, err := os.ReadFile("VERSION"); err == nil {
		canonicalVersion = strings.TrimSpace(string(data))
	}
	if canonicalVersion != "" {
		checks["version-alignment"] = "ok"
	} else {
		checks["version-alignment"] = "missing"
		failed = true
	}
	if data, err := os.ReadFile("schemas/openapi.yaml"); err == nil {
		if problems := canonicalOpenAPIErrors(data); len(problems) == 0 {
			checks["canonical-openapi"] = "ok"
		} else {
			checks["canonical-openapi"] = "invalid: " + strings.Join(problems, "; ")
			failed = true
		}
	} else {
		checks["canonical-openapi"] = "invalid: " + err.Error()
		failed = true
	}
	for id, command := range map[string][]string{
		"repository-policy":     {"python3", "scripts/smoke/offline/repository-policy.py"},
		"version-alignment":     {"bash", "scripts/smoke/offline/version-alignment.sh"},
		"openapi-validator":     {"python3", "scripts/contracts/validate-openapi.py"},
		"compatibility-targets": {"python3", "scripts/compatibility/matrix.py", "validate", "--targets", "compatibility/targets.json"},
		"device-trust-targets":  {"python3", "scripts/device_trust/matrix.py", "validate", "--targets", "device-trust/targets.json"},
		"guard-ci-targets":      {"python3", "scripts/guard_ci/matrix.py", "validate", "--targets", "guard-ci/targets.json"},
		"guard-stabilization":   {"python3", "scripts/smoke/offline/guard-migration-compatibility-stabilization-01310.py"},
		"neverguard-release":    {"python3", "scripts/smoke/offline/neverguard-release-0140.py"},
		"serverbridge-identity": {"python3", "scripts/smoke/offline/serverbridge-crypto-node-identities-0142.py"},
	} {
		cmd := exec.Command(command[0], command[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			checks[id] = "failed: " + strings.TrimSpace(string(output))
			failed = true
		} else {
			checks[id] = "ok"
		}
	}
	status := "repository-policy-ready"
	if failed {
		status = "failed"
	}
	reportedVersion := canonicalVersion
	if reportedVersion == "" {
		reportedVersion = version
	}
	printJSON(map[string]any{"version": reportedVersion, "status": status, "productionReady": false, "next": "NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh", "checks": checks})
	if failed {
		return errors.New("release doctor обнаружил отсутствующие или несогласованные production-компоненты")
	}
	return nil
}

func releasePlan(ver string) map[string]any {
	return map[string]any{
		"schemaVersion": "1.0",
		"version":       ver,
		"createdAt":     time.Now().UTC().Format(time.RFC3339),
		"mode":          "production-release-automation",
		"artifacts":     releaseArtifacts(ver),
		"checks":        []string{"release doctor", "go test cli", "go test backend", "release verify", "release sign"},
	}
}

func desktopBackendArgs(args []string) (backend, project, profile, channel, ver string) {
	backend = strings.TrimRight(flagValue(args, "--backend", "http://127.0.0.1:8080"), "/")
	project = flagValue(args, "--project", "")
	profile = flagValue(args, "--profile", "")
	channel = flagValue(args, "--channel", "stable")
	ver = flagValue(args, "--version", "latest")
	return
}

func desktopConfigModel(args []string) map[string]any {
	_, project, profile, channel, _ := desktopBackendArgs(args)
	return map[string]any{
		"schemaVersion": "0.8.8",
		"toolVersion":   version,
		"mode":          "desktop-persisted-config",
		"status":        "product-config",
		"configPath":    "NeverLauncher/config.json",
		"projectId":     project,
		"profileId":     profile,
		"channel":       channel,
		"fields":        []string{"backendUrl", "projectId", "profileId", "channel", "gameDirectory", "javaPath", "username", "memoryMb", "pinnedPublicKey"},
		"secrets":       []string{"accessToken", "refreshToken", "password"},
		"secretPolicy":  "tokens must be stored in secure storage; config.json never contains plaintext tokens",
	}
}

func httpJSON(method, url string, body any) (map[string]any, error) {
	return httpJSONWithAuth(method, url, body, "")
}

func httpJSONWithHeaders(method, url string, body any, headers map[string]string) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		if strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{}
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, fmt.Errorf("invalid JSON response from %s: %w", url, err)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return payload, fmt.Errorf("%s returned %s: %s", url, resp.Status, strings.TrimSpace(string(data)))
	}
	return payload, nil
}

func httpJSONWithAuth(method, url string, body any, token string) (map[string]any, error) {
	headers := map[string]string{}
	if strings.TrimSpace(token) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(token)
	}
	return httpJSONWithHeaders(method, url, body, headers)
}

func publishTransactionPlan(kind, subject, channel, releaseVersion string) map[string]any {
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"kind":          kind,
		"subject":       subject,
		"channel":       channel,
		"version":       releaseVersion,
		"status":        "transaction-plan",
		"transaction":   []string{"BEGIN", "lock project/channel", "validate profile and manifest", "insert version draft", "attach storage objects", "write audit event", "promote channel pointer", "COMMIT"},
		"rollback":      []string{"ROLLBACK on validation error", "do not move channel pointer", "keep previous published version immutable"},
	}
}

func productionTables() []string {
	return []string{"schema_migrations", "projects", "profiles", "release_channels", "release_versions", "files", "storage_objects", "users", "roles", "admin_sessions", "project_user_roles", "audit_events", "telemetry_events", "crash_reports", "extensions", "registry_entries", "desktop_packages"}
}

func buildReleaseBundle(ver, out, sourceRoot, compatibilityMatrixPath, compatibilityTargetsPath, deviceTrustMatrixPath, deviceTrustTargetsPath, guardCIMatrixPath, guardCITargetsPath, expectedCommit string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if strings.TrimSpace(compatibilityMatrixPath) != "" {
		if !filepath.IsAbs(compatibilityTargetsPath) {
			compatibilityTargetsPath = filepath.Join(sourceRoot, compatibilityTargetsPath)
		}
		if err := embedCompatibilityCertification(out, compatibilityMatrixPath, compatibilityTargetsPath, ver, expectedCommit); err != nil {
			return fmt.Errorf("compatibility certification: %w", err)
		}
	}
	if strings.TrimSpace(deviceTrustMatrixPath) != "" {
		if !filepath.IsAbs(deviceTrustTargetsPath) {
			deviceTrustTargetsPath = filepath.Join(sourceRoot, deviceTrustTargetsPath)
		}
		if err := embedDeviceTrustCertification(out, deviceTrustMatrixPath, deviceTrustTargetsPath, ver, expectedCommit); err != nil {
			return fmt.Errorf("Device Trust certification: %w", err)
		}
	}
	if strings.TrimSpace(guardCIMatrixPath) != "" {
		if !filepath.IsAbs(guardCITargetsPath) {
			guardCITargetsPath = filepath.Join(sourceRoot, guardCITargetsPath)
		}
		if err := embedGuardCICertification(out, guardCIMatrixPath, guardCITargetsPath, ver, expectedCommit); err != nil {
			return fmt.Errorf("Cross-platform Guard CI certification: %w", err)
		}
	}
	sbom, err := dependencySBOM(sourceRoot, ver)
	if err != nil {
		return fmt.Errorf("dependency SBOM: %w", err)
	}
	if err := writeJSONFile(filepath.Join(out, "SBOM.spdx.json"), sbom); err != nil {
		return err
	}
	provenance, err := slsaProvenance(sourceRoot, out, ver)
	if err != nil {
		return fmt.Errorf("SLSA provenance: %w", err)
	}
	if err := writeJSONFile(filepath.Join(out, "PROVENANCE.json"), provenance); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "RELEASE_NOTES.txt"), []byte(releaseDescription(ver)), 0o644); err != nil {
		return err
	}

	entries := releaseBundleEntries(ver, out)
	requiredFiles := []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SBOM.spdx.json", "PROVENANCE.json", "RELEASE_NOTES.txt"}
	checks := []string{"required-artifacts", "sha256", "ed25519-external-trust", "sbom", "provenance", "release-notes", "source-secret-scan"}
	compatibilityCertified := false
	if _, err := os.Stat(filepath.Join(out, compatibilityCertificationReleaseFile)); err == nil {
		requiredFiles = append(requiredFiles, compatibilityTargetsReleaseFile, compatibilityMatrixReleaseFile, compatibilityCertificationReleaseFile)
		checks = append(checks, "minecraft-compatibility-certification")
		compatibilityCertified = true
	}
	deviceTrustCertified := false
	if _, err := os.Stat(filepath.Join(out, deviceTrustCertificationReleaseFile)); err == nil {
		requiredFiles = append(requiredFiles, deviceTrustTargetsReleaseFile, deviceTrustMatrixReleaseFile, deviceTrustCertificationReleaseFile)
		checks = append(checks, "device-trust-certification")
		deviceTrustCertified = true
	}
	guardCICertified := false
	if _, err := os.Stat(filepath.Join(out, guardCICertificationReleaseFile)); err == nil {
		requiredFiles = append(requiredFiles, guardCITargetsReleaseFile, guardCIMatrixReleaseFile, guardCICertificationReleaseFile)
		checks = append(checks, "cross-platform-guard-ci-certification")
		guardCICertified = true
	}
	manifest := map[string]any{
		"schemaVersion":          cliSchemaVersion,
		"name":                   "NeverLauncher",
		"version":                ver,
		"createdAt":              time.Now().UTC().Format(time.RFC3339),
		"mode":                   "release-pipeline",
		"artifacts":              entries,
		"checks":                 checks,
		"requiredFiles":          requiredFiles,
		"compatibilityCertified": compatibilityCertified,
		"deviceTrustCertified":   deviceTrustCertified,
		"guardCICertified":       guardCICertified,
	}
	if err := writeJSONFile(filepath.Join(out, "RELEASE_MANIFEST.json"), manifest); err != nil {
		return err
	}

	checksums, err := releaseChecksums(out)
	if err != nil {
		return err
	}
	if len(checksums) == 0 {
		return errors.New("release bundle не содержит файлов для SHA256SUMS")
	}
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(strings.Join(checksums, "\n")+"\n"), 0o644)
}

func releaseBundleEntries(ver, out string) []map[string]any {
	known := map[string]bool{}
	var entries []map[string]any
	requiredNames := append([]string{}, releaseArtifacts(ver)...)
	if _, err := os.Stat(filepath.Join(out, compatibilityCertificationReleaseFile)); err == nil {
		requiredNames = append(requiredNames, compatibilityTargetsReleaseFile, compatibilityMatrixReleaseFile, compatibilityCertificationReleaseFile)
	}
	if _, err := os.Stat(filepath.Join(out, deviceTrustCertificationReleaseFile)); err == nil {
		requiredNames = append(requiredNames, deviceTrustTargetsReleaseFile, deviceTrustMatrixReleaseFile, deviceTrustCertificationReleaseFile)
	}
	if _, err := os.Stat(filepath.Join(out, guardCICertificationReleaseFile)); err == nil {
		requiredNames = append(requiredNames, guardCITargetsReleaseFile, guardCIMatrixReleaseFile, guardCICertificationReleaseFile)
		requiredNames = append(requiredNames, guardCIArtifactNamesFromBundle(out)...)
	}
	for _, name := range requiredNames {
		known[name] = true
		entry := map[string]any{"name": name, "required": true, "status": "missing"}
		path := filepath.Join(out, name)
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			if sum, size, err := hashFile(path); err == nil {
				entry["status"] = "present"
				entry["size"] = size
				entry["sha256"] = sum
			}
		}
		entries = append(entries, entry)
	}
	if items, err := os.ReadDir(out); err == nil {
		for _, item := range items {
			name := item.Name()
			if item.IsDir() || known[name] || name == "SHA256SUMS" || name == "SHA256SUMS.sig" {
				continue
			}
			path := filepath.Join(out, name)
			if sum, size, err := hashFile(path); err == nil {
				entries = append(entries, map[string]any{"name": name, "required": false, "status": "present", "size": size, "sha256": sum})
			}
		}
	}
	return entries
}

func releaseChecksums(dir string) ([]string, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, item := range items {
		name := item.Name()
		if item.IsDir() || name == "SHA256SUMS" || name == "SHA256SUMS.sig" {
			continue
		}
		sum, _, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		lines = append(lines, sum+"  "+name)
	}
	return lines, nil
}

func verifyReleaseBundle(dir, publicKeyPath string) error {
	for _, name := range []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "RELEASE_NOTES.txt", "SBOM.spdx.json", "PROVENANCE.json", "PROVENANCE.json.sig"} {
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.IsDir() {
			return fmt.Errorf("не найден обязательный release file %s", name)
		}
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
	if err != nil {
		return err
	}
	var manifest struct {
		Version   string `json:"version"`
		Artifacts []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Status   string `json:"status"`
			SHA256   string `json:"sha256"`
			Size     int64  `json:"size"`
		} `json:"artifacts"`
		RequiredFiles []string `json:"requiredFiles"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return fmt.Errorf("RELEASE_MANIFEST.json invalid: %w", err)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return errors.New("RELEASE_MANIFEST.json не содержит version")
	}
	for _, name := range manifest.RequiredFiles {
		if st, err := os.Stat(filepath.Join(dir, filepath.Clean(name))); err != nil || st.IsDir() {
			return fmt.Errorf("requiredFiles содержит отсутствующий файл %s", name)
		}
	}
	requiredCount := 0
	for _, artifact := range manifest.Artifacts {
		if !artifact.Required {
			continue
		}
		requiredCount++
		if artifact.Status != "present" {
			return fmt.Errorf("required artifact %s имеет status=%s вместо present", artifact.Name, artifact.Status)
		}
		path := filepath.Join(dir, filepath.Clean(artifact.Name))
		actual, size, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("required artifact %s отсутствует или unreadable: %w", artifact.Name, err)
		}
		if artifact.Size > 0 && artifact.Size != size {
			return fmt.Errorf("required artifact %s size mismatch: manifest=%d actual=%d", artifact.Name, artifact.Size, size)
		}
		if artifact.SHA256 == "" || !strings.EqualFold(artifact.SHA256, actual) {
			return fmt.Errorf("required artifact %s sha256 mismatch", artifact.Name)
		}
	}
	if requiredCount == 0 {
		return errors.New("RELEASE_MANIFEST.json не содержит required artifacts")
	}
	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	verified := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return fmt.Errorf("некорректная строка SHA256SUMS: %s", line)
		}
		expected, name := parts[0], parts[1]
		actual, _, err := hashFile(filepath.Join(dir, filepath.Clean(name)))
		if err != nil {
			return fmt.Errorf("не удалось проверить %s: %w", name, err)
		}
		if !strings.EqualFold(actual, expected) {
			return fmt.Errorf("checksum mismatch для %s", name)
		}
		verified++
	}
	if verified == 0 {
		return errors.New("SHA256SUMS не содержит проверяемых файлов")
	}
	return verifyReleaseSignature(dir, publicKeyPath)
}

func releaseArtifacts(ver string) []string {
	artifacts := []string{
		"neverlauncher-source-" + ver + ".zip",
		"neverlauncher-cli-linux-amd64",
		"neverlauncher-cli-windows-amd64.exe",
		"neverlauncher-api-linux-amd64",
		"neverlauncher-admin-web-" + ver + ".zip",
		"neverlauncher-desktop-web-" + ver + ".zip",
		"neverlauncher-desktop-linux-amd64",
		"neverlauncher-desktop-package-" + ver + ".zip",
		"neverruntime-linux-amd64",
		"neverlauncher-velocity-bridge-" + ver + ".jar",
		"neverlauncher-bungeecord-bridge-" + ver + ".jar",
		"neverlauncher-waterfall-bridge-" + ver + ".jar",
		"neverlauncher-bukkit-bridge-" + ver + ".jar",
		"neverlauncher-spigot-bridge-" + ver + ".jar",
		"neverlauncher-paper-bridge-" + ver + ".jar",
		"neverlauncher-purpur-bridge-" + ver + ".jar",
		"neverlauncher-folia-bridge-" + ver + ".jar",
		"BRIDGE_RELEASE_ALLOWLIST.json",
		"BRIDGE_PLUGIN_MANIFEST.json",
		"SBOM.spdx.json",
		"PROVENANCE.json",
		"RELEASE_NOTES.txt",
	}
	if guardCICertificationRequired(ver) {
		for _, osName := range []string{"linux", "windows", "macos"} {
			names := expectedGuardArtifactNames0139(osName, ver)
			for _, role := range []string{"package", "launcher", "guard", "manifest", "allowlist"} {
				name := names[role]
				found := false
				for _, existing := range artifacts {
					if existing == name {
						found = true
						break
					}
				}
				if !found {
					artifacts = append(artifacts, name)
				}
			}
		}
	}
	return artifacts
}

func releaseBundleVersion(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
	if err != nil {
		return "", err
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Version) == "" {
		return "", errors.New("RELEASE_MANIFEST.json не содержит version")
	}
	return strings.TrimSpace(payload.Version), nil
}

func releaseDescription(ver string) string {
	extra := ""
	if compatibilityCertificationRequired(ver) {
		extra = "\n- официальный publish-check требует COMPATIBILITY_TARGETS/MATRIX/CERTIFICATION, привязанные к той же версии и source commit;"
	}
	if deviceTrustCertificationRequired(ver) {
		extra += "\n- начиная с 0.13.0 официальный publish-check также требует DEVICE_TRUST_TARGETS/MATRIX/CERTIFICATION для того же product version и source commit;"
	}
	if guardCICertificationRequired(ver) {
		extra += "\n- начиная с 0.13.9 publish-check требует cross-platform GUARD_CI_TARGETS/MATRIX/CERTIFICATION и повторно сверяет exact Windows/Linux/macOS Guard artifacts по SHA-256;"
	}
	return fmt.Sprintf("# NeverLauncher %s — Release Pipeline\n\n"+
		"NeverLauncher %s закрепляет воспроизводимый release pipeline для release artifacts.\n\n"+
		"Основное:\n"+
		"- единый build-release сценарий для CLI, Backend API, Admin Web, Desktop Web/native, NeverRuntime и ServerBridge;\n"+
		"- фактический SHA256SUMS вместо декларативных placeholder-комментариев;\n"+
		"- SBOM.spdx.json, PROVENANCE.json и RELEASE_MANIFEST.json в каждом release bundle;\n"+
		"- проверка release bundle через nl release verify;\n"+
		"- Ed25519-подпись SHA256SUMS и отдельная signed SLSA provenance attestation с внешним trust anchor;\n"+
		"- source package формируется только из git-tracked/allowlisted файлов и проходит secret scan.%s", ver, ver, extra)
}

func buildManifest(root, project, profile, ver string) (Manifest, error) {
	var files []ManifestFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		files = append(files, ManifestFile{Path: filepath.ToSlash(rel), Size: size, SHA256: sum, URL: "", Required: true})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{SchemaVersion: "1.0", ProjectID: project, ProfileID: profile, Channel: "stable", Version: ver, CreatedAt: time.Now().UTC().Format(time.RFC3339), Files: files}, nil
}

func buildManifestDiff(oldManifest, newManifest Manifest) ManifestDiff {
	oldFiles := indexManifestFiles(oldManifest.Files)
	newFiles := indexManifestFiles(newManifest.Files)
	diff := ManifestDiff{FromVersion: oldManifest.Version, ToVersion: newManifest.Version}

	for path, newFile := range newFiles {
		oldFile, exists := oldFiles[path]
		switch {
		case !exists:
			diff.Added = append(diff.Added, newFile)
			diff.TotalDownloadSize += newFile.Size
		case oldFile.SHA256 != newFile.SHA256 || oldFile.Size != newFile.Size:
			diff.Changed = append(diff.Changed, newFile)
			diff.TotalDownloadSize += newFile.Size
		default:
			diff.Unchanged = append(diff.Unchanged, path)
		}
	}
	for path := range oldFiles {
		if _, exists := newFiles[path]; !exists {
			diff.Deleted = append(diff.Deleted, path)
		}
	}
	return diff
}

func buildUpdatePlan(oldManifest, newManifest Manifest) UpdatePlan {
	diff := buildManifestDiff(oldManifest, newManifest)
	plan := UpdatePlan{
		FromVersion:       oldManifest.Version,
		ToVersion:         newManifest.Version,
		Download:          append(diff.Added, diff.Changed...),
		Delete:            diff.Deleted,
		Keep:              diff.Unchanged,
		Verify:            diff.Unchanged,
		TotalDownloadSize: diff.TotalDownloadSize,
		ResumeDownloads:   true,
		MaxParallel:       4,
	}
	for _, file := range plan.Download {
		plan.Verify = append(plan.Verify, file.Path)
	}
	return plan
}

func indexManifestFiles(files []ManifestFile) map[string]ManifestFile {
	result := make(map[string]ManifestFile, len(files))
	for _, file := range files {
		result[file.Path] = file
	}
	return result
}

func readManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	if manifest.ProjectID == "" || manifest.ProfileID == "" || manifest.Version == "" {
		return Manifest{}, errors.New("manifest не содержит обязательные поля projectId, profileId или version")
	}
	return manifest, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func writeJSONFile(path string, value any) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func printJSON(value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Println("{}")
		return
	}
	fmt.Println(string(data))
}

func flagValue(args []string, name, fallback string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"=")
		}
	}
	return fallback
}

func flagBool(args []string, name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(flagValue(args, name, "")))
	if value == "" {
		for _, arg := range args {
			if arg == name {
				return true
			}
		}
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
