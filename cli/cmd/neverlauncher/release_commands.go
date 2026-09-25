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
		if releaseVerificationV2Required0158(ver) {
			policySource := flagValue(args, "--trust-policy", strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE")))
			if policySource == "" {
				return errors.New("0.15.8+ release build требует --trust-policy или NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE")
			}
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			raw, err := os.ReadFile(policySource)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(out, releaseTrustPolicyFile0158), raw, 0o644); err != nil {
				return err
			}
		}
		if err := buildReleaseBundle(
			ver, out, flagValue(args, "--source-root", "."),
			flagValue(args, "--compatibility-matrix", ""),
			flagValue(args, "--compatibility-targets", "compatibility/targets.json"),
			flagValue(args, "--device-trust-matrix", ""),
			flagValue(args, "--device-trust-targets", "device-trust/targets.json"),
			flagValue(args, "--guard-ci-matrix", ""),
			flagValue(args, "--guard-ci-targets", "guard-ci/targets.json"),
			flagValue(args, "--source-commit", ""),
			flagValue(args, "--public-base-url", strings.TrimSpace(os.Getenv("NEVERLAUNCHER_PUBLIC_RELEASE_BASE_URL"))),
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
		trustState := flagValue(args, "--trust-state", strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE")))
		trustPolicy := flagValue(args, "--trust-policy", strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE")))
		if err := verifyReleaseBundleWithTrust(args[1], publicKey, trustState, trustPolicy); err != nil {
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
			if serverBridge2CertificationRequired0150(manifestVersion) {
				if err := verifyServerBridge2CertificationInBundle0150(args[1], manifestVersion); err != nil {
					return fmt.Errorf("ServerBridge 2 certification: %w", err)
				}
			}
			if windowsSigningRequired0152(manifestVersion) {
				if err := verifyWindowsSigningEvidence0152(args[1], manifestVersion, true); err != nil {
					return fmt.Errorf("Windows x64/ARM64 Authenticode signing: %w", err)
				}
			}
			if linuxProductionRequired0153(manifestVersion) {
				if err := verifyLinuxProductionEvidence0153(args[1], manifestVersion, true); err != nil {
					return fmt.Errorf("Linux x64/ARM64 production packages: %w", err)
				}
			}
			if macOSProductionRequired0154(manifestVersion) {
				if err := verifyMacOSNotarizationEvidence0154(args[1], manifestVersion, true); err != nil {
					return fmt.Errorf("macOS x64/ARM64 Developer ID notarization: %w", err)
				}
			}
			if managedJREDistributionRequired0155(manifestVersion) {
				if err := verifyManagedJREDistribution0155(args[1], manifestVersion, true); err != nil {
					return fmt.Errorf("Managed JRE Distribution: %w", err)
				}
			}
			if updaterVersionAtLeast0156(manifestVersion) {
				report, err := runUpdaterSelfTest0156()
				if err != nil {
					return fmt.Errorf("Unified Transactional Updater Core self-test: %w", err)
				}
				if fmt.Sprint(report["status"]) != "ok" {
					return fmt.Errorf("Unified Transactional Updater Core self-test status=%v", report["status"])
				}
			}
			if componentTransactionalUpdateRequired0157(manifestVersion) {
				report, err := runComponentUpdaterSelfTest0157()
				if err != nil {
					return fmt.Errorf("Desktop/Guard/Runtime transactional update self-test: %w", err)
				}
				if fmt.Sprint(report["status"]) != "ok" || fmt.Sprint(report["macosTreeRollback"]) != "ok" {
					return fmt.Errorf("Desktop/Guard/Runtime transactional update self-test incomplete: %v", report)
				}
			}
			if migrationStabilizationRequired01510(manifestVersion) {
				report, err := runMigrationStabilizationSelfTest01510()
				if err != nil {
					return fmt.Errorf("0.15.10 migration + stabilization self-test: %w", err)
				}
				if fmt.Sprint(report["status"]) != "ok" {
					return fmt.Errorf("0.15.10 migration + stabilization self-test status=%v", report["status"])
				}
			}
			fmt.Println("Release publish-check пройден: Release Verification v2 trust/key lifecycle + bundle cryptography + certifications + ServerBridge 2 + Windows/Linux/macOS production delivery + Managed JRE Distribution + Unified Transactional Updater Core + Desktop/Guard/Runtime transactional update + Public Production Delivery Matrix + migration stabilization")
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
		fmt.Println("SHA256SUMS.sig создан с Ed25519 (Release Verification v2 для 0.15.8+)")
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
		"scripts/smoke/offline/delivery-manifest-platform-architecture-0151.py",
		"scripts/smoke/offline/signed-windows-x64-arm64-0152.py",
		"scripts/smoke/offline/linux-x64-arm64-production-packages-0153.py",
		"scripts/smoke/offline/notarized-macos-x64-arm64-0154.py",
		"scripts/smoke/offline/managed-jre-distribution-0155.py",
		"scripts/smoke/offline/unified-transactional-updater-core-0156.py",
		"scripts/smoke/offline/desktop-guard-runtime-transactional-update-0157.py",
		"scripts/smoke/offline/release-verification-v2-trust-lifecycle-0158.py",
		"scripts/smoke/offline/public-production-delivery-matrix-e2e-0159.py",
		"scripts/smoke/offline/migration-stabilization-01510.py",
		".github/workflows/public-production-delivery.yml",
		"scripts/release/managed-jre-distribution.py",
		"scripts/release/build-linux-production.sh",
		"scripts/release/linux-package.py",
		"scripts/release/build-macos-production.sh",
		"scripts/release/macos-package.py",
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
		"repository-policy":              {"python3", "scripts/smoke/offline/repository-policy.py"},
		"version-alignment":              {"bash", "scripts/smoke/offline/version-alignment.sh"},
		"openapi-validator":              {"python3", "scripts/contracts/validate-openapi.py"},
		"compatibility-targets":          {"python3", "scripts/compatibility/matrix.py", "validate", "--targets", "compatibility/targets.json"},
		"device-trust-targets":           {"python3", "scripts/device_trust/matrix.py", "validate", "--targets", "device-trust/targets.json"},
		"guard-ci-targets":               {"python3", "scripts/guard_ci/matrix.py", "validate", "--targets", "guard-ci/targets.json"},
		"guard-stabilization":            {"python3", "scripts/smoke/offline/guard-migration-compatibility-stabilization-01310.py"},
		"neverguard-release":             {"python3", "scripts/smoke/offline/neverguard-release-0140.py"},
		"serverbridge-identity":          {"python3", "scripts/smoke/offline/serverbridge-crypto-node-identities-0142.py"},
		"delivery-manifest":              {"python3", "scripts/smoke/offline/delivery-manifest-platform-architecture-0151.py"},
		"windows-dual-signing":           {"python3", "scripts/smoke/offline/signed-windows-x64-arm64-0152.py"},
		"macos-dual-notarization":        {"python3", "scripts/smoke/offline/notarized-macos-x64-arm64-0154.py"},
		"managed-jre-distribution":       {"python3", "scripts/smoke/offline/managed-jre-distribution-0155.py"},
		"transactional-updater-core":     {"python3", "scripts/smoke/offline/unified-transactional-updater-core-0156.py"},
		"component-transactional-update": {"python3", "scripts/smoke/offline/desktop-guard-runtime-transactional-update-0157.py"},
		"release-verification-v2":        {"python3", "scripts/smoke/offline/release-verification-v2-trust-lifecycle-0158.py"},
		"public-production-delivery":     {"python3", "scripts/smoke/offline/public-production-delivery-matrix-e2e-0159.py"},
		"migration-stabilization":        {"python3", "scripts/smoke/offline/migration-stabilization-01510.py"},
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

func buildReleaseBundle(ver, out, sourceRoot, compatibilityMatrixPath, compatibilityTargetsPath, deviceTrustMatrixPath, deviceTrustTargetsPath, guardCIMatrixPath, guardCITargetsPath, expectedCommit, publicBaseURL string) error {
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
	if linuxProductionRequired0153(ver) {
		if err := writeLinuxProductionEvidence0153(out, ver); err != nil {
			return fmt.Errorf("Linux x64/ARM64 production evidence: %w", err)
		}
	}
	if deliveryManifestRequired0151(ver) {
		if err := writeDeliveryManifest0151(out, ver); err != nil {
			return fmt.Errorf("delivery manifest: %w", err)
		}
		if err := verifyDeliveryManifest0151(out, ver); err != nil {
			return fmt.Errorf("delivery manifest self-check: %w", err)
		}
	}
	if publicProductionDeliveryRequired0159(ver) {
		if err := writePublicProductionDeliveryMatrix0159(out, ver, publicBaseURL); err != nil {
			return fmt.Errorf("Public Production Delivery Matrix: %w", err)
		}
		if err := verifyPublicProductionDeliveryMatrix0159(out, ver); err != nil {
			return fmt.Errorf("Public Production Delivery Matrix self-check: %w", err)
		}
	}
	if windowsSigningRequired0152(ver) {
		if err := verifyWindowsSigningEvidence0152(out, ver, false); err != nil {
			return fmt.Errorf("Windows x64/ARM64 delivery evidence: %w", err)
		}
	}
	if linuxProductionRequired0153(ver) {
		if err := verifyLinuxProductionEvidence0153(out, ver, true); err != nil {
			return fmt.Errorf("Linux x64/ARM64 production evidence: %w", err)
		}
	}
	if macOSProductionRequired0154(ver) {
		if err := verifyMacOSNotarizationEvidence0154(out, ver, false); err != nil {
			return fmt.Errorf("macOS x64/ARM64 delivery evidence: %w", err)
		}
	}
	if managedJREDistributionRequired0155(ver) {
		if err := verifyManagedJREDistribution0155(out, ver, true); err != nil {
			return fmt.Errorf("Managed JRE Distribution: %w", err)
		}
	}

	entries := releaseBundleEntries(ver, out)
	requiredFiles := []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SBOM.spdx.json", "PROVENANCE.json", "RELEASE_NOTES.txt"}
	checks := []string{"required-artifacts", "sha256", "ed25519-external-trust", "sbom", "provenance", "release-notes", "source-secret-scan"}
	if deliveryManifestRequired0151(ver) {
		requiredFiles = append(requiredFiles, deliveryManifestFile0151)
		checks = append(checks, "delivery-manifest-platform-architecture")
	}
	if windowsSigningRequired0152(ver) {
		requiredFiles = append(requiredFiles, windowsSigningEvidenceFile0152)
		checks = append(checks, "windows-x64-arm64-authenticode-evidence")
	}
	if linuxProductionRequired0153(ver) {
		requiredFiles = append(requiredFiles, linuxProductionEvidenceFile0153, linuxDeliveryAllowlistFile0153, "LINUX_PACKAGE_MANIFEST_X64.json", "LINUX_PACKAGE_MANIFEST_ARM64.json")
		checks = append(checks, "linux-x64-arm64-production-packages")
	}
	if macOSProductionRequired0154(ver) {
		requiredFiles = append(requiredFiles, macOSNotarizationEvidenceFile0154, macOSDeliveryAllowlistFile0154, "MACOS_PACKAGE_MANIFEST_X64.json", "MACOS_PACKAGE_MANIFEST_ARM64.json")
		checks = append(checks, "macos-x64-arm64-developer-id-notarization")
	}
	if managedJREDistributionRequired0155(ver) {
		requiredFiles = append(requiredFiles, managedJREArtifacts0155(ver)...)
		checks = append(checks, "managed-jre-temurin21-six-target-distribution")
	}
	if updaterVersionAtLeast0156(ver) {
		checks = append(checks, "unified-transactional-updater-core")
	}
	if componentTransactionalUpdateRequired0157(ver) {
		checks = append(checks, "desktop-guard-runtime-transactional-update")
	}
	if releaseVerificationV2Required0158(ver) {
		if _, err := loadReleaseTrustPolicy0158(filepath.Join(out, releaseTrustPolicyFile0158)); err != nil {
			return fmt.Errorf("Release Verification v2 trust policy: %w", err)
		}
		requiredFiles = append(requiredFiles, releaseTrustPolicyFile0158)
		checks = append(checks, "release-verification-v2-trust-lifecycle-anti-rollback")
	}
	if publicProductionDeliveryRequired0159(ver) {
		requiredFiles = append(requiredFiles, publicProductionDeliveryMatrixFile0159)
		checks = append(checks, "public-production-delivery-matrix-six-target-e2e")
	}
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

func verifyReleaseBundleWithTrust(dir, publicKeyPath, trustStatePath, trustPolicyPath string) error {
	manifestVersion, err := releaseBundleVersion(dir)
	if err != nil {
		return err
	}
	if migrationStabilizationRequired01510(manifestVersion) {
		return withReleaseTrustStateLock01510(trustStatePath, func() error {
			return verifyReleaseBundleWithTrustUnlocked(dir, publicKeyPath, trustStatePath, trustPolicyPath)
		})
	}
	return verifyReleaseBundleWithTrustUnlocked(dir, publicKeyPath, trustStatePath, trustPolicyPath)
}

func verifyReleaseBundleWithTrustUnlocked(dir, publicKeyPath, trustStatePath, trustPolicyPath string) error {
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
	if deliveryManifestRequired0151(manifest.Version) {
		if err := verifyDeliveryManifest0151(dir, manifest.Version); err != nil {
			return fmt.Errorf("delivery manifest: %w", err)
		}
	}
	if windowsSigningRequired0152(manifest.Version) {
		if err := verifyWindowsSigningEvidence0152(dir, manifest.Version, false); err != nil {
			return fmt.Errorf("Windows x64/ARM64 delivery evidence: %w", err)
		}
	}
	if linuxProductionRequired0153(manifest.Version) {
		if err := verifyLinuxProductionEvidence0153(dir, manifest.Version, true); err != nil {
			return fmt.Errorf("Linux x64/ARM64 production evidence: %w", err)
		}
	}
	if macOSProductionRequired0154(manifest.Version) {
		if err := verifyMacOSNotarizationEvidence0154(dir, manifest.Version, false); err != nil {
			return fmt.Errorf("macOS x64/ARM64 delivery evidence: %w", err)
		}
	}
	if managedJREDistributionRequired0155(manifest.Version) {
		if err := verifyManagedJREDistribution0155(dir, manifest.Version, true); err != nil {
			return fmt.Errorf("Managed JRE Distribution: %w", err)
		}
	}
	if publicProductionDeliveryRequired0159(manifest.Version) {
		if err := verifyPublicProductionDeliveryMatrix0159(dir, manifest.Version); err != nil {
			return fmt.Errorf("Public Production Delivery Matrix: %w", err)
		}
	}
	for _, name := range manifest.RequiredFiles {
		clean, err := safeReleaseRelativePath0158(name)
		if err != nil {
			return fmt.Errorf("requiredFiles path %q invalid: %w", name, err)
		}
		if st, err := os.Stat(filepath.Join(dir, clean)); err != nil || st.IsDir() {
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
		cleanArtifact, err := safeReleaseRelativePath0158(artifact.Name)
		if err != nil {
			return fmt.Errorf("required artifact path %q invalid: %w", artifact.Name, err)
		}
		path := filepath.Join(dir, cleanArtifact)
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
		cleanName, err := safeReleaseRelativePath0158(name)
		if err != nil {
			return fmt.Errorf("SHA256SUMS path %q invalid: %w", name, err)
		}
		actual, _, err := hashFile(filepath.Join(dir, cleanName))
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
	if releaseVerificationV2Required0158(manifest.Version) {
		ctx, err := verifyReleaseSignatureV20158(dir, publicKeyPath, trustStatePath, trustPolicyPath)
		if err != nil {
			return err
		}
		if err := commitTrustState0158(ctx); err != nil {
			return fmt.Errorf("commit release trust state: %w", err)
		}
		return nil
	}
	return verifyReleaseSignature(dir, publicKeyPath)
}

func verifyReleaseBundleWithTrustState(dir, publicKeyPath, trustStatePath string) error {
	return verifyReleaseBundleWithTrust(dir, publicKeyPath, trustStatePath, strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE")))
}

func verifyReleaseBundle(dir, publicKeyPath string) error {
	return verifyReleaseBundleWithTrust(dir, publicKeyPath, strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE")), strings.TrimSpace(os.Getenv("NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE")))
}

func releaseArtifacts(ver string) []string {
	artifacts := []string{
		"neverlauncher-source-" + ver + ".zip",
		"neverlauncher-admin-web-" + ver + ".zip",
		"neverlauncher-desktop-web-" + ver + ".zip",
		"neverlauncher-desktop-package-" + ver + ".zip",
		"neverlauncher-velocity-bridge-" + ver + ".jar",
		"neverlauncher-bungeecord-bridge-" + ver + ".jar",
		"neverlauncher-waterfall-bridge-" + ver + ".jar",
		"neverlauncher-bukkit-bridge-" + ver + ".jar",
		"neverlauncher-spigot-bridge-" + ver + ".jar",
		"neverlauncher-paper-bridge-" + ver + ".jar",
		"neverlauncher-purpur-bridge-" + ver + ".jar",
		"neverlauncher-folia-bridge-" + ver + ".jar",
		"neverlauncher-fabric-bridge-" + ver + ".jar",
		"neverlauncher-forge-bridge-" + ver + ".jar",
		"neverlauncher-neoforge-bridge-" + ver + ".jar",
		"BRIDGE_RELEASE_ALLOWLIST.json",
		"BRIDGE_PLUGIN_MANIFEST.json",
		serverBridge2CertificationReleaseFile,
		"SBOM.spdx.json",
		"PROVENANCE.json",
		"RELEASE_NOTES.txt",
	}
	if linuxProductionRequired0153(ver) {
		artifacts = append(artifacts, linuxProductionArtifacts0153(ver)...)
	} else {
		artifacts = append(artifacts,
			"neverlauncher-cli-linux-amd64",
			"neverlauncher-api-linux-amd64",
			"neverlauncher-desktop-linux-amd64",
			"neverruntime-linux-amd64",
		)
	}
	if !windowsSigningRequired0152(ver) {
		artifacts = append(artifacts, "neverlauncher-cli-windows-amd64.exe")
	}
	if deliveryManifestRequired0151(ver) {
		artifacts = append(artifacts, deliveryManifestFile0151)
	}
	if releaseVerificationV2Required0158(ver) {
		artifacts = append(artifacts, releaseTrustPolicyFile0158)
	}
	if publicProductionDeliveryRequired0159(ver) {
		artifacts = append(artifacts, publicProductionDeliveryMatrixFile0159)
	}
	if windowsSigningRequired0152(ver) {
		artifacts = append(artifacts,
			"neverlauncher-cli-windows-x64.exe",
			"neverlauncher-cli-windows-arm64.exe",
			"neverlauncher-desktop-windows-x64.exe",
			"neverlauncher-desktop-windows-arm64.exe",
			"neverguard-windows-x64.exe",
			"neverguard-windows-arm64.exe",
		)
		if componentTransactionalUpdateRequired0157(ver) {
			artifacts = append(artifacts, "neverruntime-windows-x64.exe", "neverruntime-windows-arm64.exe")
		}
		artifacts = append(artifacts,
			"neverlauncher-desktop-"+ver+"-windows-x64.zip",
			"neverlauncher-desktop-"+ver+"-windows-arm64.zip",
			"WINDOWS_PACKAGE_MANIFEST_X64.json",
			"WINDOWS_PACKAGE_MANIFEST_ARM64.json",
			windowsDeliveryAllowlistFile0152,
			windowsSigningEvidenceFile0152,
		)
	}
	if macOSProductionRequired0154(ver) {
		artifacts = append(artifacts, macOSProductionArtifacts0154(ver)...)
	}
	if managedJREDistributionRequired0155(ver) {
		artifacts = append(artifacts, managedJREArtifacts0155(ver)...)
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
	if serverBridge2CertificationRequired0150(ver) {
		extra += "\n- начиная с 0.15.0 publish-check требует SERVERBRIDGE2_CERTIFICATION.json и повторно сверяет все 11 platform JAR с exact-version BRIDGE_RELEASE_ALLOWLIST.json;"
	}
	if deliveryManifestRequired0151(ver) {
		extra += "\n- начиная с 0.15.1 подписанный DELIVERY_MANIFEST.json фиксирует SHA-256/size каждого delivery artifact и каноническую platform/architecture пару (windows/linux/macos + x64/arm64/universal); release verify повторно проверяет inventory fail-closed;"
	}
	if windowsSigningRequired0152(ver) {
		extra += "\n- начиная с 0.15.2 publish-check требует реальные Windows x64+ARM64 PE для CLI/Desktop/NeverGuard, Authenticode SHA-256 + RFC3161 timestamp и WINDOWS_SIGNING_EVIDENCE.json, связанный с DELIVERY_MANIFEST.json и package ZIP;"
	}
	if linuxProductionRequired0153(ver) {
		extra += "\n- начиная с 0.15.3 publish-check требует нативно собранные Linux x64+ARM64 CLI/API/Desktop/NeverGuard/NeverRuntime, проверяет ELF e_machine, deterministic tar.gz, embedded package manifests и их привязку к DELIVERY_MANIFEST.json;"
	}
	if macOSProductionRequired0154(ver) {
		extra += "\n- начиная с 0.15.4 publish-check требует отдельные macOS x64+ARM64 Mach-O, Developer ID Application + Hardened Runtime, Accepted Apple notarization, stapled ticket, Gatekeeper acceptance и MACOS_NOTARIZATION_EVIDENCE.json, связанный с DELIVERY_MANIFEST.json;"
	}
	if managedJREDistributionRequired0155(ver) {
		extra += "\n- начиная с 0.15.5 publish-check требует Managed JRE Distribution: exact Temurin 21 vendor archives для Windows/Linux/macOS x64+ARM64, MANAGED_JRE_MANIFEST/EVIDENCE, проверку SHA-256/size/архитектуры bin/java и binding к DELIVERY_MANIFEST.json;"
	}
	if updaterVersionAtLeast0156(ver) {
		extra += "\n- начиная с 0.15.6 client install/update/package-apply используют Unified Transactional Updater Core: verified same-filesystem staging, durable journal, crash recovery, automatic rollback и fail-closed post-verify; publish-check выполняет реальный updater self-test;"
	}
	if publicProductionDeliveryRequired0159(ver) {
		extra += "\n- начиная с 0.15.9 PUBLIC_PRODUCTION_DELIVERY_MATRIX.json публикует точный six-target Windows/Linux/macOS x64+ARM64 inventory с HTTPS URL, SHA-256/size и Managed JRE binding; post-publish nl delivery public-e2e скачивает публичные bytes, сверяет matrix/delivery manifest и повторно выполняет Release Verification v2 end-to-end;"
	}
	if migrationStabilizationRequired01510(ver) {
		extra += "\n- начиная с 0.15.10 migration stabilization сериализует Release Verification через persistent trust-state lock, мигрирует state 2.0→2.1 с same-version RELEASE_MANIFEST binding, переносит legacy macOS component state в canonical location и удаляет terminal updater staging/backup payload после durable rollback;"
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
