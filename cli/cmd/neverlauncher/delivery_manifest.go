package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const deliveryManifestFile0151 = "DELIVERY_MANIFEST.json"

type DeliveryTarget struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

type DeliveryArtifact struct {
	Name         string `json:"name"`
	Component    string `json:"component"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Executable   bool   `json:"executable,omitempty"`
}

type DeliveryManifest struct {
	SchemaVersion    string             `json:"schemaVersion"`
	Product          string             `json:"product"`
	Version          string             `json:"version"`
	GeneratedAt      string             `json:"generatedAt"`
	PublishedTargets []DeliveryTarget   `json:"publishedTargets"`
	Artifacts        []DeliveryArtifact `json:"artifacts"`
}

func deliveryManifestRequired0151(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 1)))
}

func parseCoreVersion(ver string) (int, int, int, bool) {
	core := strings.TrimSpace(ver)
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	values := make([]int, 3)
	for i, part := range parts {
		if part == "" {
			return 0, 0, 0, false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return 0, 0, 0, false
			}
			values[i] = values[i]*10 + int(ch-'0')
		}
	}
	return values[0], values[1], values[2], true
}

func normalizeDeliveryPlatform(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "linux":
		return "linux", nil
	case "windows", "win", "win32", "win64":
		return "windows", nil
	case "macos", "darwin", "osx", "mac":
		return "macos", nil
	case "any", "all", "*":
		return "any", nil
	default:
		return "", fmt.Errorf("unsupported delivery platform %q", value)
	}
}

func normalizeDeliveryArchitecture(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x64", "amd64", "x86_64", "x86-64":
		return "x64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	case "universal", "universal2":
		return "universal", nil
	case "any", "all", "*":
		return "any", nil
	default:
		return "", fmt.Errorf("unsupported delivery architecture %q", value)
	}
}

func currentDeliveryTarget() (DeliveryTarget, error) {
	platform, err := normalizeDeliveryPlatform(runtime.GOOS)
	if err != nil {
		return DeliveryTarget{}, err
	}
	arch, err := normalizeDeliveryArchitecture(runtime.GOARCH)
	if err != nil {
		return DeliveryTarget{}, err
	}
	return DeliveryTarget{Platform: platform, Architecture: arch}, nil
}

func canonicalDeliveryTarget(platform, arch string) (DeliveryTarget, error) {
	p, err := normalizeDeliveryPlatform(platform)
	if err != nil {
		return DeliveryTarget{}, err
	}
	a, err := normalizeDeliveryArchitecture(arch)
	if err != nil {
		return DeliveryTarget{}, err
	}
	if p == "any" && a != "any" {
		return DeliveryTarget{}, errors.New("platform=any requires architecture=any")
	}
	if a == "universal" && p != "macos" {
		return DeliveryTarget{}, errors.New("architecture=universal is valid only for macos")
	}
	return DeliveryTarget{Platform: p, Architecture: a}, nil
}

func deliveryTargetCompatible(artifact DeliveryArtifact, target DeliveryTarget) bool {
	if artifact.Platform != "any" && artifact.Platform != target.Platform {
		return false
	}
	if artifact.Architecture == "any" {
		return true
	}
	if artifact.Architecture == target.Architecture {
		return true
	}
	return artifact.Platform == "macos" && artifact.Architecture == "universal" && (target.Architecture == "x64" || target.Architecture == "arm64")
}

func deliveryArtifactTarget(name string) DeliveryTarget {
	lower := strings.ToLower(name)
	patterns := []struct {
		Needle string
		Target DeliveryTarget
	}{
		{"windows-arm64", DeliveryTarget{"windows", "arm64"}},
		{"windows-amd64", DeliveryTarget{"windows", "x64"}},
		{"windows-x64", DeliveryTarget{"windows", "x64"}},
		{"linux-arm64", DeliveryTarget{"linux", "arm64"}},
		{"linux-amd64", DeliveryTarget{"linux", "x64"}},
		{"linux-x64", DeliveryTarget{"linux", "x64"}},
		{"macos-universal", DeliveryTarget{"macos", "universal"}},
		{"macos-arm64", DeliveryTarget{"macos", "arm64"}},
		{"macos-amd64", DeliveryTarget{"macos", "x64"}},
		{"macos-x64", DeliveryTarget{"macos", "x64"}},
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern.Needle) {
			return pattern.Target
		}
	}
	return DeliveryTarget{Platform: "any", Architecture: "any"}
}

func deliveryArtifactComponent(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "neverguard-"):
		return "guard"
	case strings.HasPrefix(lower, "neverlauncher-desktop-web-"):
		return "desktop-web"
	case strings.HasPrefix(lower, "neverlauncher-desktop-package-"):
		return "desktop-bundle"
	case strings.HasPrefix(lower, "neverlauncher-desktop-"):
		if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".msi") || strings.HasSuffix(lower, ".deb") || strings.HasSuffix(lower, ".appimage") {
			return "desktop-package"
		}
		return "desktop-launcher"
	case strings.HasPrefix(lower, "neverlauncher-cli-"):
		return "cli"
	case strings.HasPrefix(lower, "neverlauncher-api-"):
		return "api"
	case strings.HasPrefix(lower, "neverruntime-"):
		return "runtime"
	case strings.HasPrefix(lower, "neverlauncher-jre-"):
		return "managed-jre"
	case strings.HasPrefix(lower, "neverlauncher-admin-web-"):
		return "admin-web"
	case strings.HasPrefix(lower, "neverlauncher-source-"):
		return "source"
	case strings.Contains(lower, "-bridge-") && strings.HasSuffix(lower, ".jar"):
		return "serverbridge"
	default:
		return "release-metadata"
	}
}

func deliveryArtifactFormat(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".appimage"):
		return "appimage"
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(lower)), ".")
	if ext != "" {
		return ext
	}
	return "binary"
}

func deliveryArtifactExecutable(name, component string) bool {
	if component == "cli" || component == "api" || component == "runtime" || component == "desktop-launcher" || component == "guard" {
		return !strings.HasSuffix(strings.ToLower(name), ".zip")
	}
	return false
}

func buildDeliveryManifest0151(dir, ver string) (DeliveryManifest, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return DeliveryManifest{}, err
	}
	manifest := DeliveryManifest{
		SchemaVersion: "1.0",
		Product:       "NeverLauncher",
		Version:       strings.TrimSpace(ver),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if manifest.Version == "" {
		return DeliveryManifest{}, errors.New("delivery manifest version is empty")
	}
	targets := map[string]DeliveryTarget{}
	for _, item := range items {
		if item.IsDir() {
			continue
		}
		name := item.Name()
		if windowsSigningRequired0152(ver) && strings.Contains(strings.ToLower(name), "windows-amd64") {
			// 0.15.2 keeps pre-signing x64 Guard CI aliases in the bundle for certification evidence,
			// but they are not publishable delivery artifacts. Canonical signed delivery uses windows-x64.
			continue
		}
		if linuxProductionRequired0153(ver) && strings.Contains(strings.ToLower(name), "linux-amd64") {
			// 0.15.3 keeps the historical x64 Guard CI alias only as certification evidence.
			// Publishable Linux delivery uses canonical linux-x64/linux-arm64 names.
			continue
		}
		if macOSProductionRequired0154(ver) && strings.Contains(strings.ToLower(name), "macos-universal") {
			// 0.15.4 keeps the historical universal Guard CI package only as certification evidence.
			// Publishable macOS delivery uses separately notarized macos-x64/macos-arm64 packages.
			continue
		}
		switch name {
		case deliveryManifestFile0151, "RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "PROVENANCE.json.sig":
			continue
		}
		path := filepath.Join(dir, name)
		sum, size, err := hashFile(path)
		if err != nil {
			return DeliveryManifest{}, err
		}
		if size <= 0 {
			return DeliveryManifest{}, fmt.Errorf("delivery artifact %s is empty", name)
		}
		target := deliveryArtifactTarget(name)
		component := deliveryArtifactComponent(name)
		artifact := DeliveryArtifact{
			Name:         name,
			Component:    component,
			Platform:     target.Platform,
			Architecture: target.Architecture,
			Format:       deliveryArtifactFormat(name),
			SHA256:       sum,
			Size:         size,
			Executable:   deliveryArtifactExecutable(name, component),
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
		if target.Platform != "any" {
			key := target.Platform + "/" + target.Architecture
			targets[key] = target
		}
	}
	if len(manifest.Artifacts) == 0 {
		return DeliveryManifest{}, errors.New("delivery bundle contains no artifacts")
	}
	for _, target := range targets {
		manifest.PublishedTargets = append(manifest.PublishedTargets, target)
	}
	sort.Slice(manifest.PublishedTargets, func(i, j int) bool {
		left := manifest.PublishedTargets[i].Platform + "/" + manifest.PublishedTargets[i].Architecture
		right := manifest.PublishedTargets[j].Platform + "/" + manifest.PublishedTargets[j].Architecture
		return left < right
	})
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].Name < manifest.Artifacts[j].Name })
	return manifest, nil
}

func writeDeliveryManifest0151(dir, ver string) error {
	manifest, err := buildDeliveryManifest0151(dir, ver)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(dir, deliveryManifestFile0151), manifest)
}

func readDeliveryManifest0151(dir string) (DeliveryManifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, deliveryManifestFile0151))
	if err != nil {
		return DeliveryManifest{}, err
	}
	var manifest DeliveryManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return DeliveryManifest{}, fmt.Errorf("invalid %s: %w", deliveryManifestFile0151, err)
	}
	return manifest, nil
}

func validDeliverySHA256(value string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == 32
}

func safeDeliveryArtifactPath(dir, name string) (string, error) {
	if strings.TrimSpace(name) == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("invalid delivery artifact path %q", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("delivery artifact escapes bundle: %s", name)
	}
	return filepath.Join(dir, clean), nil
}

func verifyDeliveryManifest0151(dir, expectedVersion string) error {
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		return err
	}
	if manifest.SchemaVersion != "1.0" || manifest.Product != "NeverLauncher" || strings.TrimSpace(manifest.Version) == "" {
		return errors.New("delivery manifest header is invalid")
	}
	if strings.TrimSpace(expectedVersion) != "" && manifest.Version != strings.TrimSpace(expectedVersion) {
		return fmt.Errorf("delivery manifest version mismatch: manifest=%s expected=%s", manifest.Version, expectedVersion)
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("delivery manifest has no artifacts")
	}

	seenNames := map[string]struct{}{}
	actualTargets := map[string]DeliveryTarget{}
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == deliveryManifestFile0151 || artifact.Name == "RELEASE_MANIFEST.json" || artifact.Name == "SHA256SUMS" || artifact.Name == "SHA256SUMS.sig" || artifact.Name == "PROVENANCE.json.sig" {
			return fmt.Errorf("delivery manifest contains circular/control artifact %s", artifact.Name)
		}
		if _, exists := seenNames[artifact.Name]; exists {
			return fmt.Errorf("duplicate delivery artifact %s", artifact.Name)
		}
		seenNames[artifact.Name] = struct{}{}
		if strings.TrimSpace(artifact.Component) == "" || strings.TrimSpace(artifact.Format) == "" || artifact.Size <= 0 || !validDeliverySHA256(artifact.SHA256) {
			return fmt.Errorf("delivery artifact metadata invalid: %s", artifact.Name)
		}
		target, err := canonicalDeliveryTarget(artifact.Platform, artifact.Architecture)
		if err != nil || target.Platform != artifact.Platform || target.Architecture != artifact.Architecture {
			return fmt.Errorf("delivery artifact target is not canonical for %s: %s/%s", artifact.Name, artifact.Platform, artifact.Architecture)
		}
		path, err := safeDeliveryArtifactPath(dir, artifact.Name)
		if err != nil {
			return err
		}
		actual, size, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("delivery artifact %s unavailable: %w", artifact.Name, err)
		}
		if size != artifact.Size || !strings.EqualFold(actual, artifact.SHA256) {
			return fmt.Errorf("delivery artifact %s checksum/size mismatch", artifact.Name)
		}
		if target.Platform != "any" {
			actualTargets[target.Platform+"/"+target.Architecture] = target
		}
	}

	publishedTargets := map[string]struct{}{}
	for _, target := range manifest.PublishedTargets {
		canonical, err := canonicalDeliveryTarget(target.Platform, target.Architecture)
		if err != nil || canonical.Platform == "any" || canonical.Platform != target.Platform || canonical.Architecture != target.Architecture {
			return fmt.Errorf("published delivery target is invalid: %s/%s", target.Platform, target.Architecture)
		}
		key := target.Platform + "/" + target.Architecture
		if _, duplicate := publishedTargets[key]; duplicate {
			return fmt.Errorf("duplicate published delivery target %s", key)
		}
		publishedTargets[key] = struct{}{}
	}
	if len(publishedTargets) != len(actualTargets) {
		return errors.New("publishedTargets does not match concrete delivery artifacts")
	}
	for key := range actualTargets {
		if _, ok := publishedTargets[key]; !ok {
			return fmt.Errorf("publishedTargets is missing %s", key)
		}
	}
	return nil
}

func resolveDeliveryArtifacts0151(manifest DeliveryManifest, target DeliveryTarget, component, format string) []DeliveryArtifact {
	component = strings.TrimSpace(strings.ToLower(component))
	format = strings.TrimSpace(strings.ToLower(format))
	var matches []DeliveryArtifact
	for _, artifact := range manifest.Artifacts {
		if component != "" && strings.ToLower(artifact.Component) != component {
			continue
		}
		if format != "" && strings.ToLower(artifact.Format) != format {
			continue
		}
		if deliveryTargetCompatible(artifact, target) {
			matches = append(matches, artifact)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		leftExact := matches[i].Platform == target.Platform && matches[i].Architecture == target.Architecture
		rightExact := matches[j].Platform == target.Platform && matches[j].Architecture == target.Architecture
		if leftExact != rightExact {
			return leftExact
		}
		leftUniversal := matches[i].Platform == "macos" && matches[i].Architecture == "universal"
		rightUniversal := matches[j].Platform == "macos" && matches[j].Architecture == "universal"
		if leftUniversal != rightUniversal {
			return leftUniversal
		}
		return matches[i].Name < matches[j].Name
	})
	return matches
}

func handleDelivery(args []string) error {
	if len(args) == 0 {
		return errors.New("available delivery subcommands: target, manifest, verify, verify-windows, prepare-linux, verify-linux, verify-macos, verify-jre, resolve")
	}
	switch args[0] {
	case "target":
		platform := flagValue(args, "--platform", "")
		arch := flagValue(args, "--arch", "")
		var target DeliveryTarget
		var err error
		if platform == "" && arch == "" {
			target, err = currentDeliveryTarget()
		} else {
			if platform == "" || arch == "" {
				return errors.New("delivery target requires both --platform and --arch")
			}
			target, err = canonicalDeliveryTarget(platform, arch)
		}
		if err != nil {
			return err
		}
		printJSON(map[string]any{"schemaVersion": "1.0", "platform": target.Platform, "architecture": target.Architecture})
		return nil
	case "manifest":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery manifest requires --bundle <dir>")
		}
		ver := flagValue(args, "--version", version)
		if err := writeDeliveryManifest0151(dir, ver); err != nil {
			return err
		}
		return verifyDeliveryManifest0151(dir, ver)
	case "verify":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery verify requires --bundle <dir>")
		}
		return verifyDeliveryManifest0151(dir, flagValue(args, "--version", ""))
	case "verify-windows":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery verify-windows requires --bundle <dir>")
		}
		ver := flagValue(args, "--version", version)
		if err := verifyDeliveryManifest0151(dir, ver); err != nil {
			return err
		}
		return verifyWindowsSigningEvidence0152(dir, ver, flagBool(args, "--production", false))
	case "prepare-linux":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery prepare-linux requires --bundle <dir>")
		}
		ver := flagValue(args, "--version", version)
		return writeLinuxProductionEvidence0153(dir, ver)
	case "verify-linux":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery verify-linux requires --bundle <dir>")
		}
		ver := flagValue(args, "--version", version)
		if err := verifyDeliveryManifest0151(dir, ver); err != nil {
			return err
		}
		return verifyLinuxProductionEvidence0153(dir, ver, true)
	case "verify-macos":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery verify-macos requires --bundle <dir>")
		}
		ver := flagValue(args, "--version", version)
		if err := verifyDeliveryManifest0151(dir, ver); err != nil {
			return err
		}
		return verifyMacOSNotarizationEvidence0154(dir, ver, flagBool(args, "--production", false))
	case "verify-jre":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("delivery verify-jre requires --bundle <dir>")
		}
		ver := flagValue(args, "--version", version)
		if err := verifyDeliveryManifest0151(dir, ver); err != nil {
			return err
		}
		return verifyManagedJREDistribution0155(dir, ver, true)
	case "resolve":
		dir := flagValue(args, "--bundle", "")
		if dir == "" {
			return errors.New("delivery resolve requires --bundle <dir>")
		}
		if err := verifyDeliveryManifest0151(dir, flagValue(args, "--version", "")); err != nil {
			return err
		}
		manifest, err := readDeliveryManifest0151(dir)
		if err != nil {
			return err
		}
		platform := flagValue(args, "--platform", "")
		arch := flagValue(args, "--arch", "")
		var target DeliveryTarget
		if platform == "" && arch == "" {
			target, err = currentDeliveryTarget()
		} else if platform == "" || arch == "" {
			return errors.New("delivery resolve requires both --platform and --arch when overriding host target")
		} else {
			target, err = canonicalDeliveryTarget(platform, arch)
		}
		if err != nil {
			return err
		}
		matches := resolveDeliveryArtifacts0151(manifest, target, flagValue(args, "--component", ""), flagValue(args, "--format", ""))
		if len(matches) == 0 {
			return fmt.Errorf("no delivery artifacts for %s/%s", target.Platform, target.Architecture)
		}
		printJSON(map[string]any{"schemaVersion": "1.0", "version": manifest.Version, "target": target, "artifacts": matches})
		return nil
	default:
		return fmt.Errorf("unknown delivery subcommand: %s", args[0])
	}
}
