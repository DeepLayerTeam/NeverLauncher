package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Release BOM v1 binds every shipped byte to the exact source component set.
// Unlike an advisory manifest, a missing or modified artifact blocks signing,
// verification, and consequently publication/install through release verify.
const releaseBOMFile03214 = "RELEASE_BOM.json"

type bomComponent03214 struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	SourceFile   string `json:"sourceFile"`
	SourceSHA256 string `json:"sourceSha256"`
}
type bomArtifact03214 struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type releaseBOM03214 struct {
	Schema         int                 `json:"schema"`
	ProductVersion string              `json:"productVersion"`
	Components     []bomComponent03214 `json:"components"`
	Artifacts      []bomArtifact03214  `json:"artifacts"`
}

func releaseBOMRequired03214(ver string) bool {
	v, ok := parseVersionTriple0158(ver)
	return ok && compareVersionTriple0158(v, [3]int{0, 32, 14}) >= 0
}

// Enumerate the actual build inputs of Backend/API, CLI, Desktop, Admin,
// Guard probes, NeverRuntime and every published ServerBridge plugin.
func bomSources03214() map[string]string {
	m := map[string]string{
		"backend-api":                "services/api/go.mod",
		"backend-api-checksums":      "services/api/go.sum",
		"installer":                  "installer/go.mod",
		"prestarter":                 "prestarter/go.mod",
		"sdk-admin-typescript":       "sdk/admin/typescript/package.json",
		"sdk-backend-go":             "sdk/backend/go/go.mod",
		"sdk-cli-go":                 "sdk/cli/go/go.mod",
		"sdk-desktop-rust":           "sdk/desktop/rust/Cargo.toml",
		"sdk-desktop-typescript":     "sdk/desktop/typescript/package.json",
		"cli":                        "cli/go.mod",
		"admin":                      "apps/admin/package-lock.json",
		"admin-package":              "apps/admin/package.json",
		"desktop-web":                "apps/desktop/package-lock.json",
		"desktop-package":            "apps/desktop/package.json",
		"desktop-native":             "apps/desktop/src-tauri/Cargo.toml",
		"desktop-tauri-config":       "apps/desktop/src-tauri/tauri.conf.json",
		"neverruntime":               "runtime/neverruntime/Cargo.toml",
		"guard-sensor":          "runtime/guard-sensor/Cargo.toml",
		"guard-memory-probe":    "runtime/guard-memory-probe/Cargo.toml",
		"guard-thread-probe":    "runtime/guard-thread-probe/Cargo.toml",
		"guard-debug-probe":     "runtime/guard-debug-probe/Cargo.toml",
		"guard-jvm-probe":       "runtime/guard-jvm-probe/Cargo.toml",
		"serverbridge-certification": "serverbridge/targets.json",
		"guard-certification":        "guard-ci/targets.json",
		"device-trust-certification": "device-trust/targets.json",
		"serverbridge-hybrid":        "serverbridge/hybrid-targets.json",
		"api-contract":               "schemas/openapi.yaml",
	}
	for _, name := range []string{"bridge-common", "proxy-family-common", "bungee-family-common", "bukkit-family-common", "modloader-family-common", "velocity-bridge", "bungeecord-bridge", "waterfall-bridge", "bukkit-bridge", "spigot-bridge", "paper-bridge", "purpur-bridge", "folia-bridge", "fabric-bridge", "forge-bridge", "neoforge-bridge", "quilt-bridge", "sponge-bridge", "vanilla-bridge"} {
		m["plugin-"+name] = "plugins/" + name + "/build.gradle.kts"
	}
	return m
}

var bomCargoVersion03214 = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)

func bomComponentVersion03214(name, product string) string {
	switch name {
	case "sdk-admin-typescript", "sdk-desktop-rust", "sdk-desktop-typescript":
		return "0.21.0"
	default:
		return product
	}
}

func bomCheckSourceVersion03214(name, rel, ver string, raw []byte) error {
	s := string(raw)
	switch {
	case strings.HasSuffix(rel, "Cargo.toml"):
		match := bomCargoVersion03214.FindStringSubmatch(s)
		if len(match) != 2 || match[1] != ver {
			return fmt.Errorf("%s Cargo package version mismatch with %s", name, ver)
		}
	case strings.HasSuffix(rel, "build.gradle.kts"):
		if !strings.Contains(s, `version = rootProject.file("VERSION").readText().trim()`) {
			return fmt.Errorf("%s plugin must derive version from VERSION", name)
		}
	case strings.HasSuffix(rel, ".json") && !strings.HasSuffix(rel, "targets.json") && !strings.HasSuffix(rel, "hybrid-targets.json") && rel != "schemas/openapi.yaml":
		var obj struct {
			Version  string `json:"version"`
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if obj.Version != ver {
			return fmt.Errorf("%s version=%q expected %q", name, obj.Version, ver)
		}
		if root, ok := obj.Packages[""]; ok && root.Version != ver {
			return fmt.Errorf("%s lock root version=%q expected %q", name, root.Version, ver)
		}
	case strings.HasSuffix(rel, "targets.json"):
		var obj struct {
			ProductVersion string `json:"productVersion"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		if obj.ProductVersion != ver {
			return fmt.Errorf("%s productVersion mismatch", name)
		}
	case rel == "schemas/openapi.yaml":
		if !strings.Contains(s, "NeverLauncher "+ver+".") {
			return errors.New("OpenAPI version mismatch")
		}
	}
	return nil
}

func bomSourceComponents03214(root, ver string) ([]bomComponent03214, error) {
	rootVersion, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(rootVersion)) != ver {
		return nil, fmt.Errorf("source VERSION mismatch: %q != %q", strings.TrimSpace(string(rootVersion)), ver)
	}
	sources := bomSources03214()
	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]bomComponent03214, 0, len(keys))
	for _, name := range keys {
		rel := sources[name]
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := bomCheckSourceVersion03214(name, rel, bomComponentVersion03214(name, ver), raw); err != nil {
			return nil, err
		}
		h := sha256.Sum256(raw)
		out = append(out, bomComponent03214{Name: name, Version: bomComponentVersion03214(name, ver), SourceFile: rel, SourceSHA256: hex.EncodeToString(h[:])})
	}
	return out, nil
}

// Only these files are created after the BOM; they are bound by SHA256SUMS
// and the existing release signature, avoiding a circular digest dependency.
func bomPostBuildFile03214(name string) bool {
	switch name {
	case "RELEASE_BOM.json", "RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "PROVENANCE.json.sig", "RELEASE_TRUST_STATE.json":
		return true
	}
	return false
}
func bomArtifactFiles03214(dir string) ([]bomArtifact03214, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]bomArtifact03214, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if bomPostBuildFile03214(name) {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 || !e.Type().IsRegular() {
			return nil, fmt.Errorf("BOM: unexpected non-regular release file %q", name)
		}
		h, n, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return nil, fmt.Errorf("BOM: empty artifact %q", name)
		}
		out = append(out, bomArtifact03214{File: name, SHA256: h, Size: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}
func bomCheckRequiredArtifacts03214(dir, ver string, items []bomArtifact03214) error {
	have := make(map[string]bool, len(items))
	for _, e := range items {
		have[e.File] = true
	}
	for _, name := range releaseArtifacts(ver) {
		if name == releaseBOMFile03214 {
			continue
		}
		if !have[name] {
			return fmt.Errorf("BOM: required shipping artifact missing: %s", name)
		}
	}
	return nil
}
func writeReleaseBOM03214(out, sourceRoot, ver string) error {
	if !releaseBOMRequired03214(ver) {
		return nil
	}
	sources, err := bomSourceComponents03214(sourceRoot, ver)
	if err != nil {
		return fmt.Errorf("BOM source: %w", err)
	}
	artifacts, err := bomArtifactFiles03214(out)
	if err != nil {
		return err
	}
	if err := bomCheckRequiredArtifacts03214(out, ver, artifacts); err != nil {
		return err
	}
	if len(artifacts) == 0 {
		return errors.New("BOM: release has no artifacts")
	}
	return writeJSONFile(filepath.Join(out, releaseBOMFile03214), releaseBOM03214{Schema: 1, ProductVersion: ver, Components: sources, Artifacts: artifacts})
}
func verifyReleaseBOM03214(dir, ver string) error {
	if !releaseBOMRequired03214(ver) {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, releaseBOMFile03214))
	if err != nil {
		return fmt.Errorf("BOM is mandatory: %w", err)
	}
	var bom releaseBOM03214
	if err := json.Unmarshal(raw, &bom); err != nil {
		return fmt.Errorf("BOM invalid JSON: %w", err)
	}
	if bom.Schema != 1 || bom.ProductVersion != ver {
		return fmt.Errorf("BOM schema/version mismatch: %d %q expected %q", bom.Schema, bom.ProductVersion, ver)
	}
	expectedSources := bomSources03214()
	if len(bom.Components) != len(expectedSources) {
		return errors.New("BOM source component set incomplete or extended")
	}
	seen := make(map[string]bool)
	for _, c := range bom.Components {
		rel, ok := expectedSources[c.Name]
		if !ok || seen[c.Name] || c.Version != bomComponentVersion03214(c.Name, ver) || c.SourceFile != rel || !bomSHA03214(c.SourceSHA256) {
			return fmt.Errorf("BOM source component mismatch: %s", c.Name)
		}
		seen[c.Name] = true
	}
	actual, err := bomArtifactFiles03214(dir)
	if err != nil {
		return err
	}
	if len(actual) != len(bom.Artifacts) {
		return errors.New("BOM artifact count differs from actual release files")
	}
	for i, e := range actual {
		expected := bom.Artifacts[i]
		if e != expected || !bomSHA03214(expected.SHA256) {
			return fmt.Errorf("BOM artifact mismatch: actual=%s expected=%s", e.File, expected.File)
		}
	}
	return bomCheckRequiredArtifacts03214(dir, ver, bom.Artifacts)
}
func bomSHA03214(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil && strings.ToLower(v) == v
}

// Enforce BOM presence inside the Ed25519-signed SHA256SUMS boundary and
// the release manifest required list. Otherwise a valid-looking BOM could
// remain unsigned and be swapped independently of a signed bundle.
func verifyReleaseBOMBinding03214(dir, ver string) error {
	if !releaseBOMRequired03214(ver) {
		return nil
	}
	var manifest struct {
		RequiredFiles []string `json:"requiredFiles"`
		Artifacts     []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			SHA256   string `json:"sha256"`
			Status   string `json:"status"`
		} `json:"artifacts"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	requiredFile, requiredArtifact := false, false
	digest, _, err := hashFile(filepath.Join(dir, releaseBOMFile03214))
	if err != nil {
		return err
	}
	for _, v := range manifest.RequiredFiles {
		if v == releaseBOMFile03214 {
			requiredFile = true
		}
	}
	for _, a := range manifest.Artifacts {
		if a.Name == releaseBOMFile03214 && a.Required && a.Status == "present" && a.SHA256 == digest {
			requiredArtifact = true
		}
	}
	if !requiredFile || !requiredArtifact {
		return errors.New("BOM must be a required release-manifest artifact with exact digest")
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	bomCount, manifestCount := 0, 0
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == releaseBOMFile03214 {
			bomCount++
			if fields[0] != digest {
				return errors.New("BOM checksum is not pinned")
			}
		}
		if fields[1] == "RELEASE_MANIFEST.json" {
			manifestCount++
		}
	}
	if bomCount != 1 || manifestCount != 1 {
		return errors.New("BOM and RELEASE_MANIFEST must each occur once in SHA256SUMS")
	}
	return nil
}
