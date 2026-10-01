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
	"strconv"
	"strings"
	"time"
)

const (
	compatibilityTargetsReleaseFile       = "COMPATIBILITY_TARGETS.json"
	compatibilityMatrixReleaseFile        = "COMPATIBILITY_MATRIX.json"
	compatibilityCertificationReleaseFile = "COMPATIBILITY_CERTIFICATION.json"
)

var compatibilitySHA256RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type releaseCompatibilityTarget struct {
	ID             string `json:"id"`
	Minecraft      string `json:"minecraft"`
	Loader         string `json:"loader"`
	LoaderVersion  string `json:"loaderVersion"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	JavaMajor      int    `json:"javaMajor,omitempty"`
	Scope          string `json:"scope,omitempty"`
	MatchingServer bool   `json:"matchingServer,omitempty"`
	Required       bool   `json:"required"`
}

type releaseCompatibilityTargets struct {
	SchemaVersion  string                       `json:"schemaVersion"`
	ProductVersion string                       `json:"productVersion,omitempty"`
	Targets        []releaseCompatibilityTarget `json:"targets"`
}

type releaseCompatibilityResult struct {
	SchemaVersion         string          `json:"schemaVersion"`
	ProductVersion        string          `json:"productVersion"`
	TargetID              string          `json:"targetId"`
	Status                string          `json:"status"`
	MinecraftVersion      string          `json:"minecraftVersion"`
	Loader                string          `json:"loader"`
	LoaderSelector        string          `json:"loaderSelector"`
	ResolvedLoaderVersion string          `json:"resolvedLoaderVersion"`
	OS                    string          `json:"os"`
	Arch                  string          `json:"arch"`
	JavaMajor             int             `json:"javaMajor,omitempty"`
	DetectedJavaMajor     int             `json:"detectedJavaMajor,omitempty"`
	JREVendor             string          `json:"jreVendor,omitempty"`
	JRERuntimeVersion     string          `json:"jreRuntimeVersion,omitempty"`
	JREExecutableSHA256   string          `json:"jreExecutableSha256,omitempty"`
	Scope                 string          `json:"scope,omitempty"`
	MatchingServer        bool            `json:"matchingServer,omitempty"`
	Commit                string          `json:"commit"`
	RunID                 string          `json:"runId"`
	ExitCode              int             `json:"exitCode"`
	Checks                map[string]bool `json:"checks"`
	EvidenceSHA256        string          `json:"evidenceSha256"`
}

type releaseCompatibilityMatrix struct {
	SchemaVersion  string                       `json:"schemaVersion"`
	ProductVersion string                       `json:"productVersion"`
	GeneratedAt    string                       `json:"generatedAt"`
	Repository     string                       `json:"repository"`
	Commit         string                       `json:"commit"`
	RunID          string                       `json:"runId"`
	Status         string                       `json:"status"`
	Targets        []releaseCompatibilityResult `json:"targets"`
	Errors         []string                     `json:"errors"`
}

type releaseCompatibilityJREBuild struct {
	JavaMajor        int    `json:"javaMajor"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	Vendor           string `json:"vendor"`
	RuntimeVersion   string `json:"runtimeVersion"`
	ExecutableSHA256 string `json:"executableSha256"`
	TargetCount      int    `json:"targetCount"`
}

type releaseCompatibilityCertification struct {
	SchemaVersion     string                         `json:"schemaVersion"`
	ProductVersion    string                         `json:"productVersion"`
	CertifiedAt       string                         `json:"certifiedAt"`
	Repository        string                         `json:"repository"`
	Commit            string                         `json:"commit"`
	RunID             string                         `json:"runId"`
	MatrixSHA256      string                         `json:"matrixSha256"`
	TargetsSHA256     string                         `json:"targetsSha256"`
	RequiredTargetIDs []string                       `json:"requiredTargetIds"`
	PassedTargetIDs   []string                       `json:"passedTargetIds"`
	LoaderFamilies    []string                       `json:"loaderFamilies"`
	VanillaVersions   []string                       `json:"vanillaVersions,omitempty"`
	JavaMajors        []int                          `json:"javaMajors,omitempty"`
	JREBuilds         []releaseCompatibilityJREBuild `json:"jreBuilds,omitempty"`
	Scopes            []string                       `json:"scopes,omitempty"`
	Policy            string                         `json:"policy"`
}

var vanillaCompatibilityBaselineII = map[string]struct {
	JavaMajor int
	Scope     string
}{
	"1.7.10": {JavaMajor: 8, Scope: "client"},
	"1.12.2": {JavaMajor: 8, Scope: "client"},
	"1.16.5": {JavaMajor: 8, Scope: "client"},
	"1.17.1": {JavaMajor: 16, Scope: "client"},
	"1.18.2": {JavaMajor: 17, Scope: "client"},
	"1.20.4": {JavaMajor: 17, Scope: "client"},
	"1.20.6": {JavaMajor: 21, Scope: "client"},
	"1.21.1": {JavaMajor: 21, Scope: "integration"},
}

var legacyVanillaJava8Compatibility0163 = []string{
	"1.7.10", "1.8.9", "1.9.4", "1.10.2", "1.11.2",
	"1.12.2", "1.13.2", "1.14.4", "1.15.2", "1.16.5",
}

var legacyVanillaPre17Compatibility0164 = []string{
	"1.0", "1.1", "1.2.5", "1.3.2", "1.4.7", "1.5.2", "1.6.4", "1.7.10",
}

var java16_17VanillaCompatibility0166 = map[string]int{
	"1.17.1": 16,
	"1.18.2": 17,
	"1.19.4": 17,
	"1.20.1": 17,
	"1.20.2": 17,
	"1.20.4": 17,
}

var java21VanillaCompatibility0167 = map[string]string{
	"1.20.5":  "client",
	"1.20.6":  "client",
	"1.21":    "client",
	"1.21.1":  "integration",
	"1.21.2":  "client",
	"1.21.3":  "client",
	"1.21.4":  "client",
	"1.21.5":  "client",
	"1.21.6":  "client",
	"1.21.7":  "client",
	"1.21.8":  "client",
	"1.21.9":  "client",
	"1.21.10": "client",
}

var java25VanillaCompatibility0168 = map[string]string{
	"26.1":   "client",
	"26.1.1": "client",
	"26.1.2": "client",
	"26.3":   "client",
}

var crossPlatformVanillaCompatibility0169 = []struct {
	OS   string
	Arch string
}{
	{OS: "linux", Arch: "x86_64"},
	{OS: "linux", Arch: "aarch64"},
	{OS: "windows", Arch: "x86_64"},
	{OS: "windows", Arch: "aarch64"},
	{OS: "macos", Arch: "x86_64"},
	{OS: "macos", Arch: "aarch64"},
}

var actualClientE2EIICompatibility01610 = map[string]int{
	"1.7.10":  8,
	"1.17.1":  16,
	"1.20.4":  17,
	"1.21.10": 21,
	"26.3":    25,
}

func compatibilityVersionAtLeast(ver string, wantMajor, wantMinor, wantPatch int) bool {
	core := strings.SplitN(strings.SplitN(strings.TrimSpace(ver), "+", 2)[0], "-", 2)[0]
	parts := strings.Split(core, ".")
	if len(parts) < 3 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	if major != wantMajor {
		return major > wantMajor
	}
	if minor != wantMinor {
		return minor > wantMinor
	}
	return patch >= wantPatch
}

func compatibilityVanillaBaselineIIRequired(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 2)
}

func compatibilityLegacyVanillaJava8Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 3)
}

func compatibilityLegacyVanillaPre17Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 4)
}

func compatibilityJava16_17VanillaRequired(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 6)
}

func compatibilityJava21VanillaRequired(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 7)
}

func compatibilityJava25VanillaRequired(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 8)
}

func compatibilityCrossPlatformVanillaRequired(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 9)
}

func compatibilityActualClientE2EIIRequired(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 10)
}

func compatibilityHardening01611Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 16, 11)
}

func compatibilityIIGa0170Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 17, 0)
}

func compatibilityLegacyVanilla0170v1Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 17, 0)
}

func compatibilityCertificationRequired(ver string) bool {
	parts := strings.SplitN(strings.TrimSpace(ver), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 0 || minor >= 11
}

func embedCompatibilityCertification(out, matrixPath, targetsPath, ver, expectedCommit string) error {
	if strings.TrimSpace(matrixPath) == "" {
		return errors.New("compatibility matrix path пуст")
	}
	if strings.TrimSpace(targetsPath) == "" {
		return errors.New("compatibility targets path пуст")
	}
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("read compatibility matrix: %w", err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("read compatibility targets: %w", err)
	}
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, ver, expectedCommit)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, compatibilityMatrixReleaseFile), matrixRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, compatibilityTargetsReleaseFile), targetsRaw, 0o644); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(out, compatibilityCertificationReleaseFile), certification)
}

func validateCompatibilityEvidence(matrixRaw, targetsRaw []byte, ver, expectedCommit string) (releaseCompatibilityCertification, error) {
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		return releaseCompatibilityCertification{}, fmt.Errorf("COMPATIBILITY_TARGETS invalid: %w", err)
	}
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		return releaseCompatibilityCertification{}, fmt.Errorf("COMPATIBILITY_MATRIX invalid: %w", err)
	}
	if targets.SchemaVersion != "1.0" || matrix.SchemaVersion != "1.0" {
		return releaseCompatibilityCertification{}, errors.New("compatibility evidence требует schemaVersion=1.0")
	}
	ver = strings.TrimSpace(ver)
	targetsProductVersion := strings.TrimSpace(targets.ProductVersion)
	if ver == "" || (targetsProductVersion != "" && targetsProductVersion != ver) || matrix.ProductVersion != ver {
		return releaseCompatibilityCertification{}, fmt.Errorf("compatibility productVersion mismatch: release=%s targets=%s matrix=%s", ver, targets.ProductVersion, matrix.ProductVersion)
	}
	if matrix.Status != "passed" || len(matrix.Errors) != 0 {
		return releaseCompatibilityCertification{}, errors.New("compatibility matrix не имеет fail-closed status=passed")
	}
	if strings.TrimSpace(matrix.Repository) == "" || strings.TrimSpace(matrix.Commit) == "" || strings.TrimSpace(matrix.RunID) == "" {
		return releaseCompatibilityCertification{}, errors.New("compatibility matrix не содержит repository/commit/runId")
	}
	if strings.TrimSpace(expectedCommit) != "" && matrix.Commit != strings.TrimSpace(expectedCommit) {
		return releaseCompatibilityCertification{}, fmt.Errorf("compatibility matrix commit mismatch: expected=%s actual=%s", strings.TrimSpace(expectedCommit), matrix.Commit)
	}

	enhanced := compatibilityVanillaBaselineIIRequired(ver)
	allowedLoaders := map[string]bool{"vanilla": true, "fabric": true, "quilt": true, "forge": true, "neoforge": true}
	targetByID := map[string]releaseCompatibilityTarget{}
	requiredIDs := []string{}
	baselineTargets := map[string]releaseCompatibilityTarget{}
	requiredVanillaTargets := map[string]releaseCompatibilityTarget{}
	requiredLoaderTargets := map[string]bool{}
	for _, target := range targets.Targets {
		id := strings.TrimSpace(target.ID)
		if id == "" {
			return releaseCompatibilityCertification{}, errors.New("compatibility target без id")
		}
		if _, exists := targetByID[id]; exists {
			return releaseCompatibilityCertification{}, fmt.Errorf("duplicate compatibility target: %s", id)
		}
		if !allowedLoaders[target.Loader] {
			return releaseCompatibilityCertification{}, fmt.Errorf("unsupported loader in compatibility target %s: %s", id, target.Loader)
		}
		if strings.TrimSpace(target.Minecraft) == "" || strings.TrimSpace(target.OS) == "" || strings.TrimSpace(target.Arch) == "" {
			return releaseCompatibilityCertification{}, fmt.Errorf("incomplete compatibility target: %s", id)
		}
		if enhanced {
			if target.JavaMajor <= 0 {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s не содержит javaMajor", id)
			}
			if target.Scope != "client" && target.Scope != "integration" {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s имеет неподдерживаемый scope=%s", id, target.Scope)
			}
			if target.Scope == "client" && target.Loader != "vanilla" {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s: client scope разрешён только для Vanilla", id)
			}
			if target.MatchingServer && !(target.Loader == "vanilla" && target.Scope == "client" && target.OS == "linux" && target.Arch == "x86_64") {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s: matchingServer требует Vanilla client scope на linux/x86_64", id)
			}
		}
		targetByID[id] = target
		if target.Required {
			requiredIDs = append(requiredIDs, id)
			if enhanced {
				requiredLoaderTargets[target.Loader] = true
			}
			if enhanced && target.Loader == "vanilla" {
				requiredVanillaTargets[target.Minecraft] = target
				if _, baseline := vanillaCompatibilityBaselineII[target.Minecraft]; baseline {
					baselineTargets[target.Minecraft] = target
				}
			}
		}
	}
	if len(requiredIDs) == 0 {
		return releaseCompatibilityCertification{}, errors.New("compatibility targets не содержат required targets")
	}
	if enhanced {
		for loader := range allowedLoaders {
			if !requiredLoaderTargets[loader] {
				return releaseCompatibilityCertification{}, fmt.Errorf("compatibility 0.16.2+ missing required loader family %s", loader)
			}
		}
		for minecraft, expected := range vanillaCompatibilityBaselineII {
			target, ok := baselineTargets[minecraft]
			if !ok {
				return releaseCompatibilityCertification{}, fmt.Errorf("Vanilla Compatibility Baseline II missing required Minecraft %s", minecraft)
			}
			if target.JavaMajor != expected.JavaMajor || target.Scope != expected.Scope {
				return releaseCompatibilityCertification{}, fmt.Errorf("Vanilla %s baseline mismatch: expected Java %d scope=%s, got Java %d scope=%s", minecraft, expected.JavaMajor, expected.Scope, target.JavaMajor, target.Scope)
			}
		}
		if compatibilityLegacyVanillaJava8Required(ver) {
			for _, minecraft := range legacyVanillaJava8Compatibility0163 {
				target, ok := requiredVanillaTargets[minecraft]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Legacy Vanilla 0.16.3 missing required Minecraft %s", minecraft)
				}
				if target.JavaMajor != 8 || target.Scope != "client" {
					return releaseCompatibilityCertification{}, fmt.Errorf("Legacy Vanilla %s mismatch: expected Java 8 scope=client, got Java %d scope=%s", minecraft, target.JavaMajor, target.Scope)
				}
			}
		}
		if compatibilityLegacyVanillaPre17Required(ver) {
			for _, minecraft := range legacyVanillaPre17Compatibility0164 {
				target, ok := requiredVanillaTargets[minecraft]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Legacy Vanilla 0.16.4 missing required Minecraft %s", minecraft)
				}
				if target.JavaMajor != 8 || target.Scope != "client" {
					return releaseCompatibilityCertification{}, fmt.Errorf("Legacy Vanilla %s pre-1.7 mismatch: expected Java 8 scope=client, got Java %d scope=%s", minecraft, target.JavaMajor, target.Scope)
				}
			}
		}
		if compatibilityJava16_17VanillaRequired(ver) {
			for minecraft, javaMajor := range java16_17VanillaCompatibility0166 {
				target, ok := requiredVanillaTargets[minecraft]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Java 16/17 Vanilla 0.16.6 missing required Minecraft %s", minecraft)
				}
				if target.JavaMajor != javaMajor || target.Scope != "client" {
					return releaseCompatibilityCertification{}, fmt.Errorf("Java 16/17 Vanilla %s mismatch: expected Java %d scope=client, got Java %d scope=%s", minecraft, javaMajor, target.JavaMajor, target.Scope)
				}
			}
		}
		if compatibilityJava21VanillaRequired(ver) {
			for minecraft, scope := range java21VanillaCompatibility0167 {
				target, ok := requiredVanillaTargets[minecraft]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Java 21 Vanilla 0.16.7 missing required Minecraft %s", minecraft)
				}
				if target.JavaMajor != 21 || target.Scope != scope {
					return releaseCompatibilityCertification{}, fmt.Errorf("Java 21 Vanilla %s mismatch: expected Java 21 scope=%s, got Java %d scope=%s", minecraft, scope, target.JavaMajor, target.Scope)
				}
			}
		}
		if compatibilityJava25VanillaRequired(ver) {
			for minecraft, scope := range java25VanillaCompatibility0168 {
				target, ok := requiredVanillaTargets[minecraft]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Java 25 Vanilla 0.16.8 missing required Minecraft %s", minecraft)
				}
				if target.JavaMajor != 25 || target.Scope != scope {
					return releaseCompatibilityCertification{}, fmt.Errorf("Java 25 Vanilla %s mismatch: expected Java 25 scope=%s, got Java %d scope=%s", minecraft, scope, target.JavaMajor, target.Scope)
				}
			}
		}
		if compatibilityCrossPlatformVanillaRequired(ver) {
			platformTargets := map[string]releaseCompatibilityTarget{}
			for _, target := range targets.Targets {
				if target.Required && target.Loader == "vanilla" && target.Minecraft == "26.3" {
					platformTargets[target.OS+"/"+target.Arch] = target
				}
			}
			for _, platform := range crossPlatformVanillaCompatibility0169 {
				key := platform.OS + "/" + platform.Arch
				target, ok := platformTargets[key]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Cross-platform Vanilla 0.16.9 missing required 26.3 target %s", key)
				}
				if target.JavaMajor != 25 || target.Scope != "client" {
					return releaseCompatibilityCertification{}, fmt.Errorf("Cross-platform Vanilla 26.3 %s mismatch: expected Java 25 scope=client, got Java %d scope=%s", key, target.JavaMajor, target.Scope)
				}
			}
		}
		if compatibilityActualClientE2EIIRequired(ver) {
			for minecraft, javaMajor := range actualClientE2EIICompatibility01610 {
				count := 0
				for _, target := range targets.Targets {
					if target.Required && target.Loader == "vanilla" && target.Minecraft == minecraft && target.OS == "linux" && target.Arch == "x86_64" && target.MatchingServer {
						count++
						if target.JavaMajor != javaMajor || target.Scope != "client" {
							return releaseCompatibilityCertification{}, fmt.Errorf("Actual Client E2E II %s mismatch: expected Java %d scope=client linux/x86_64", minecraft, javaMajor)
						}
					}
				}
				if count != 1 {
					return releaseCompatibilityCertification{}, fmt.Errorf("Actual Client E2E II 0.16.10 requires one matching-server target for Minecraft %s", minecraft)
				}
			}
		}
		if compatibilityLegacyVanilla0170v1Required(ver) {
			for _, minecraft := range legacyVanilla0170v1Releases {
				target, ok := requiredVanillaTargets[minecraft]
				if !ok {
					return releaseCompatibilityCertification{}, fmt.Errorf("Legacy Vanilla 0.17.0v1 missing required Minecraft %s", minecraft)
				}
				if target.JavaMajor != 8 || target.Scope != "client" || target.OS != "linux" || target.Arch != "x86_64" {
					return releaseCompatibilityCertification{}, fmt.Errorf("Legacy Vanilla %s 0.17.0v1 mismatch: expected Java 8 scope=client linux/x86_64, got Java %d scope=%s %s/%s", minecraft, target.JavaMajor, target.Scope, target.OS, target.Arch)
				}
			}
		}
		if compatibilityIIGa0170Required(ver) {
			vanillaTargets := 0
			vanillaVersions := map[string]bool{}
			gaJava := map[int]bool{}
			for _, target := range targets.Targets {
				if target.Required && target.Loader == "vanilla" {
					vanillaTargets++
					vanillaVersions[target.Minecraft] = true
					gaJava[target.JavaMajor] = true
				}
			}
			if vanillaTargets < 98 || len(vanillaVersions) < 93 {
				return releaseCompatibilityCertification{}, fmt.Errorf("Minecraft Compatibility II GA 0.17.0v1 requires >=98 required Vanilla targets and >=93 unique releases; got targets=%d releases=%d", vanillaTargets, len(vanillaVersions))
			}
			for _, major := range []int{8, 16, 17, 21, 25} {
				if !gaJava[major] {
					return releaseCompatibilityCertification{}, fmt.Errorf("Minecraft Compatibility II GA missing JRE major %d", major)
				}
			}
		}
	}

	resultByID := map[string]releaseCompatibilityResult{}
	for _, result := range matrix.Targets {
		id := strings.TrimSpace(result.TargetID)
		if _, ok := targetByID[id]; !ok {
			return releaseCompatibilityCertification{}, fmt.Errorf("matrix содержит unexpected target: %s", id)
		}
		if _, exists := resultByID[id]; exists {
			return releaseCompatibilityCertification{}, fmt.Errorf("matrix содержит duplicate target: %s", id)
		}
		resultByID[id] = result
	}
	if len(resultByID) != len(targetByID) {
		return releaseCompatibilityCertification{}, fmt.Errorf("matrix target count mismatch: expected=%d actual=%d", len(targetByID), len(resultByID))
	}

	legacyMandatoryChecks := []string{"actualClient", "packageVerified", "signedManifest", "cleanSync", "paperJoin", "sessionRevokeDeny", "paperHealthy"}
	clientMandatoryChecks := []string{"materialized", "packageVerified", "runtimeResolved", "javaMatched", "actualClient"}
	integrationMandatoryChecks := []string{"actualClient", "packageVerified", "signedManifest", "cleanSync", "paperJoin", "sessionRevokeDeny", "paperHealthy", "javaMatched"}
	passedIDs := []string{}
	loaderSet := map[string]bool{}
	vanillaVersionSet := map[string]bool{}
	javaMajorSet := map[int]bool{}
	jreBuildSet := map[string]*releaseCompatibilityJREBuild{}
	scopeSet := map[string]bool{}
	mutable := map[string]bool{"latest": true, "latest-stable": true, "recommended": true, "stable": true}
	for id, target := range targetByID {
		result, ok := resultByID[id]
		if !ok {
			return releaseCompatibilityCertification{}, fmt.Errorf("matrix missing target: %s", id)
		}
		if result.SchemaVersion != "1.0" || result.ProductVersion != ver || result.Status != "passed" || result.ExitCode != 0 {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s не имеет валидный PASS/exitCode=0", id)
		}
		if result.MinecraftVersion != target.Minecraft || result.Loader != target.Loader || result.LoaderSelector != target.LoaderVersion || result.OS != target.OS || result.Arch != target.Arch {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s identity mismatch между targets и matrix", id)
		}
		if enhanced {
			if result.JavaMajor != target.JavaMajor || result.DetectedJavaMajor != target.JavaMajor || result.Scope != target.Scope || result.MatchingServer != target.MatchingServer {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s Java/scope/matching mismatch: target Java=%d scope=%s matchingServer=%t, result Java=%d detected=%d scope=%s matchingServer=%t", id, target.JavaMajor, target.Scope, target.MatchingServer, result.JavaMajor, result.DetectedJavaMajor, result.Scope, result.MatchingServer)
			}
		}
		if result.Commit != matrix.Commit || result.RunID != matrix.RunID {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s commit/runId не совпадает с aggregate matrix", id)
		}
		mandatoryChecks := legacyMandatoryChecks
		if enhanced {
			if target.Scope == "client" {
				mandatoryChecks = clientMandatoryChecks
			} else {
				mandatoryChecks = integrationMandatoryChecks
			}
		}
		if compatibilityCrossPlatformVanillaRequired(ver) {
			mandatoryChecks = append(append([]string{}, mandatoryChecks...), "platformMatched")
		}
		if compatibilityActualClientE2EIIRequired(ver) && target.MatchingServer {
			mandatoryChecks = append(append([]string{}, mandatoryChecks...), "matchingServer", "serverVersionMatched", "serverHealthy", "clientJoinedServer")
		}
		if compatibilityIIGa0170Required(ver) {
			mandatoryChecks = append(append([]string{}, mandatoryChecks...), "jreCertified")
		}
		for _, check := range mandatoryChecks {
			if result.Checks == nil || result.Checks[check] != true {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s required check %s != true", id, check)
			}
		}
		if !compatibilitySHA256RE.MatchString(result.EvidenceSHA256) {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s не содержит валидный evidenceSha256", id)
		}
		if compatibilityIIGa0170Required(ver) {
			vendor := strings.TrimSpace(result.JREVendor)
			runtimeVersion := strings.TrimSpace(result.JRERuntimeVersion)
			jreSHA := strings.ToLower(strings.TrimSpace(result.JREExecutableSHA256))
			if vendor == "" || runtimeVersion == "" || !compatibilitySHA256RE.MatchString(jreSHA) {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s не содержит полную certified JRE identity", id)
			}
			key := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%s", target.JavaMajor, target.OS, target.Arch, vendor, runtimeVersion, jreSHA)
			if row, ok := jreBuildSet[key]; ok {
				row.TargetCount++
			} else {
				jreBuildSet[key] = &releaseCompatibilityJREBuild{JavaMajor: target.JavaMajor, OS: target.OS, Arch: target.Arch, Vendor: vendor, RuntimeVersion: runtimeVersion, ExecutableSHA256: jreSHA, TargetCount: 1}
			}
		}
		if target.Loader == "vanilla" {
			if strings.TrimSpace(result.ResolvedLoaderVersion) != "" {
				return releaseCompatibilityCertification{}, fmt.Errorf("Vanilla target %s не должен иметь resolvedLoaderVersion", id)
			}
		} else {
			resolved := strings.ToLower(strings.TrimSpace(result.ResolvedLoaderVersion))
			if resolved == "" || mutable[resolved] {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s не разрешил loader в immutable version", id)
			}
		}
		passedIDs = append(passedIDs, id)
		loaderSet[target.Loader] = true
		if enhanced {
			javaMajorSet[target.JavaMajor] = true
			scopeSet[target.Scope] = true
			if target.Loader == "vanilla" && target.Required {
				vanillaVersionSet[target.Minecraft] = true
			}
		}
	}

	sort.Strings(requiredIDs)
	sort.Strings(passedIDs)
	loaderFamilies := make([]string, 0, len(loaderSet))
	for loader := range loaderSet {
		loaderFamilies = append(loaderFamilies, loader)
	}
	sort.Strings(loaderFamilies)
	vanillaVersions := make([]string, 0, len(vanillaVersionSet))
	for minecraft := range vanillaVersionSet {
		vanillaVersions = append(vanillaVersions, minecraft)
	}
	sort.Strings(vanillaVersions)
	javaMajors := make([]int, 0, len(javaMajorSet))
	for major := range javaMajorSet {
		javaMajors = append(javaMajors, major)
	}
	sort.Ints(javaMajors)
	jreBuilds := make([]releaseCompatibilityJREBuild, 0, len(jreBuildSet))
	for _, row := range jreBuildSet {
		jreBuilds = append(jreBuilds, *row)
	}
	sort.Slice(jreBuilds, func(i, j int) bool {
		a, b := jreBuilds[i], jreBuilds[j]
		if a.JavaMajor != b.JavaMajor {
			return a.JavaMajor < b.JavaMajor
		}
		if a.OS != b.OS {
			return a.OS < b.OS
		}
		if a.Arch != b.Arch {
			return a.Arch < b.Arch
		}
		if a.Vendor != b.Vendor {
			return a.Vendor < b.Vendor
		}
		if a.RuntimeVersion != b.RuntimeVersion {
			return a.RuntimeVersion < b.RuntimeVersion
		}
		return a.ExecutableSHA256 < b.ExecutableSHA256
	})
	scopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	matrixHash := sha256.Sum256(matrixRaw)
	targetsHash := sha256.Sum256(targetsRaw)
	policy := "all-required-targets-must-pass-actual-client-e2e"
	if enhanced {
		policy = "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact"
	}
	if compatibilityLegacyVanillaJava8Required(ver) {
		policy += ";legacy-vanilla-1.7.10-1.16.5-java8"
	}
	if compatibilityLegacyVanillaPre17Required(ver) {
		policy += ";legacy-vanilla-1.0-1.7.10-java8"
	}
	if compatibilityJava16_17VanillaRequired(ver) {
		policy += ";vanilla-1.17.1-1.20.4-java16-17-exact"
	}
	if compatibilityJava21VanillaRequired(ver) {
		policy += ";vanilla-1.20.5-1.21.10-java21-exact"
	}
	if compatibilityJava25VanillaRequired(ver) {
		policy += ";vanilla-26.1.x-26.3-java25-exact"
	}
	if compatibilityCrossPlatformVanillaRequired(ver) {
		policy += ";cross-platform-vanilla-windows-linux-macos-x64-arm64"
	}
	if compatibilityActualClientE2EIIRequired(ver) {
		policy += ";actual-client-e2e-II-real-clients-matching-mojang-servers"
	}
	if compatibilityHardening01611Required(ver) {
		policy += ";compatibility-hardening-cache-recovery-upstream-failure-security"
	}
	if compatibilityLegacyVanilla0170v1Required(ver) {
		policy += ";legacy-vanilla-0.17.0v1-complete-53-release-grid-java8"
	}
	if compatibilityIIGa0170Required(ver) {
		policy += ";minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base"
	}
	return releaseCompatibilityCertification{
		SchemaVersion:     "1.0",
		ProductVersion:    ver,
		CertifiedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Repository:        matrix.Repository,
		Commit:            matrix.Commit,
		RunID:             matrix.RunID,
		MatrixSHA256:      hex.EncodeToString(matrixHash[:]),
		TargetsSHA256:     hex.EncodeToString(targetsHash[:]),
		RequiredTargetIDs: requiredIDs,
		PassedTargetIDs:   passedIDs,
		LoaderFamilies:    loaderFamilies,
		VanillaVersions:   vanillaVersions,
		JavaMajors:        javaMajors,
		JREBuilds:         jreBuilds,
		Scopes:            scopes,
		Policy:            policy,
	}, nil
}

func verifyCompatibilityCertificationInBundle(dir, ver string) error {
	matrixPath := filepath.Join(dir, compatibilityMatrixReleaseFile)
	targetsPath := filepath.Join(dir, compatibilityTargetsReleaseFile)
	certPath := filepath.Join(dir, compatibilityCertificationReleaseFile)
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", compatibilityMatrixReleaseFile, err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", compatibilityTargetsReleaseFile, err)
	}
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", compatibilityCertificationReleaseFile, err)
	}
	var stored releaseCompatibilityCertification
	if err := json.Unmarshal(certRaw, &stored); err != nil {
		return fmt.Errorf("%s invalid: %w", compatibilityCertificationReleaseFile, err)
	}
	expected, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, ver, stored.Commit)
	if err != nil {
		return err
	}
	if stored.SchemaVersion != expected.SchemaVersion || stored.ProductVersion != expected.ProductVersion || stored.Repository != expected.Repository || stored.Commit != expected.Commit || stored.RunID != expected.RunID || stored.MatrixSHA256 != expected.MatrixSHA256 || stored.TargetsSHA256 != expected.TargetsSHA256 || stored.Policy != expected.Policy {
		return errors.New("COMPATIBILITY_CERTIFICATION не соответствует embedded matrix/targets")
	}
	if strings.Join(stored.RequiredTargetIDs, "\x00") != strings.Join(expected.RequiredTargetIDs, "\x00") ||
		strings.Join(stored.PassedTargetIDs, "\x00") != strings.Join(expected.PassedTargetIDs, "\x00") ||
		strings.Join(stored.LoaderFamilies, "\x00") != strings.Join(expected.LoaderFamilies, "\x00") ||
		strings.Join(stored.VanillaVersions, "\x00") != strings.Join(expected.VanillaVersions, "\x00") ||
		fmt.Sprint(stored.JavaMajors) != fmt.Sprint(expected.JavaMajors) ||
		fmt.Sprint(stored.JREBuilds) != fmt.Sprint(expected.JREBuilds) ||
		strings.Join(stored.Scopes, "\x00") != strings.Join(expected.Scopes, "\x00") {
		return errors.New("COMPATIBILITY_CERTIFICATION target/loader/vanilla/java coverage mismatch")
	}
	return nil
}
