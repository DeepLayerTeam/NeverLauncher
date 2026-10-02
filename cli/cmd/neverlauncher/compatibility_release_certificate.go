package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const loaderCompatibilityReleaseCertificateFile01711 = "LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json"

const loaderCompatibilityReleaseCertificateKind01711 = "neverlauncher-loader-compatibility-release-certificate"

type loaderCompatibilityFamilyCertificate01711 struct {
	Loader               string   `json:"loader"`
	RequiredTargets      int      `json:"requiredTargets"`
	PassedTargets        int      `json:"passedTargets"`
	MinecraftVersions    []string `json:"minecraftVersions"`
	Platforms            []string `json:"platforms"`
	JavaMajors           []int    `json:"javaMajors"`
	Scopes               []string `json:"scopes"`
	PinnedTargets        int      `json:"pinnedTargets"`
	NativeE2ETargets     int      `json:"nativeE2eTargets"`
	CrossPlatformTargets int      `json:"crossPlatformTargets"`
	HardeningTargets     int      `json:"hardeningTargets"`
	EvidenceRootSHA256   string   `json:"evidenceRootSha256"`
}

type loaderCompatibilityPlatformCertificate01711 struct {
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	RequiredTargets int    `json:"requiredTargets"`
	PassedTargets   int    `json:"passedTargets"`
}

type loaderCompatibilityReleaseCertificate01711 struct {
	SchemaVersion                    string                                        `json:"schemaVersion"`
	Kind                             string                                        `json:"kind"`
	ProductVersion                   string                                        `json:"productVersion"`
	Status                           string                                        `json:"status"`
	CertifiedAt                      string                                        `json:"certifiedAt"`
	Repository                       string                                        `json:"repository"`
	Commit                           string                                        `json:"commit"`
	RunID                            string                                        `json:"runId"`
	CompatibilityCertificationSHA256 string                                        `json:"compatibilityCertificationSha256"`
	MatrixSHA256                     string                                        `json:"matrixSha256"`
	TargetsSHA256                    string                                        `json:"targetsSha256"`
	EvidenceRootSHA256               string                                        `json:"evidenceRootSha256"`
	CertificateID                    string                                        `json:"certificateId"`
	RequiredTargetCount              int                                           `json:"requiredTargetCount"`
	PassedTargetCount                int                                           `json:"passedTargetCount"`
	LoaderFamilies                   []loaderCompatibilityFamilyCertificate01711   `json:"loaderFamilies"`
	Platforms                        []loaderCompatibilityPlatformCertificate01711 `json:"platforms"`
	JavaMajors                       []int                                         `json:"javaMajors"`
	Scopes                           []string                                      `json:"scopes"`
	Invariants                       map[string]bool                               `json:"invariants"`
	Policy                           string                                        `json:"policy"`
}

type loaderCompatibilityReleaseCertificateIdentity01711 struct {
	SchemaVersion                    string                                        `json:"schemaVersion"`
	Kind                             string                                        `json:"kind"`
	ProductVersion                   string                                        `json:"productVersion"`
	Status                           string                                        `json:"status"`
	CertifiedAt                      string                                        `json:"certifiedAt"`
	Repository                       string                                        `json:"repository"`
	Commit                           string                                        `json:"commit"`
	RunID                            string                                        `json:"runId"`
	CompatibilityCertificationSHA256 string                                        `json:"compatibilityCertificationSha256"`
	MatrixSHA256                     string                                        `json:"matrixSha256"`
	TargetsSHA256                    string                                        `json:"targetsSha256"`
	EvidenceRootSHA256               string                                        `json:"evidenceRootSha256"`
	RequiredTargetCount              int                                           `json:"requiredTargetCount"`
	PassedTargetCount                int                                           `json:"passedTargetCount"`
	LoaderFamilies                   []loaderCompatibilityFamilyCertificate01711   `json:"loaderFamilies"`
	Platforms                        []loaderCompatibilityPlatformCertificate01711 `json:"platforms"`
	JavaMajors                       []int                                         `json:"javaMajors"`
	Scopes                           []string                                      `json:"scopes"`
	Invariants                       map[string]bool                               `json:"invariants"`
	Policy                           string                                        `json:"policy"`
}

func compatibilityReleaseCertificate01711Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 17, 11)
}

func loaderCompatibilityEvidenceRoot01711(results []releaseCompatibilityResult, loader string) string {
	rows := make([]releaseCompatibilityResult, 0, len(results))
	for _, result := range results {
		if loader == "" || result.Loader == loader {
			rows = append(rows, result)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TargetID < rows[j].TargetID })
	digest := sha256.New()
	for _, result := range rows {
		checks := make([]string, 0, len(result.Checks))
		for name, passed := range result.Checks {
			checks = append(checks, fmt.Sprintf("%s=%t", name, passed))
		}
		sort.Strings(checks)
		fmt.Fprintf(digest, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\n",
			result.TargetID,
			strings.ToLower(strings.TrimSpace(result.EvidenceSHA256)),
			result.ResolvedLoaderVersion,
			strings.ToLower(strings.TrimSpace(result.ResolutionLockSHA256)),
			strings.ToLower(strings.TrimSpace(result.ResolutionSourceSHA256)),
			strings.ToLower(strings.TrimSpace(result.ReproducibilitySHA256)),
			result.JREExecutableSHA256,
			result.OS+"/"+result.Arch,
			strings.Join(checks, ","),
		)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func buildLoaderCompatibilityReleaseCertificate01711(matrixRaw, targetsRaw, compatibilityCertificationRaw []byte, certification releaseCompatibilityCertification) (loaderCompatibilityReleaseCertificate01711, error) {
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		return loaderCompatibilityReleaseCertificate01711{}, fmt.Errorf("release certificate targets: %w", err)
	}
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		return loaderCompatibilityReleaseCertificate01711{}, fmt.Errorf("release certificate matrix: %w", err)
	}
	if matrix.ProductVersion != certification.ProductVersion || matrix.Repository != certification.Repository || matrix.Commit != certification.Commit || matrix.RunID != certification.RunID {
		return loaderCompatibilityReleaseCertificate01711{}, errors.New("loader compatibility release certificate cohort mismatch")
	}

	requiredByID := make(map[string]releaseCompatibilityTarget, len(targets.Targets))
	for _, target := range targets.Targets {
		if target.Required {
			requiredByID[target.ID] = target
		}
	}
	resultByID := make(map[string]releaseCompatibilityResult, len(matrix.Targets))
	for _, result := range matrix.Targets {
		resultByID[result.TargetID] = result
	}

	familyNames := []string{"vanilla", "fabric", "quilt", "forge", "neoforge"}
	families := make([]loaderCompatibilityFamilyCertificate01711, 0, len(familyNames))
	for _, loader := range familyNames {
		minecraftSet := map[string]bool{}
		platformSet := map[string]bool{}
		javaSet := map[int]bool{}
		scopeSet := map[string]bool{}
		requiredCount := 0
		passedCount := 0
		pinnedCount := 0
		nativeCount := 0
		crossPlatformCount := 0
		hardeningCount := 0
		for id, target := range requiredByID {
			if target.Loader != loader {
				continue
			}
			requiredCount++
			minecraftSet[target.Minecraft] = true
			platformSet[target.OS+"/"+target.Arch] = true
			javaSet[target.JavaMajor] = true
			scopeSet[target.Scope] = true
			result, ok := resultByID[id]
			if ok && result.Status == "passed" && result.ExitCode == 0 {
				passedCount++
			}
			if loader != "vanilla" && compatibilitySHA256RE.MatchString(strings.ToLower(strings.TrimSpace(result.ResolutionLockSHA256))) {
				pinnedCount++
			}
			if result.Checks["loaderNativeClientJoin"] {
				nativeCount++
			}
			if result.Checks["loaderPlatformLaunch"] {
				crossPlatformCount++
			}
			if result.Checks["loaderCacheVerified"] && result.Checks["loaderUpstreamRecovery"] {
				hardeningCount++
			}
		}
		minecraftVersions := sortedStringSet01711(minecraftSet)
		platforms := sortedStringSet01711(platformSet)
		javaMajors := sortedIntSet01711(javaSet)
		scopes := sortedStringSet01711(scopeSet)
		families = append(families, loaderCompatibilityFamilyCertificate01711{
			Loader: loader, RequiredTargets: requiredCount, PassedTargets: passedCount,
			MinecraftVersions: minecraftVersions, Platforms: platforms, JavaMajors: javaMajors, Scopes: scopes,
			PinnedTargets: pinnedCount, NativeE2ETargets: nativeCount, CrossPlatformTargets: crossPlatformCount,
			HardeningTargets: hardeningCount, EvidenceRootSHA256: loaderCompatibilityEvidenceRoot01711(matrix.Targets, loader),
		})
	}

	platformKeys := map[string]bool{}
	for _, target := range requiredByID {
		platformKeys[target.OS+"/"+target.Arch] = true
	}
	platformNames := sortedStringSet01711(platformKeys)
	platforms := make([]loaderCompatibilityPlatformCertificate01711, 0, len(platformNames))
	for _, key := range platformNames {
		parts := strings.SplitN(key, "/", 2)
		row := loaderCompatibilityPlatformCertificate01711{OS: parts[0], Arch: parts[1]}
		for id, target := range requiredByID {
			if target.OS+"/"+target.Arch != key {
				continue
			}
			row.RequiredTargets++
			if result, ok := resultByID[id]; ok && result.Status == "passed" && result.ExitCode == 0 {
				row.PassedTargets++
			}
		}
		platforms = append(platforms, row)
	}

	certDigest := sha256.Sum256(compatibilityCertificationRaw)
	passedIDSet := map[string]bool{}
	for _, id := range certification.PassedTargetIDs {
		passedIDSet[id] = true
	}
	requiredPassedCount := 0
	allRequiredPassed := len(certification.RequiredTargetIDs) == len(requiredByID)
	for id := range requiredByID {
		result, ok := resultByID[id]
		if ok && result.Status == "passed" && result.ExitCode == 0 && passedIDSet[id] {
			requiredPassedCount++
			continue
		}
		allRequiredPassed = false
	}
	completeFamilyCoverage := len(certification.LoaderFamilies) == len(familyNames)
	certifiedFamilies := map[string]bool{}
	for _, loader := range certification.LoaderFamilies {
		certifiedFamilies[loader] = true
	}
	for _, name := range familyNames {
		if !certifiedFamilies[name] {
			completeFamilyCoverage = false
			break
		}
	}
	immutableLoaderPins := true
	if compatibilityLoaderResolution0177Required(certification.ProductVersion) {
		want := 0
		for _, target := range requiredByID {
			if target.Loader != "vanilla" {
				want++
			}
		}
		immutableLoaderPins = len(certification.LoaderPins) == want
	}
	loaderNativeE2E := !compatibilityLoaderNativeE2E0178Required(certification.ProductVersion) || len(certification.LoaderNativeTargets) == 4
	crossPlatformLoaders := !compatibilityCrossPlatformLoaders0179Required(certification.ProductVersion) || len(certification.CrossPlatformLoaderTargets) == 24
	loaderHardening := !compatibilityLoaderHardening01710Required(certification.ProductVersion) || len(certification.LoaderHardeningTargets) == 4
	certifiedJRE := len(certification.JREBuilds) > 0 && len(certification.JavaMajors) > 0
	invariants := map[string]bool{
		"allRequiredTargetsPassed":     allRequiredPassed,
		"matrixTargetsBound":           certification.MatrixSHA256 != "" && certification.TargetsSHA256 != "",
		"exactSourceCommit":            strings.TrimSpace(certification.Commit) != "",
		"completeLoaderFamilyCoverage": completeFamilyCoverage,
		"certifiedJREIdentity":         certifiedJRE,
		"immutableLoaderPins":          immutableLoaderPins,
		"loaderNativeE2E":              loaderNativeE2E,
		"crossPlatformLoaders":         crossPlatformLoaders,
		"loaderHardeningRecovery":      loaderHardening,
	}
	for name, ok := range invariants {
		if !ok {
			return loaderCompatibilityReleaseCertificate01711{}, fmt.Errorf("loader compatibility RC invariant %s=false", name)
		}
	}

	cert := loaderCompatibilityReleaseCertificate01711{
		SchemaVersion:                    "1.0",
		Kind:                             loaderCompatibilityReleaseCertificateKind01711,
		ProductVersion:                   certification.ProductVersion,
		Status:                           "certified",
		CertifiedAt:                      certification.CertifiedAt,
		Repository:                       certification.Repository,
		Commit:                           certification.Commit,
		RunID:                            certification.RunID,
		CompatibilityCertificationSHA256: hex.EncodeToString(certDigest[:]),
		MatrixSHA256:                     certification.MatrixSHA256,
		TargetsSHA256:                    certification.TargetsSHA256,
		EvidenceRootSHA256:               loaderCompatibilityEvidenceRoot01711(matrix.Targets, ""),
		RequiredTargetCount:              len(requiredByID),
		PassedTargetCount:                requiredPassedCount,
		LoaderFamilies:                   families,
		Platforms:                        platforms,
		JavaMajors:                       append([]int(nil), certification.JavaMajors...),
		Scopes:                           append([]string(nil), certification.Scopes...),
		Invariants:                       invariants,
		Policy:                           "loader-compatibility-rc-0.17.11-full-release-certificate-all-292-targets-evidence-root-signed-bundle",
	}
	identity := loaderCompatibilityReleaseCertificateIdentity01711{
		SchemaVersion: cert.SchemaVersion, Kind: cert.Kind, ProductVersion: cert.ProductVersion, Status: cert.Status,
		CertifiedAt: cert.CertifiedAt, Repository: cert.Repository, Commit: cert.Commit, RunID: cert.RunID,
		CompatibilityCertificationSHA256: cert.CompatibilityCertificationSHA256, MatrixSHA256: cert.MatrixSHA256,
		TargetsSHA256: cert.TargetsSHA256, EvidenceRootSHA256: cert.EvidenceRootSHA256,
		RequiredTargetCount: cert.RequiredTargetCount, PassedTargetCount: cert.PassedTargetCount,
		LoaderFamilies: cert.LoaderFamilies, Platforms: cert.Platforms, JavaMajors: cert.JavaMajors, Scopes: cert.Scopes,
		Invariants: cert.Invariants, Policy: cert.Policy,
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return loaderCompatibilityReleaseCertificate01711{}, err
	}
	identityDigest := sha256.Sum256(identityRaw)
	cert.CertificateID = "sha256:" + hex.EncodeToString(identityDigest[:])
	return cert, nil
}

func writeLoaderCompatibilityReleaseCertificate01711(out string, matrixRaw, targetsRaw []byte, certification releaseCompatibilityCertification) error {
	compatRaw, err := os.ReadFile(filepath.Join(out, compatibilityCertificationReleaseFile))
	if err != nil {
		return err
	}
	cert, err := buildLoaderCompatibilityReleaseCertificate01711(matrixRaw, targetsRaw, compatRaw, certification)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(out, loaderCompatibilityReleaseCertificateFile01711), cert)
}

func verifyLoaderCompatibilityReleaseCertificate01711(dir, ver string) error {
	if !compatibilityReleaseCertificate01711Required(ver) {
		return nil
	}
	matrixRaw, err := os.ReadFile(filepath.Join(dir, compatibilityMatrixReleaseFile))
	if err != nil {
		return err
	}
	targetsRaw, err := os.ReadFile(filepath.Join(dir, compatibilityTargetsReleaseFile))
	if err != nil {
		return err
	}
	compatRaw, err := os.ReadFile(filepath.Join(dir, compatibilityCertificationReleaseFile))
	if err != nil {
		return err
	}
	var compatibilityCertification releaseCompatibilityCertification
	if err := json.Unmarshal(compatRaw, &compatibilityCertification); err != nil {
		return fmt.Errorf("%s invalid: %w", compatibilityCertificationReleaseFile, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, loaderCompatibilityReleaseCertificateFile01711))
	if err != nil {
		return fmt.Errorf("%s missing: %w", loaderCompatibilityReleaseCertificateFile01711, err)
	}
	var stored loaderCompatibilityReleaseCertificate01711
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("%s invalid: %w", loaderCompatibilityReleaseCertificateFile01711, err)
	}
	expected, err := buildLoaderCompatibilityReleaseCertificate01711(matrixRaw, targetsRaw, compatRaw, compatibilityCertification)
	if err != nil {
		return err
	}
	storedRaw, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	expectedRaw, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	if string(storedRaw) != string(expectedRaw) {
		return errors.New("LOADER_COMPATIBILITY_RELEASE_CERTIFICATE не соответствует embedded compatibility cohort")
	}
	return nil
}

func sortedStringSet01711(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sortedIntSet01711(set map[int]bool) []int {
	values := make([]int, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Ints(values)
	return values
}
