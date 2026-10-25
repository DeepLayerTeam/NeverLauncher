package moduleparity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CurrentMatrixPath is the executable, post-0.30.10 evidence inventory.
// The historical MatrixPath is kept unchanged for baseline regression tests.
const CurrentMatrixPath = "compatibility/gravit/module-parity-0310.json"
const PreviousMatrixPath03012 = "compatibility/gravit/module-parity-03012.json"
const PreviousMatrixPath03011 = "compatibility/gravit/module-parity-03011.json"

func LoadCurrentMatrix(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, CurrentMatrixPath), &m)
	return m, err
}

// InspectCurrent checks the current inventory without ever inferring parity.
func InspectCurrent(root string) (Report, error) {
	return inspectEvidenceMatrix03012(root, CurrentMatrixPath, "0.31.0", "0.30.12", true)
}

// Keep the exact previous release auditable without pretending the current tree is 0.30.12.
func InspectPrevious03012(root string) (Report, error) {
 return inspectEvidenceMatrix03012(root, PreviousMatrixPath03012, "0.30.12", "0.30.11", false)
}
func LoadPreviousMatrix03012(root string) (Matrix, error) {
 var m Matrix
 err := readJSON(filepath.Join(root, PreviousMatrixPath03012), &m)
 return m, err
}

// Historical 0.30.11 evidence remains directly auditable after upgrading.
func InspectPrevious03011(root string) (Report, error) {
	return inspectEvidenceMatrix03012(root, PreviousMatrixPath03011, "0.30.11", "0.30.10", false)
}
func LoadPreviousMatrix03011(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, PreviousMatrixPath03011), &m)
	return m, err
}

func inspectEvidenceMatrix03012(root, filename, expectedVersion, expectedBaseline string, requireCurrent bool) (Report, error) {
	baseline, err := Inspect(root)
	if err != nil {
		return Report{}, fmt.Errorf("historical contract regression: %w", err)
	}
	var m Matrix
	if err := readJSON(filepath.Join(root, filename), &m); err != nil {
		return Report{}, err
	}
	versionBytes, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return Report{}, err
	}
	version := strings.TrimSpace(string(versionBytes))
	if (requireCurrent && version != expectedVersion) || m.SchemaVersion != "1.0" || m.ProductVersion != expectedVersion || m.AuditBaseline != expectedBaseline || m.Upstream.Commit != baseline.UpstreamCommit || m.Upstream.Repository != "GravitLauncher/LauncherModules" {
		return Report{}, fmt.Errorf("%s parity matrix/version/upstream mismatch", expectedVersion)
	}
	if len(m.Modules) != 19 {
		return Report{}, fmt.Errorf("expected 19 Gravit modules, got %d", len(m.Modules))
	}
	report := Report{SchemaVersion: "1.0", ProductVersion: expectedVersion, UpstreamCommit: m.Upstream.Commit, AuditStatus: "current-evidence-not-certified", FullyCertified: false, Results: make([]Result, 0, 19)}
	for i, mod := range m.Modules {
		old := baseline.Results[i]
		if mod.ID != old.ModuleID || mod.UpstreamModule != old.UpstreamModule || strings.TrimSpace(mod.Equivalent) == "" || strings.TrimSpace(mod.Limitations) == "" {
			return Report{}, fmt.Errorf("M%02d identity/equivalence invalid", i+1)
		}
		if mod.Status != "partial" && mod.Status != "blocked" && mod.Status != "planned" {
			return Report{}, fmt.Errorf("%s unsafe status %q", mod.ID, mod.Status)
		}
		if old.Status == "blocked" && mod.Status != "blocked" {
			return Report{}, fmt.Errorf("%s unsafe command exclusion cannot be removed", mod.ID)
		}
		if mod.Status == "partial" && (len(mod.SourceRefs) == 0 || len(mod.TestRefs) == 0) {
			return Report{}, fmt.Errorf("%s partial without executable evidence", mod.ID)
		}
		seen := map[string]bool{}
		digests := map[string]string{}
		for _, ref := range append(append([]string{}, mod.SourceRefs...), mod.TestRefs...) {
			if seen[ref] {
				return Report{}, fmt.Errorf("%s duplicate evidence %s", mod.ID, ref)
			}
			seen[ref] = true
			path, e := SafeRepoFile(root, ref)
			if e != nil {
				return Report{}, fmt.Errorf("%s: %w", mod.ID, e)
			}
			sum, e := digest(path)
			if e != nil {
				return Report{}, e
			}
			digests[ref] = sum
		}
		for _, ref := range mod.TestRefs {
			if !strings.HasSuffix(ref, "_test.go") && !strings.HasSuffix(ref, ".test.mjs") {
				return Report{}, fmt.Errorf("%s test is not runnable via parity auditor: %s", mod.ID, ref)
			}
		}
		report.Results = append(report.Results, Result{ModuleID: mod.ID, UpstreamModule: mod.UpstreamModule, Status: mod.Status, SourceValidated: true, SourceDigests: digests, Test: TestOutcome{Status: "not-run"}, Limitations: mod.Limitations})
	}
	return report, nil
}
