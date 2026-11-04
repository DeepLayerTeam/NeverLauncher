package moduleparity

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// latestAuditVersionAllowed keeps the immutable 0.42.11 source-port baseline
// auditable in newer releases. It does not imply that partial modules became
// fully compatible merely because the product version was incremented.
func latestAuditVersionAllowed(version string) bool {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) != 3 {
		return false
	}
	major, e0 := strconv.Atoi(parts[0])
	minor, e1 := strconv.Atoi(parts[1])
	patch, e2 := strconv.Atoi(parts[2])
	if e0 != nil || e1 != nil || e2 != nil || major < 0 || minor < 0 || patch < 0 {
		return false
	}
	return major > 0 || (major == 0 && (minor > 42 || minor == 42 && patch >= 11))
}

// LatestMatrixPath04211 inventories the same 19 modules using CURRENT source paths.
// Local source/tests are evidence of implementations, not upstream parity certification.
const LatestMatrixPath04211 = "compatibility/gravit/module-parity-04211.json"

func LoadLatestMatrix04211(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, LatestMatrixPath04211), &m)
	return m, err
}

func InspectLatest04211(root string) (Report, error) {
	// The 0.30.1 historical checker refers to directories removed in modern
	// releases. This current audit validates live files without executing the
	// stale historical path; it still compares identities to the pinned 0.31.0
	// upstream inventory and never promotes partial modules to verified.
	var current, baseline Matrix
	if err := readJSON(filepath.Join(root, LatestMatrixPath04211), &current); err != nil {
		return Report{}, err
	}
	if err := readJSON(filepath.Join(root, CurrentMatrixPath), &baseline); err != nil {
		return Report{}, err
	}
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return Report{}, err
	}
	if !latestAuditVersionAllowed(string(version)) || current.SchemaVersion != "1.0" || current.ProductVersion != "0.42.11" || current.AuditBaseline != "0.31.0" || current.Upstream != baseline.Upstream || len(current.Modules) != 19 || len(baseline.Modules) != 19 {
		return Report{}, fmt.Errorf("pinned 0.42.11 Gravit module inventory/version mismatch")
	}
	report := Report{SchemaVersion: "1.0", ProductVersion: strings.TrimSpace(string(version)), UpstreamCommit: current.Upstream.Commit, AuditStatus: "evidence-present-not-certified", FullyCertified: false, Results: make([]Result, 0, 19)}
	for i, mod := range current.Modules {
		expected := fmt.Sprintf("M%02d", i+1)
		if mod.ID != expected || mod.ID != baseline.Modules[i].ID || mod.UpstreamModule != baseline.Modules[i].UpstreamModule || strings.TrimSpace(mod.Equivalent) == "" || strings.TrimSpace(mod.Limitations) == "" || (mod.Status != "partial" && mod.Status != "blocked") || (baseline.Modules[i].Status == "blocked" && mod.Status != "blocked") {
			return Report{}, fmt.Errorf("%s invalid identity, status or limitation", expected)
		}
		if mod.Status == "partial" && (len(mod.SourceRefs) == 0 || len(mod.TestRefs) == 0) {
			return Report{}, fmt.Errorf("%s missing source or runnable tests", mod.ID)
		}
		seen := map[string]bool{}
		hashes := map[string]string{}
		for _, ref := range append(append([]string{}, mod.SourceRefs...), mod.TestRefs...) {
			if seen[ref] {
				return Report{}, fmt.Errorf("%s duplicate evidence %q", mod.ID, ref)
			}
			seen[ref] = true
			safe, err := SafeRepoFile(root, ref)
			if err != nil {
				return Report{}, fmt.Errorf("%s: %w", mod.ID, err)
			}
			sum, err := digest(safe)
			if err != nil {
				return Report{}, err
			}
			hashes[ref] = sum
		}
		for _, ref := range mod.TestRefs {
			if !strings.HasSuffix(ref, "_test.go") && !strings.HasSuffix(ref, ".test.mjs") {
				return Report{}, fmt.Errorf("%s unexecutable test evidence: %s", mod.ID, ref)
			}
		}
		report.Results = append(report.Results, Result{ModuleID: mod.ID, UpstreamModule: mod.UpstreamModule, Status: mod.Status, SourceValidated: true, SourceDigests: hashes, Test: TestOutcome{Status: "not-run"}, Limitations: mod.Limitations})
	}
	return report, nil
}
