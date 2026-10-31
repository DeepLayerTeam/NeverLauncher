package moduleparity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func latestFixture04211(t *testing.T) string {
	t.Helper()
	original, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	var matrix Matrix
	if err := readJSON(filepath.Join(original, LatestMatrixPath04211), &matrix); err != nil {
		t.Fatal(err)
	}
	references := []string{"VERSION", LatestMatrixPath04211, CurrentMatrixPath}
	for _, mod := range matrix.Modules {
		references = append(references, mod.SourceRefs...)
		references = append(references, mod.TestRefs...)
	}
	seen := map[string]bool{}
	for _, rel := range references {
		if seen[rel] {
			continue
		}
		seen[rel] = true
		originalPath, err := SafeRepoFile(original, rel)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(originalPath)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return tmp
}

func TestLatest04211EvidenceAndStatus(t *testing.T) {
	root := latestFixture04211(t)
	got, err := InspectLatest04211(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.FullyCertified || got.ProductVersion != "0.42.11" || len(got.Results) != 19 {
		t.Fatalf("wrong results: %+v", got)
	}
	for i, r := range got.Results {
		if r.Test.Status != "not-run" || !r.SourceValidated || len(r.SourceDigests) == 0 {
			t.Fatalf("fake runtime evidence M%02d: %+v", i+1, r)
		}
		if i == 16 && r.Status != "blocked" {
			t.Fatal("unsafe command pack must remain blocked")
		}
		if i != 16 && r.Status != "partial" {
			t.Fatalf("M%02d status was promoted without execution", i+1)
		}
	}
}

func TestLatest04211FailsClosed(t *testing.T) {
	for _, mutation := range []string{"unsafe", "verified", "missing", "unknown", "baseline"} {
		t.Run(mutation, func(t *testing.T) {
			root := latestFixture04211(t)
			file := filepath.Join(root, LatestMatrixPath04211)
			var m Matrix
			if err := readJSON(file, &m); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "unsafe":
				m.Modules[16].Status = "partial"
			case "verified":
				m.Modules[0].Status = "verified"
			case "missing":
				m.Modules[1].SourceRefs[0] = "cli/does-not-exist.go"
			case "unknown":
				m.Modules[1].UpstreamModule = "ForgedModule"
			case "baseline":
				m.AuditBaseline = "0.42.0"
			}
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectLatest04211(root); err == nil {
				t.Fatal("forged evidence was accepted")
			}
		})
	}
}
