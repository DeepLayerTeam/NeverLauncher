package moduleparity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func currentFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t) // historical evidence and Java contract fixture
	original, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	var m Matrix
	if err = readJSON(filepath.Join(original, CurrentMatrixPath), &m); err != nil {
		t.Fatal(err)
	}
	refs := []string{CurrentMatrixPath}
	for _, mod := range m.Modules {
		refs = append(refs, mod.SourceRefs...)
		refs = append(refs, mod.TestRefs...)
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		data, e := os.ReadFile(filepath.Join(original, ref))
		if e != nil {
			t.Fatal(e)
		}
		target := filepath.Join(root, ref)
		if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(target, data, 0644); e != nil {
			t.Fatal(e)
		}
	}
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("0.30.11\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestModuleParity03011CurrentEvidence(t *testing.T) {
	r, e := InspectCurrent(currentFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if r.ProductVersion != "0.30.11" || len(r.Results) != 19 || r.FullyCertified {
		t.Fatalf("invalid current report: %+v", r)
	}
	for _, mod := range r.Results {
		if !mod.SourceValidated || mod.Test.Status != "not-run" {
			t.Fatalf("falsely certified: %+v", mod)
		}
	}
	if r.Results[1].Status != "partial" || r.Results[16].Status != "blocked" {
		t.Fatal("current implementation status drift")
	}
}
func TestModuleParity03011RejectForgedParity(t *testing.T) {
	for _, kind := range []string{"verified", "missing", "trust"} {
		t.Run(kind, func(t *testing.T) {
			root := currentFixture(t)
			var m Matrix
			if e := readJSON(filepath.Join(root, CurrentMatrixPath), &m); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "verified":
				m.Modules[1].Status = "verified"
			case "missing":
				m.Modules[13].TestRefs = nil
			case "trust":
				m.Modules[16].Status = "partial"
			}
			data, e := json.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(root, CurrentMatrixPath), data, 0644); e != nil {
				t.Fatal(e)
			}
			if _, e = InspectCurrent(root); e == nil {
				t.Fatal("tampered implementation status accepted")
			}
		})
	}
}
