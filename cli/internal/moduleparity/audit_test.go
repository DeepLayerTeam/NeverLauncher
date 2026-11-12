package moduleparity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	original, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var m Matrix
	if err := readJSON(filepath.Join(original, MatrixPath), &m); err != nil {
		t.Fatal(err)
	}
	refs := []string{"VERSION", MatrixPath, HistoricalPath, JavaContractPath, "sdk/api/extension-host-protocol.json", "services/api/internal/extensioncontract/contract.go", "services/api/internal/extensionhost/host.go"}
	for _, mod := range m.Modules {
		refs = append(refs, mod.SourceRefs...)
		refs = append(refs, mod.TestRefs...)
	}
	seen := map[string]bool{}
	for _, relative := range refs {
		if seen[relative] {
			continue
		}
		seen[relative] = true
		b, e := os.ReadFile(filepath.Join(original, relative))
		if e != nil {
			t.Fatal(e)
		}
		dest := filepath.Join(root, relative)
		if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dest, b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	return root
}
func editMatrix(t *testing.T, root string, modify func(*Matrix)) {
	t.Helper()
	var m Matrix
	if err := readJSON(filepath.Join(root, MatrixPath), &m); err != nil {
		t.Fatal(err)
	}
	modify(&m)
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, MatrixPath), b, 0644); e != nil {
		t.Fatal(e)
	}
}
func TestAudit0301ValidSourceInventoryDoesNotClaimParity(t *testing.T) {
	root := fixture(t)
	r, e := Inspect(root)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Results) != 19 || r.FullyCertified {
		t.Fatalf("Недействительный отчёт аудита %#v", r)
	}
	for _, v := range r.Results {
		if !v.SourceValidated || v.Test.Status != "not-run" {
			t.Fatalf("Статическая проверка ошибочно выдаётся за запуск тестов: %#v", v)
		}
	}
}
func TestAudit0301RejectsDuplicateAndOverclaim(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Matrix)
	}{
		{"duplicate", func(m *Matrix) { m.Modules[1].ID = "M01" }},
		{"forged full parity", func(m *Matrix) { m.Modules[0].Status = "verified" }},
		{"Отсутствует тест", func(m *Matrix) { m.Modules[0].TestRefs = nil }},
		{"wrong revision", func(m *Matrix) { m.Upstream.Commit = strings.Repeat("a", 40) }},
		{"Выход за пределы допустимого пути", func(m *Matrix) { m.Modules[0].SourceRefs = []string{"../../private"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixture(t)
			editMatrix(t, root, tc.edit)
			if _, e := Inspect(root); e == nil {
				t.Fatal("Приняты изменённые посторонним образом данные")
			}
		})
	}
}
func TestAudit0301RejectsJavaHostVersionDrift(t *testing.T) {
	root := fixture(t)
	path := filepath.Join(root, "sdk/api/extension-host-protocol.json")
	bytes, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b := strings.Replace(string(bytes), `"hostProtocolVersion": "1.0"`, `"hostProtocolVersion": "999.0"`, 1)
	if e = os.WriteFile(path, []byte(b), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Inspect(root); e == nil {
		t.Fatal("Принят несовместимый Java ABI")
	}
}
func TestAudit0301RefusesSymlinks(t *testing.T) {
	root := fixture(t)
	real := filepath.Join(root, "VERSION")
	link := filepath.Join(root, "unsafe-link")
	if e := os.Symlink(real, link); e != nil {
		t.Skip(e)
	}
	if _, e := SafeRepoFile(root, "unsafe-link"); e == nil {
		t.Fatal("Принята символьная ссылка")
	}
	for _, p := range []string{"../VERSION", "/etc/passwd", "services//VERSION", "."} {
		if _, e := SafeRepoFile(root, p); e == nil {
			t.Errorf("Принят небезопасный путь %q", p)
		}
	}
}
func TestAudit0301VersionDrift(t *testing.T) {
	root := fixture(t)
	if e := os.WriteFile(filepath.Join(root, "VERSION"), []byte("0.30.0\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Inspect(root); e == nil {
		t.Fatal("Принято расхождение версий")
	}
}

func TestAudit0302PinnedBaselineSupportsLaterRelease(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("0.30.2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.ProductVersion != "0.30.2" || report.FullyCertified || len(report.Results) != 19 {
		t.Fatalf("Недействительный отчёт: %+v", report)
	}
	for _, version := range []string{"0.30.0", "0.29.99", "0.30.01", "2.bad.0"} {
		if notBeforeModuleAudit0302(version) {
			t.Fatalf("Принят несовместимый выпуск %s", version)
		}
	}
}
