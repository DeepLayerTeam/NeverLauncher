package moduleparity

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CurrentMatrixPath — исполняемая опись доказательств после 0.30.10. Исторический
// MatrixPath остаётся неизменным для регрессионной проверки базы.
const CurrentMatrixPath = "compatibility/gravit/module-parity_variant4.json"
const PreviousMatrixPath03012 = "compatibility/gravit/module-parity_variant3.json"
const PreviousMatrixPath03011 = "compatibility/gravit/module-parity_variant2.json"

func LoadCurrentMatrix(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, CurrentMatrixPath), &m)
	return m, err
}

// InspectCurrent проверяет текущую опись, никогда не делая вывод о полной совместимости.
func InspectCurrent(root string) (Report, error) {
	return inspectEvidenceMatrix03012(root, CurrentMatrixPath, "0.31.0", "0.30.12", true)
}

// Сохраняйте возможность аудита точного предыдущего выпуска, не выдавая текущее дерево за 0.30.12.
func InspectPrevious03012(root string) (Report, error) {
	return inspectEvidenceMatrix03012(root, PreviousMatrixPath03012, "0.30.12", "0.30.11", false)
}
func LoadPreviousMatrix03012(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, PreviousMatrixPath03012), &m)
	return m, err
}

// Исторические доказательства 0.30.11 остаются напрямую проверяемыми после обновления.
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
		return Report{}, fmt.Errorf("Нарушение совместимости с историческим контрактом: %w", err)
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
		return Report{}, fmt.Errorf("%s: несовпадение матрицы соответствия, версии или исходного проекта", expectedVersion)
	}
	if len(m.Modules) != 19 {
		return Report{}, fmt.Errorf("Ожидалось 19 модулей Gravit, получено %d", len(m.Modules))
	}
	report := Report{SchemaVersion: "1.0", ProductVersion: expectedVersion, UpstreamCommit: m.Upstream.Commit, AuditStatus: "current-evidence-not-certified", FullyCertified: false, Results: make([]Result, 0, 19)}
	for i, mod := range m.Modules {
		old := baseline.Results[i]
		if mod.ID != old.ModuleID || mod.UpstreamModule != old.UpstreamModule || strings.TrimSpace(mod.Equivalent) == "" || strings.TrimSpace(mod.Limitations) == "" {
			return Report{}, fmt.Errorf("M%02d: недопустимая идентификация или эквивалентность", i+1)
		}
		if mod.Status != "partial" && mod.Status != "blocked" && mod.Status != "planned" {
			return Report{}, fmt.Errorf("%s: небезопасное состояние %q", mod.ID, mod.Status)
		}
		if old.Status == "blocked" && mod.Status != "blocked" {
			return Report{}, fmt.Errorf("%s: исключение небезопасной команды нельзя отменить", mod.ID)
		}
		if mod.Status == "partial" && (len(mod.SourceRefs) == 0 || len(mod.TestRefs) == 0) {
			return Report{}, fmt.Errorf("%s: частичная реализация без исполняемых подтверждений", mod.ID)
		}
		seen := map[string]bool{}
		digests := map[string]string{}
		for _, ref := range append(append([]string{}, mod.SourceRefs...), mod.TestRefs...) {
			if seen[ref] {
				return Report{}, fmt.Errorf("%s: повторяющееся подтверждение %s", mod.ID, ref)
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
				return Report{}, fmt.Errorf("%s: тест нельзя запустить через аудитор соответствия: %s", mod.ID, ref)
			}
		}
		report.Results = append(report.Results, Result{ModuleID: mod.ID, UpstreamModule: mod.UpstreamModule, Status: mod.Status, SourceValidated: true, SourceDigests: digests, Test: TestOutcome{Status: "not-run"}, Limitations: mod.Limitations})
	}
	return report, nil
}

// latestAuditVersionAllowed позволяет проверять неизменяемую базу переноса
// исходников 0.42.11 в новых выпусках. Увеличение версии продукта само по себе не
// делает частичные модули полностью совместимыми.
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

// LatestMatrixPath04211 проверяет те же 19 модулей по ТЕКУЩИМ путям исходников. Наличие локального кода и
// тестов доказывает реализацию, но не сертифицирует совместимость с первоисточником.
const LatestMatrixPath04211 = "compatibility/gravit/module-parity_variant5.json"

func LoadLatestMatrix04211(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, LatestMatrixPath04211), &m)
	return m, err
}

func InspectLatest04211(root string) (Report, error) {
	// Исторический верификатор 0.30.1 ссылается на удалённые в новых выпусках
	// каталоги. Текущий аудит проверяет живые файлы без выполнения устаревшего пути,
	// но сравнивает идентичности с закреплённой описью источника 0.31.0 и не
	// объявляет частичные модули проверенными.
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
		return Report{}, fmt.Errorf("Несовпадение списка или версии модулей Gravit, закреплённых для 0.42.11")
	}
	report := Report{SchemaVersion: "1.0", ProductVersion: strings.TrimSpace(string(version)), UpstreamCommit: current.Upstream.Commit, AuditStatus: "evidence-present-not-certified", FullyCertified: false, Results: make([]Result, 0, 19)}
	for i, mod := range current.Modules {
		expected := fmt.Sprintf("M%02d", i+1)
		if mod.ID != expected || mod.ID != baseline.Modules[i].ID || mod.UpstreamModule != baseline.Modules[i].UpstreamModule || strings.TrimSpace(mod.Equivalent) == "" || strings.TrimSpace(mod.Limitations) == "" || (mod.Status != "partial" && mod.Status != "blocked") || (baseline.Modules[i].Status == "blocked" && mod.Status != "blocked") {
			return Report{}, fmt.Errorf("%s: недопустимый идентификатор, состояние или ограничение", expected)
		}
		if mod.Status == "partial" && (len(mod.SourceRefs) == 0 || len(mod.TestRefs) == 0) {
			return Report{}, fmt.Errorf("%s: отсутствуют исходники или запускаемые тесты", mod.ID)
		}
		seen := map[string]bool{}
		hashes := map[string]string{}
		for _, ref := range append(append([]string{}, mod.SourceRefs...), mod.TestRefs...) {
			if seen[ref] {
				return Report{}, fmt.Errorf("%s: повторяющееся подтверждение %q", mod.ID, ref)
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
				return Report{}, fmt.Errorf("%s: подтверждающий тест не может быть выполнен: %s", mod.ID, ref)
			}
		}
		report.Results = append(report.Results, Result{ModuleID: mod.ID, UpstreamModule: mod.UpstreamModule, Status: mod.Status, SourceValidated: true, SourceDigests: hashes, Test: TestOutcome{Status: "not-run"}, Limitations: mod.Limitations})
	}
	return report, nil
}
