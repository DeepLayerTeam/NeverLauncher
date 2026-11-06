package httpapi

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Пользовательский выбор задаётся разделёнными запятыми ID подписанных компонентов, никогда путями.
var validationPreset0348 = regexp.MustCompile(`^[a-zA-Z0-9_.:/@+,\-]{1,160}$`)

// RequiredMatrixSelections0348 получает ОБЯЗАТЕЛЬНЫЙ набор вариантов из снимка ПОДПИСАННОГО выпуска, а не
// из отчётов обработчиков. Дополнительные ограниченные случаи — детерминированные совместимые попарные
// выборы. Это намеренно НЕ означает проверку всех 2^N комбинаций.
func RequiredMatrixSelections0348(cat *model.ComponentCatalog0241) ([]string, int, error) {
	if cat == nil {
		return []string{"default"}, 0, nil
	}
	if len(cat.Components) == 0 && len(cat.Presets) == 0 {
		return []string{"default"}, 0, nil
	}
	presets := make([]string, 0, len(cat.Presets))
	for _, p := range cat.Presets {
		presets = append(presets, p.ID)
	}
	sort.Strings(presets)
	if len(presets) == 0 {
		presets = []string{"default"}
	}
	// Выбирайте минимальную подписанную базу, чтобы не проверять повторно комбинации из стандартного
	// опубликованного набора пресетов.
	base := ""
	min := int(^uint(0) >> 1)
	for _, p := range cat.Presets {
		if len(p.Components) < min {
			base = p.ID
			min = len(p.Components)
		}
	}
	available := make([]string, 0)
	for _, c := range cat.Components {
		if c.Required || c.Limited || (c.Visible != nil && !*c.Visible) {
			continue
		}
		available = append(available, c.ID)
	}
	sort.Strings(available)
	// Фиксированный документированный верхний предел защищает инфраструктуру аттестации. Непокрытые кандидаты
	// указываются отдельно и никогда не объявляются проверенными. Перебор подмножеств и экспоненциальное время
	// работы не применяются.
	const maxAdditionalPairs = 12
	conditional := make([]string, 0)
	pairs := make([]string, 0, maxAdditionalPairs)
	unchecked := 0
	// Каждый необязательный компонент с условиями, который не включён ни одним опубликованным пресетом,
	// получает отдельную положительную проверку независимо от пар.
	for _, c := range cat.Components {
		if c.Conditions == nil || c.Required || c.Limited || (c.Visible != nil && !*c.Visible) {
			continue
		}
		named := false
		for _, p := range cat.Presets {
			if contains0348(p.Components, c.ID) {
				named = true
				break
			}
		}
		if named {
			continue
		}
		choice := "@custom:v1:" + base + ":+" + c.ID
		if len(choice) > 160 || !compatiblePair0348(cat, base, []string{c.ID}) {
			unchecked++
		} else {
			conditional = append(conditional, choice)
		}
	}
	// Каждый достижимый компонент с условиями обязателен к проверке. В отличие от попарного необязательного
	// покрытия, его нельзя незаметно усечь. Лимит настроенных целей — 128, чтобы осталось место для попарных
	// проверок.
	if len(conditional)+len(presets) > 116 {
		return nil, 0, fmt.Errorf("Матрица компонентов превышает возможности доступных целей: %d обязательных выборов по предустановкам или условиям", len(conditional)+len(presets))
	}
	const maxCandidatePairs = 512
	examined := 0
	totalPairs := len(available) * (len(available) - 1) / 2
	for i := 0; i < len(available); i++ {
		for j := i + 1; j < len(available); j++ {
			if examined >= maxCandidatePairs {
				// Все прочие возможные пары считаются НЕПРОВЕРЕННЫМИ, а не пройденными. Не выполняйте O(N^2) операций
				// резолвера для каталога из 4096 компонентов.
				unchecked += totalPairs - examined
				selections := append(append(presets, conditional...), pairs...)
				return selections, unchecked, nil
			}
			examined++
			ids := []string{available[i], available[j]}
			if !compatiblePair0348(cat, base, ids) {
				continue
			}
			covered := false
			for _, p := range cat.Presets {
				if contains0348(p.Components, ids[0]) && contains0348(p.Components, ids[1]) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			choice := "@custom:v1:" + base + ":+" + ids[0] + ",+" + ids[1]
			if len(choice) > 160 {
				unchecked++
				continue
			}
			if len(pairs) < maxAdditionalPairs {
				pairs = append(pairs, choice)
			} else {
				unchecked++
			}
		}
	}
	selections := append(append(presets, conditional...), pairs...)
	return selections, unchecked, nil
}
func contains0348(items []string, value string) bool {
	for _, i := range items {
		if i == value {
			return true
		}
	}
	return false
}
func compatiblePair0348(cat *model.ComponentCatalog0241, base string, ids []string) bool {
	// Используйте промышленный резолвер зависимостей и конфликтов для временного выбора в памяти; сам каталог
	// и подписанный дайджест не изменяются.
	copyCat := *cat
	copyCat.Presets = append(append([]model.CatalogPreset0242(nil), cat.Presets...), model.CatalogPreset0242{ID: "matrix_case_0348", Name: "matrix case", Components: append([]string(nil), ids...)})
	if base != "" {
		for _, p := range cat.Presets {
			if p.ID == base {
				for _, id := range p.Components {
					if !contains0348(copyCat.Presets[len(copyCat.Presets)-1].Components, id) {
						copyCat.Presets[len(copyCat.Presets)-1].Components = append(copyCat.Presets[len(copyCat.Presets)-1].Components, id)
					}
				}
				break
			}
		}
	} else {
		for _, c := range cat.Components {
			if c.Default && !contains0348(copyCat.Presets[len(copyCat.Presets)-1].Components, c.ID) {
				copyCat.Presets[len(copyCat.Presets)-1].Components = append(copyCat.Presets[len(copyCat.Presets)-1].Components, c.ID)
			}
		}
	}
	resolved, err := model.PreviewCatalogGraph0248(copyCat, "matrix_case_0348")
	if err != nil {
		return false
	}
	// Пара может быть совместима по графу, но невозможна на любом компьютере (только Windows вместе с только
	// Linux, несовместимые диапазоны Java и т. п.). Не добавляйте такую недостижимую цель в обязательную
	// матрицу.
	byID := map[string]model.CatalogComponent0241{}
	for _, c := range cat.Components {
		byID[c.ID] = c
	}
	for i := 0; i < len(resolved); i++ {
		for j := i + 1; j < len(resolved); j++ {
			if !coReachable0348(byID[resolved[i]].Conditions, byID[resolved[j]].Conditions) {
				return false
			}
		}
	}
	return true
}
func overlap0348(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		if contains0348(b, x) {
			return true
		}
	}
	return false
}
func coReachable0348(a, b *model.ComponentConditions0244) bool {
	if a == nil || b == nil {
		return true
	}
	if !overlap0348(a.OS, b.OS) || !overlap0348(a.Arch, b.Arch) ||
		!overlap0348(a.MinecraftVersions, b.MinecraftVersions) || !overlap0348(a.Loaders, b.Loaders) {
		return false
	}
	low := a.JavaMajorMin
	if b.JavaMajorMin > low {
		low = b.JavaMajorMin
	}
	high := uint32(99)
	if a.JavaMajorMax > 0 && a.JavaMajorMax < high {
		high = a.JavaMajorMax
	}
	if b.JavaMajorMax > 0 && b.JavaMajorMax < high {
		high = b.JavaMajorMax
	}
	return low <= high
}

// Проверка применяется при выдаче разрешения, приёмке доказательств и чтении покрытия. Отсутствующие
// пресеты нельзя скрыть матрицей оператора из одного элемента.
func validateComponentMatrix0348(manifest model.Manifest, targets []validationTarget0346) error {
	required, _, err := RequiredMatrixSelections0348(manifest.ComponentCatalog)
	if err != nil {
		return err
	}
	byPreset := map[string]int{}
	for _, t := range targets {
		byPreset[t.Preset]++
	}
	for _, choice := range required {
		if byPreset[choice] == 0 {
			return fmt.Errorf("Для обязательного выбора компонента в среде выполнения %q нет подходящей цели", choice)
		}
	}
	if manifest.ComponentCatalog == nil {
		return nil
	}
	cat := manifest.ComponentCatalog
	// Старые схемы манифеста/каталога не представляют нативный план выбранных файлов Runtime. Считайте их
	// непроверенными, а не сертифицируйте фиктивные пресеты.
	if manifest.SchemaVersion != "3.0" || cat.SchemaVersion == model.ComponentCatalogSchema0241 {
		return fmt.Errorf("матрица компонентов среды выполнения: требуется «схема исполняемого манифеста 3.0 и схема каталога не ниже 2.0»")
	}
	// Настроенная цель обязана использовать выбор, полученный из каталога. Не допускайте, чтобы поддельная
	// политика оператора незаметно подменяла именованный опубликованный пресет.
	known := map[string]bool{}
	for _, v := range required {
		known[v] = true
	}
	for _, c := range cat.Components {
		if c.Conditions == nil {
			continue
		}
		for _, os := range c.Conditions.OS {
			found := false
			for _, t := range targets {
				if t.OS == os {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Для ветви условия %s OS=%s отсутствует цель выполнения", c.ID, os)
			}
		}
		for _, arch := range c.Conditions.Arch {
			found := false
			for _, t := range targets {
				if normalizedArch0348(t.Arch) == arch {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Для ветви условия %s arch=%s отсутствует цель выполнения", c.ID, arch)
			}
		}
	}
	for _, t := range targets {
		if !known[t.Preset] {
			return fmt.Errorf("Неизвестное значение: «или не предусмотренный планом набор настроек среды выполнения» %q", t.Preset)
		}
		javaMajor, _ := strconv.Atoi(strings.SplitN(t.JavaVersion, ".", 2)[0])
		// Для именованного пресета проверяйте настоящий граф и достижимые условия окружения. Пользовательские
		// комбинации во время выполнения проверяет закреплённый нативный резолвер Runtime.
		if strings.HasPrefix(t.Preset, "@custom:v1:") {
			continue
		}
		chosen := t.Preset
		if chosen == "default" {
			isNamed := false
			for _, p := range cat.Presets {
				if p.ID == "default" {
					isNamed = true
					break
				}
			}
			if !isNamed {
				chosen = ""
			}
		}
		if cat.SchemaVersion == model.ComponentCatalogSchema0244 || cat.SchemaVersion == model.ComponentCatalogSchema0245 {
			_, err = model.ResolveCatalogConditional0244(*cat, chosen, model.ComponentEnvironment0244{
				OS: t.OS, Arch: normalizedArch0348(t.Arch), JavaMajor: uint32(javaMajor), MinecraftVersion: manifest.Minecraft.Version,
				Loader: t.Loader, LoaderVersion: manifest.Minecraft.LoaderVersion,
			})
		} else {
			_, err = model.ResolveCatalogPreset0242(*cat, chosen)
		}
		if err != nil {
			return fmt.Errorf("Некорректное значение: «выбор целевой среды выполнения %q» %q: %w", t.ID, t.Preset, err)
		}
	}
	return nil
}

func normalizedArch0348(value string) string {
	switch value {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return value
	}
}
