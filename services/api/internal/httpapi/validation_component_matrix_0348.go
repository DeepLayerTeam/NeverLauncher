package httpapi

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Custom selections use comma-separated signed component IDs (never paths).
var validationPreset0348 = regexp.MustCompile(`^[a-zA-Z0-9_.:/@+,\-]{1,160}$`)

// RequiredMatrixSelections0348 derives the MANDATORY selection list from the
// *signed release snapshot*, not from runner reports. The bounded additional
// cases are deterministic pairwise compatible selections; this is intentionally
// NOT a claim that all 2^N combinations have been exercised.
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
	// Pick the smallest signed base to avoid re-testing combinations that are
	// already present in the normal published preset set.
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
	// A fixed, documented upper bound protects the attestation infrastructure.
	// Uncovered candidates are reported independently and never described as
	// validated. No subset enumeration / exponential runtime is performed.
	const maxAdditionalPairs = 12
	conditional := make([]string, 0)
	pairs := make([]string, 0, maxAdditionalPairs)
	unchecked := 0
	// Each condition-bearing optional component that no published preset
	// enables gets its own positive selection probe, independent of pairs.
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
	// Every reachable condition-bearing component is mandatory. Unlike
	// optional pairwise coverage it may not be silently truncated. The
	// configured-target limit is 128, leaving room for pairwise probes.
	if len(conditional)+len(presets) > 116 {
		return nil, 0, fmt.Errorf("component matrix exceeds runnable target capacity: %d mandatory preset/conditional selections", len(conditional)+len(presets))
	}
	const maxCandidatePairs = 512
	examined := 0
	totalPairs := len(available) * (len(available) - 1) / 2
	for i := 0; i < len(available); i++ {
		for j := i + 1; j < len(available); j++ {
			if examined >= maxCandidatePairs {
				// All remaining possible pairs are UNEXAMINED, not passed.
				// Avoid O(N^2) resolver work on a 4096-component catalog.
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
	// Use the production dependency/conflict resolver on a temporary in-memory
	// selection (the actual catalog and signed digest are never modified).
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
	// A pair can be graph-compatible yet impossible to run on any machine
	// (Windows-only + Linux-only, disjoint Java ranges, etc.). Never add such
	// an impossible target to the mandatory matrix.
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

// This is enforced at grant issuance, evidence acceptance and coverage reads.
// Missing presets cannot be hidden by supplying a one-element operator matrix.
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
			return fmt.Errorf("required component runtime selection %q has no target", choice)
		}
	}
	if manifest.ComponentCatalog == nil {
		return nil
	}
	cat := manifest.ComponentCatalog
	// Old manifest/catalog layouts cannot represent a native selected-file
	// runtime plan. Treat them as unverified instead of certifying fake presets.
	if manifest.SchemaVersion != "3.0" || cat.SchemaVersion == model.ComponentCatalogSchema0241 {
		return fmt.Errorf("runtime component matrix requires executable manifest schema 3.0 and catalog schema >= 2.0")
	}
	// A configured target must use a catalog-derived selection. Prevent a
	// forged operator policy from silently replacing a named published preset.
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
				return fmt.Errorf("condition branch %s OS=%s has no execution target", c.ID, os)
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
				return fmt.Errorf("condition branch %s arch=%s has no execution target", c.ID, arch)
			}
		}
	}
	for _, t := range targets {
		if !known[t.Preset] {
			return fmt.Errorf("unknown or unplanned runtime preset %q", t.Preset)
		}
		javaMajor, _ := strconv.Atoi(strings.SplitN(t.JavaVersion, ".", 2)[0])
		// For a named preset, validate the real graph and its reachable
		// environment conditions. Custom combinations are validated by the
		// pinned native runtime resolver during execution.
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
			return fmt.Errorf("runtime target %q selection %q invalid: %w", t.ID, t.Preset, err)
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
