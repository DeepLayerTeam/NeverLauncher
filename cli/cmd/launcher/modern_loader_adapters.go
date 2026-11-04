package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Modern adapter resolution is an upstream compatibility check, not a guess
// based on a Maven directory or the order of rows returned by the metadata API.
// The chosen entry is persisted in the existing immutable resolution lock.
var modernLoaderVersion0272 = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$`)
var forgeLikeVersion0272 = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]*$`)

func validateForgeLikeVersionToken0272(version string) error {
	if len(version) > 128 || !forgeLikeVersion0272.MatchString(version) || strings.Contains(version, "..") || strings.Contains(version, "--") {
		return fmt.Errorf("unsafe Forge/NeoForge artifact version %q", version)
	}
	return nil
}

func validateModernLoaderEntry0272(loader string, e loaderMetaEntry) error {
	ver := strings.TrimSpace(e.Loader.Version)
	if !modernLoaderVersion0272.MatchString(ver) || isMutableLoaderSelector(ver) {
		return fmt.Errorf("%s: invalid loader version %q", loader, ver)
	}
	// A Maven coordinate from the authoritative API must correspond exactly
	// to the loader version; otherwise a valid-looking profile may install a
	// different binary than the one shown to the administrator.
	if e.Loader.Maven == "" {
		return fmt.Errorf("%s %s: no loader Maven identity", loader, ver)
	}
	parts := strings.Split(e.Loader.Maven, ":")
	if len(parts) != 3 || parts[2] != ver {
		return fmt.Errorf("%s %s: conflicting loader Maven identity %q", loader, ver, e.Loader.Maven)
	}
	if _, err := strictMavenPath(e.Loader.Maven); err != nil {
		return fmt.Errorf("%s %s Maven: %w", loader, ver, err)
	}
	expected := "net.fabricmc:fabric-loader"
	if loader == "quilt" {
		expected = "org.quiltmc:quilt-loader"
	}
	if strings.Join(parts[:2], ":") != expected {
		return fmt.Errorf("%s %s: wrong loader Maven artifact %q", loader, ver, e.Loader.Maven)
	}
	if e.Intermediary.Maven != "" {
		if _, err := strictMavenPath(e.Intermediary.Maven); err != nil {
			return fmt.Errorf("%s %s intermediary Maven: %w", loader, ver, err)
		}
	}
	return nil
}

// Compare numeric version components before prerelease tags, so 0.17.0 is
// greater than 0.16.10, and 0.17.0 is greater than 0.17.0-rc1.
// Build metadata is a deterministic tiebreaker for historical Fabric builds.
func compareModernVersions0272(a, b string) int {
	split := func(v string) ([]int, string, string) {
		base, build, _ := strings.Cut(v, "+")
		core, prerelease, _ := strings.Cut(base, "-")
		nums := []int{}
		for _, part := range strings.Split(core, ".") {
			n, _ := strconv.Atoi(part)
			nums = append(nums, n)
		}
		return nums, prerelease, build
	}
	x, xp, xb := split(a)
	y, yp, yb := split(b)
	n := len(x)
	if len(y) > n {
		n = len(y)
	}
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(x) {
			a = x[i]
		}
		if i < len(y) {
			b = y[i]
		}
		if a > b {
			return 1
		}
		if a < b {
			return -1
		}
	}
	if xp == "" && yp != "" {
		return 1
	}
	if xp != "" && yp == "" {
		return -1
	}
	if xp != yp {
		xparts := strings.Split(xp, ".")
		yparts := strings.Split(yp, ".")
		for i := 0; i < len(xparts) || i < len(yparts); i++ {
			if i >= len(xparts) {
				return -1
			}
			if i >= len(yparts) {
				return 1
			}
			if xparts[i] == yparts[i] {
				continue
			}
			xi, ex := strconv.Atoi(xparts[i])
			yi, ey := strconv.Atoi(yparts[i])
			if ex == nil && ey == nil {
				if xi > yi {
					return 1
				}
				return -1
			}
			if ex == nil {
				return -1
			}
			if ey == nil {
				return 1
			}
			if xparts[i] > yparts[i] {
				return 1
			}
			return -1
		}
	}
	if xb == yb {
		return 0
	}
	buildNumber := func(v string) (int, bool) {
		v = strings.TrimPrefix(v, "build.")
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	an, okA := buildNumber(xb)
	bn, okB := buildNumber(yb)
	if okA && okB {
		if an > bn {
			return 1
		}
		if an < bn {
			return -1
		}
		return 0
	}
	if xb > yb {
		return 1
	}
	return -1
}

func selectModernMetaEntry0272(loader, minecraft, selector string, entries []loaderMetaEntry) (loaderMetaEntry, error) {
	selector = strings.TrimSpace(selector)
	if loader != "fabric" && loader != "quilt" {
		return loaderMetaEntry{}, fmt.Errorf("unknown modern meta adapter %q", loader)
	}
	if len(entries) == 0 {
		return loaderMetaEntry{}, fmt.Errorf("%s has no loader versions for Minecraft %s", loader, minecraft)
	}
	// Duplicate versions with conflicting artifact coordinates are ambiguous,
	// even when the first row would otherwise win a latest selection.
	seen := map[string]loaderMetaEntry{}
	best := -1
	explicit := -1
	valid := 0
	for i, e := range entries {
		if previous, ok := seen[e.Loader.Version]; ok {
			if previous.Loader.Maven != e.Loader.Maven || previous.Intermediary.Maven != e.Intermediary.Maven || previous.Loader.Stable != e.Loader.Stable {
				return loaderMetaEntry{}, fmt.Errorf("%s %s metadata has conflicting duplicate version", loader, e.Loader.Version)
			}
			continue
		}
		seen[e.Loader.Version] = e
		if err := validateModernLoaderEntry0272(loader, e); err != nil {
			// Reject exact invalid requested entries; invalid unrelated historical
			// entries may be ignored rather than breaking the entire catalog.
			if e.Loader.Version == selector {
				return loaderMetaEntry{}, err
			}
			continue
		}
		valid++
		if !isMutableLoaderSelector(selector) {
			if e.Loader.Version == selector {
				explicit = i
			}
			continue
		}
		stable := e.Loader.Stable
		if loader == "quilt" {
			stable = isStableQuiltLoaderVersion(e.Loader.Version)
		}
		if strings.ToLower(selector) != "latest" && !stable {
			continue
		}
		if best < 0 || compareModernVersions0272(e.Loader.Version, entries[best].Loader.Version) > 0 {
			best = i
		}
	}
	if !isMutableLoaderSelector(selector) {
		if explicit >= 0 {
			return entries[explicit], nil
		}
		return loaderMetaEntry{}, fmt.Errorf("%s loader %s is unavailable for Minecraft %s", loader, selector, minecraft)
	}
	if best < 0 {
		return loaderMetaEntry{}, fmt.Errorf("%s has no compatible %s loader for Minecraft %s (valid entries: %d)", loader, selector, minecraft, valid)
	}
	return entries[best], nil
}
