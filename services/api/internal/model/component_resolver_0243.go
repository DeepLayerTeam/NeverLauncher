package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Component catalog schema 3 extends the signed v2 snapshot, never the local
// selection. Every dependency, conflict, constraint and exclusion is signed.
func ComponentCatalogDigest0243(c ComponentCatalog0241) string {
	if c.SchemaVersion != ComponentCatalogSchema0243 && c.SchemaVersion != ComponentCatalogSchema0244 && c.SchemaVersion != ComponentCatalogSchema0245 {
		return ComponentCatalogDigest0242(c)
	}
	h := sha256.New()
	h.Write([]byte("neverlauncher.component-catalog.v3\x00"))
	var buf [4]byte
	count := func(n int) { binary.BigEndian.PutUint32(buf[:], uint32(n)); _, _ = h.Write(buf[:]) }
	write := func(s string) { count(len(s)); _, _ = h.Write([]byte(s)) }
	// Domain-separated digest of the entire v2 topology is framed into v3.
	write(ComponentCatalogDigest0242(c))
	count(len(c.Components))
	for _, component := range c.Components {
		write(component.Version)
		write(component.ExclusiveGroup)
		count(len(component.Dependencies))
		for _, dep := range component.Dependencies {
			write(dep.ID)
			write(dep.VersionRange)
		}
		count(len(component.Conflicts))
		for _, conflict := range component.Conflicts {
			write(conflict.ID)
			write(conflict.VersionRange)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NewComponentCatalog0243(c ComponentCatalog0241, revision uint64) ComponentCatalog0241 {
	c.SchemaVersion = ComponentCatalogSchema0243
	c.Revision = revision
	if c.Components == nil {
		c.Components = []CatalogComponent0241{}
	}
	for i := range c.Presets {
		if c.Presets[i].Components == nil {
			c.Presets[i].Components = []string{}
		}
	}
	c.Digest = ComponentCatalogDigest0243(c)
	return c
}

// ResolutionError0243 provides a stable machine-readable category and a
// human-readable chain. It is returned before staging files or creating jobs.
type ResolutionError0243 struct {
	Code      string
	Component string
	Related   string
	Detail    string
}

func (e *ResolutionError0243) Error() string {
	return fmt.Sprintf("component resolution [%s]: %s", e.Code, e.Detail)
}
func resolutionError0243(code, component, related, explanation string) error {
	return &ResolutionError0243{Code: code, Component: component, Related: related, Detail: explanation}
}

type semver0243 struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver0243(source string) (semver0243, error) {
	var result semver0243
	if len(source) == 0 || len(source) > 128 || strings.ContainsAny(source, " \t\r\n") {
		return result, fmt.Errorf("invalid semantic version %q", source)
	}
	raw := strings.SplitN(source, "+", 2)
	if len(raw) == 2 && !semverIdentifiers0243(raw[1], false) {
		return result, fmt.Errorf("invalid semver build metadata %q", source)
	}
	pre := strings.SplitN(raw[0], "-", 2)
	if len(pre) == 2 {
		if !semverIdentifiers0243(pre[1], true) {
			return result, fmt.Errorf("invalid semver prerelease %q", source)
		}
		result.pre = strings.Split(pre[1], ".")
	}
	parts := strings.Split(pre[0], ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("semantic version must be MAJOR.MINOR.PATCH: %q", source)
	}
	nums := []*uint64{&result.major, &result.minor, &result.patch}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return result, fmt.Errorf("invalid semantic version %q", source)
		}
		for _, b := range []byte(part) {
			if b < '0' || b > '9' {
				return result, fmt.Errorf("invalid semantic version %q", source)
			}
		}
		v, e := strconv.ParseUint(part, 10, 64)
		if e != nil {
			return result, e
		}
		*nums[i] = v
	}
	return result, nil
}
func semverIdentifiers0243(raw string, prerelease bool) bool {
	if raw == "" {
		return false
	}
	for _, id := range strings.Split(raw, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for _, ch := range []byte(id) {
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '-') {
				return false
			}
			if ch < '0' || ch > '9' {
				numeric = false
			}
		}
		if prerelease && numeric {
			if len(id) > 1 && id[0] == '0' {
				return false
			}
			if _, err := strconv.ParseUint(id, 10, 64); err != nil {
				return false
			}
		}
	}
	return true
}
func cmpSemver0243(a, b semver0243) int {
	for i, n := range []uint64{a.major, a.minor, a.patch} {
		other := []uint64{b.major, b.minor, b.patch}[i]
		if n < other {
			return -1
		}
		if n > other {
			return 1
		}
	}
	if len(a.pre) == 0 && len(b.pre) > 0 {
		return 1
	}
	if len(a.pre) > 0 && len(b.pre) == 0 {
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, xe := strconv.ParseUint(x, 10, 64)
		yn, ye := strconv.ParseUint(y, 10, 64)
		if xe == nil && ye == nil {
			if xn < yn {
				return -1
			}
			if xn > yn {
				return 1
			}
			continue
		}
		if xe == nil {
			return -1
		}
		if ye == nil {
			return 1
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	if len(a.pre) < len(b.pre) {
		return -1
	}
	if len(a.pre) > len(b.pre) {
		return 1
	}
	return 0
}
func matchRange0243(actual, expr string) (bool, error) {
	current, err := parseSemver0243(actual)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(expr) == "" || strings.TrimSpace(expr) == "*" {
		return true, nil
	}
	if len(expr) > 256 {
		return false, fmt.Errorf("range exceeds 256 bytes")
	}
	anyMatched := false
	for _, alternative := range strings.Split(expr, "||") {
		tokens := strings.Fields(alternative)
		if len(tokens) == 0 || len(tokens) > 16 {
			return false, fmt.Errorf("invalid version range %q", expr)
		}
		ok := true
		for _, token := range tokens {
			if token == "*" {
				continue
			}
			op, version := "=", token
			for _, candidate := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
				if strings.HasPrefix(token, candidate) {
					op = candidate
					version = strings.TrimPrefix(token, candidate)
					break
				}
			}
			required, e := parseSemver0243(version)
			if e != nil {
				return false, fmt.Errorf("bad range %q: %w", expr, e)
			}
			comparison := cmpSemver0243(current, required)
			pass := false
			switch op {
			case "=":
				pass = comparison == 0
			case ">":
				pass = comparison > 0
			case ">=":
				pass = comparison >= 0
			case "<":
				pass = comparison < 0
			case "<=":
				pass = comparison <= 0
			case "^", "~":
				upper := required
				upper.pre = nil
				if op == "~" {
					if upper.minor == ^uint64(0) {
						return false, fmt.Errorf("range overflow")
					}
					upper.minor++
					upper.patch = 0
				} else if upper.major > 0 {
					if upper.major == ^uint64(0) {
						return false, fmt.Errorf("range overflow")
					}
					upper.major++
					upper.minor = 0
					upper.patch = 0
				} else if upper.minor > 0 {
					if upper.minor == ^uint64(0) {
						return false, fmt.Errorf("range overflow")
					}
					upper.minor++
					upper.patch = 0
				} else {
					if upper.patch == ^uint64(0) {
						return false, fmt.Errorf("range overflow")
					}
					upper.patch++
				}
				pass = comparison >= 0 && cmpSemver0243(current, upper) < 0
			}
			if !pass {
				ok = false
			}
		}
		if ok {
			anyMatched = true
		}
	}
	return anyMatched, nil
}

// ValidateCatalogRules0243 checks the whole signed graph, not just currently
// selected components. All declared presets must be satisfiable at publication.
func ValidateCatalogRules0243(cat ComponentCatalog0241) error {
	items := make(map[string]CatalogComponent0241, len(cat.Components))
	for _, c := range cat.Components {
		items[c.ID] = c
	}
	for _, c := range cat.Components {
		if _, err := parseSemver0243(c.Version); err != nil {
			return resolutionError0243("invalid_version", c.ID, "", fmt.Sprintf("component %s: %v", c.ID, err))
		}
		if c.ExclusiveGroup != "" && !validComponentID0241(c.ExclusiveGroup) {
			return resolutionError0243("invalid_group", c.ID, "", fmt.Sprintf("component %s has invalid exclusive group %q", c.ID, c.ExclusiveGroup))
		}
		if len(c.Dependencies) > 64 || len(c.Conflicts) > 64 {
			return resolutionError0243("limit", c.ID, "", fmt.Sprintf("component %s has too many constraints", c.ID))
		}
		depSeen := map[string]bool{}
		conflictSeen := map[string]bool{}
		for _, relation := range []struct {
			kind string
			refs []ComponentRequirement0243
			seen map[string]bool
		}{{"dependency", c.Dependencies, depSeen}, {"conflict", c.Conflicts, conflictSeen}} {
			for _, r := range relation.refs {
				other, exists := items[r.ID]
				if !exists || relation.seen[r.ID] || r.ID == c.ID {
					return resolutionError0243("invalid_reference", c.ID, r.ID, fmt.Sprintf("%s %s references missing, duplicate or self component %s", c.ID, relation.kind, r.ID))
				}
				relation.seen[r.ID] = true
				if _, err := matchRange0243(other.Version, r.VersionRange); err != nil {
					return resolutionError0243("invalid_range", c.ID, r.ID, fmt.Sprintf("%s %s %s: %v", c.ID, relation.kind, r.ID, err))
				}
			}
		}
	}
	// Global directed cycle detection, including optional branches not in presets.
	state := map[string]uint8{}
	stack := []string{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 2 {
			return nil
		}
		if state[id] == 1 {
			start := 0
			for i, s := range stack {
				if s == id {
					start = i
					break
				}
			}
			return resolutionError0243("cycle", id, id, "dependency cycle: "+strings.Join(append(append([]string{}, stack[start:]...), id), " -> "))
		}
		state[id] = 1
		stack = append(stack, id)
		for _, d := range items[id].Dependencies {
			if err := visit(d.ID); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		state[id] = 2
		return nil
	}
	for _, c := range cat.Components {
		if err := visit(c.ID); err != nil {
			return err
		}
	}
	// Conditions may filter implicit defaults differently on each player's OS,
	// but a named preset always selects all its roots explicitly. A signed preset
	// containing incompatible dependencies cannot become valid on another host.
	if cat.SchemaVersion != ComponentCatalogSchema0244 && cat.SchemaVersion != ComponentCatalogSchema0245 {
		if _, err := resolveCatalogGraph0243(cat, ""); err != nil {
			return err
		}
	}
	for _, p := range cat.Presets {
		if _, err := resolveCatalogGraph0243(cat, p.ID); err != nil {
			return fmt.Errorf("preset %q invalid: %w", p.ID, err)
		}
	}
	return nil
}

// resolveCatalogGraph0243 is deterministic: component order follows signed
// catalog order, dependency traversal follows signed reference order, outputs
// are returned in catalog order. It never mutates the signed manifest.
func resolveCatalogGraph0243(cat ComponentCatalog0241, preset string) ([]string, error) {
	components := make(map[string]CatalogComponent0241, len(cat.Components))
	for _, c := range cat.Components {
		components[c.ID] = c
	}
	selected := make(map[string]bool)
	chosen := preset
	if chosen == "" {
		chosen = cat.DefaultPreset
	}
	if chosen != "" {
		found := false
		for _, p := range cat.Presets {
			if p.ID == chosen {
				found = true
				for _, id := range p.Components {
					selected[id] = true
				}
				break
			}
		}
		if !found {
			return nil, resolutionError0243("unknown_preset", "", "", fmt.Sprintf("unknown component preset %q", chosen))
		}
	} else {
		for _, c := range cat.Components {
			if c.Default {
				selected[c.ID] = true
			}
		}
	}
	for _, c := range cat.Components {
		if c.Required {
			selected[c.ID] = true
		}
	}
	expanded := map[string]bool{}
	var activate func(string, []string) error
	activate = func(id string, chain []string) error {
		c, ok := components[id]
		if !ok {
			return resolutionError0243("missing_dependency", id, "", fmt.Sprintf("unknown dependency %s", id))
		}
		if expanded[id] {
			return nil
		}
		for _, d := range c.Dependencies {
			target := components[d.ID]
			allowed, err := matchRange0243(target.Version, d.VersionRange)
			if err != nil {
				return err
			}
			if !allowed {
				return resolutionError0243("version_mismatch", id, d.ID, fmt.Sprintf("%s requires %s %q, available version %s (via %s)", id, d.ID, d.VersionRange, target.Version, strings.Join(append(chain, id), " -> ")))
			}
			selected[d.ID] = true
			if err := activate(d.ID, append(append([]string{}, chain...), id)); err != nil {
				return err
			}
		}
		expanded[id] = true
		return nil
	}
	for _, c := range cat.Components {
		if selected[c.ID] {
			if err := activate(c.ID, nil); err != nil {
				return nil, err
			}
		}
	}
	groups := map[string]string{}
	for _, c := range cat.Components {
		if !selected[c.ID] {
			continue
		}
		if c.ExclusiveGroup != "" {
			if previous := groups[c.ExclusiveGroup]; previous != "" {
				return nil, resolutionError0243("exclusive_group", c.ID, previous, fmt.Sprintf("components %s and %s are mutually exclusive (group %s)", previous, c.ID, c.ExclusiveGroup))
			}
			groups[c.ExclusiveGroup] = c.ID
		}
		for _, conflict := range c.Conflicts {
			if !selected[conflict.ID] {
				continue
			}
			other := components[conflict.ID]
			matches, _ := matchRange0243(other.Version, conflict.VersionRange)
			if matches {
				return nil, resolutionError0243("conflict", c.ID, conflict.ID, fmt.Sprintf("components %s and %s cannot be selected together: %s conflicts with %s version %s (range %q)", c.ID, other.ID, c.ID, other.ID, other.Version, conflict.VersionRange))
			}
		}
	}
	result := make([]string, 0, len(selected))
	for _, c := range cat.Components {
		if selected[c.ID] {
			result = append(result, c.ID)
		}
	}
	return result, nil
}

// PreviewCatalogGraph0248 uses the same signed-graph resolver as the installer
// without claiming simulated OS/Java/permissions are real authorization.
// This checks static preset conflicts, cycles and dependency version ranges.
func PreviewCatalogGraph0248(cat ComponentCatalog0241, preset string) ([]string, error) {
	if err := ValidateCatalogTopology0242(cat); err != nil {
		return nil, err
	}
	return resolveCatalogGraph0243(cat, preset)
}
