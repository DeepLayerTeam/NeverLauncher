package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Conditions are signed predicates, not client commands. In schema 1.0 every
// nonempty field must match; arrays are OR sets, fields combine with AND.
// Missing trusted context never means unrestricted access.
type ComponentConditions0244 struct {
	SchemaVersion         string   `json:"schemaVersion"`
	OS                    []string `json:"os,omitempty"`
	Arch                  []string `json:"arch,omitempty"`
	JavaMajorMin          uint32   `json:"javaMajorMin,omitempty"`
	JavaMajorMax          uint32   `json:"javaMajorMax,omitempty"`
	MinecraftVersions     []string `json:"minecraftVersions,omitempty"`
	MinecraftVersionRange string   `json:"minecraftVersionRange,omitempty"`
	Loaders               []string `json:"loaders,omitempty"`
	LoaderVersionRange    string   `json:"loaderVersionRange,omitempty"`
	Permissions           []string `json:"permissions,omitempty"`
}

type ComponentEnvironment0244 struct {
	OS               string
	Arch             string
	JavaMajor        uint32
	MinecraftVersion string
	Loader           string
	LoaderVersion    string
	// This map MUST come from authenticated server-side authorization, never
	// from a Desktop JSON payload or an unverified local account profile.
	VerifiedPermissions map[string]bool
}

func ComponentCatalogDigest0244(c ComponentCatalog0241) string {
	if c.SchemaVersion != ComponentCatalogSchema0244 {
		return ComponentCatalogDigest0243(c)
	}
	h := sha256.New()
	h.Write([]byte("neverlauncher.component-catalog.v4\x00"))
	var n [4]byte
	number := func(x int) { binary.BigEndian.PutUint32(n[:], uint32(x)); _, _ = h.Write(n[:]) }
	str := func(v string) { number(len(v)); _, _ = h.Write([]byte(v)) }
	str(ComponentCatalogDigest0243(c))
	number(len(c.Components))
	for _, component := range c.Components {
		v := component.Conditions
		if v == nil {
			h.Write([]byte{0})
			continue
		}
		h.Write([]byte{1})
		str(v.SchemaVersion)
		for _, items := range [][]string{v.OS, v.Arch, v.MinecraftVersions, v.Loaders, v.Permissions} {
			number(len(items))
			for _, value := range items {
				str(value)
			}
		}
		number(int(v.JavaMajorMin))
		number(int(v.JavaMajorMax))
		str(v.MinecraftVersionRange)
		str(v.LoaderVersionRange)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func NewComponentCatalog0244(c ComponentCatalog0241, revision uint64) ComponentCatalog0241 {
	c.SchemaVersion = ComponentCatalogSchema0244
	c.Revision = revision
	if c.Components == nil {
		c.Components = []CatalogComponent0241{}
	}
	for i := range c.Presets {
		if c.Presets[i].Components == nil {
			c.Presets[i].Components = []string{}
		}
	}
	c.Digest = ComponentCatalogDigest0244(c)
	return c
}
func validPermissionName0244(s string) bool {
	if len(s) == 0 || len(s) > 128 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, ch := range []byte(s) {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' || ch == ':') {
			return false
		}
	}
	return !strings.Contains(s, "..") && !strings.Contains(s, "::")
}

func validDistinct0244(values []string, limit int, valid func(string) bool) error {
	if len(values) > limit {
		return errors.New("condition array exceeds limit")
	}
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if !valid(v) || seen[v] {
			return fmt.Errorf("invalid/duplicate condition value %q", v)
		}
		seen[v] = true
	}
	return nil
}
func ValidateCatalogConditions0244(cat ComponentCatalog0241) error {
	if cat.SchemaVersion != ComponentCatalogSchema0244 {
		for _, c := range cat.Components {
			if c.Conditions != nil {
				return fmt.Errorf("component %s has unsigned v4 conditions", c.ID)
			}
		}
		return nil
	}
	for _, c := range cat.Components {
		v := c.Conditions
		if v == nil {
			continue
		}
		if v.SchemaVersion != "1.0" {
			return fmt.Errorf("component %s: unsupported condition schema %q", c.ID, v.SchemaVersion)
		}
		if err := validDistinct0244(v.OS, 8, func(s string) bool { return s == "windows" || s == "linux" || s == "macos" }); err != nil {
			return fmt.Errorf("component %s OS: %w", c.ID, err)
		}
		if err := validDistinct0244(v.Arch, 8, func(s string) bool { return s == "x86_64" || s == "aarch64" }); err != nil {
			return fmt.Errorf("component %s arch: %w", c.ID, err)
		}
		if v.JavaMajorMax != 0 && v.JavaMajorMin > v.JavaMajorMax {
			return fmt.Errorf("component %s: inverted Java major range", c.ID)
		}
		if v.JavaMajorMin > 99 || v.JavaMajorMax > 99 {
			return fmt.Errorf("component %s: invalid Java major", c.ID)
		}
		if err := validDistinct0244(v.MinecraftVersions, 64, func(s string) bool { return len(s) > 0 && len(s) <= 80 && !strings.ContainsAny(s, " \t\r\n\x00") }); err != nil {
			return fmt.Errorf("component %s Minecraft: %w", c.ID, err)
		}
		if err := validDistinct0244(v.Loaders, 12, func(s string) bool {
			return s == "vanilla" || s == "fabric" || s == "quilt" || s == "forge" || s == "neoforge"
		}); err != nil {
			return fmt.Errorf("component %s loader: %w", c.ID, err)
		}
		if err := validDistinct0244(v.Permissions, 32, func(s string) bool { return validPermissionName0244(s) }); err != nil {
			return fmt.Errorf("component %s permissions: %w", c.ID, err)
		}
		if v.MinecraftVersionRange != "" {
			if _, err := matchRange0243("1.0.0", v.MinecraftVersionRange); err != nil {
				return fmt.Errorf("component %s Minecraft range: %w", c.ID, err)
			}
		}
		if v.LoaderVersionRange != "" {
			if _, err := matchRange0243("1.0.0", v.LoaderVersionRange); err != nil {
				return fmt.Errorf("component %s loader range: %w", c.ID, err)
			}
		}
	}
	return nil
}
func in0244(list []string, value string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}
	return false
}
func unavailable0244(v *ComponentConditions0244, env ComponentEnvironment0244) string {
	if v == nil {
		return ""
	}
	if len(v.OS) > 0 && !in0244(v.OS, env.OS) {
		return fmt.Sprintf("OS %q is not in %v", env.OS, v.OS)
	}
	if len(v.Arch) > 0 && !in0244(v.Arch, env.Arch) {
		return fmt.Sprintf("architecture %q is not in %v", env.Arch, v.Arch)
	}
	if v.JavaMajorMin > 0 && (env.JavaMajor == 0 || env.JavaMajor < v.JavaMajorMin) {
		return fmt.Sprintf("Java major %d is below %d", env.JavaMajor, v.JavaMajorMin)
	}
	if v.JavaMajorMax > 0 && (env.JavaMajor == 0 || env.JavaMajor > v.JavaMajorMax) {
		return fmt.Sprintf("Java major %d exceeds %d", env.JavaMajor, v.JavaMajorMax)
	}
	if len(v.MinecraftVersions) > 0 && !in0244(v.MinecraftVersions, env.MinecraftVersion) {
		return fmt.Sprintf("Minecraft %q is not in %v", env.MinecraftVersion, v.MinecraftVersions)
	}
	if v.MinecraftVersionRange != "" {
		ok, e := matchRange0243(env.MinecraftVersion, v.MinecraftVersionRange)
		if e != nil {
			return "Minecraft version not semver-compatible: " + e.Error()
		}
		if !ok {
			return fmt.Sprintf("Minecraft %q outside %q", env.MinecraftVersion, v.MinecraftVersionRange)
		}
	}
	if len(v.Loaders) > 0 && !in0244(v.Loaders, strings.ToLower(env.Loader)) {
		return fmt.Sprintf("loader %q is not in %v", env.Loader, v.Loaders)
	}
	if v.LoaderVersionRange != "" {
		ok, e := matchRange0243(env.LoaderVersion, v.LoaderVersionRange)
		if e != nil {
			return "loader version not semver-compatible: " + e.Error()
		}
		if !ok {
			return fmt.Sprintf("loader %q outside %q", env.LoaderVersion, v.LoaderVersionRange)
		}
	}
	for _, permission := range v.Permissions {
		if !env.VerifiedPermissions[permission] {
			return "missing verified permission: " + permission
		}
	}
	return ""
}

// ResolveCatalogConditional0244 handles automatic defaults separately from
// required, explicitly selected and dependency components. An unavailable
// default is excluded, whereas an unavailable hard selection is a clear error.
func ResolveCatalogConditional0244(cat ComponentCatalog0241, preset string, env ComponentEnvironment0244) ([]string, error) {
	if cat.SchemaVersion != ComponentCatalogSchema0244 {
		return nil, fmt.Errorf("condition resolver requires catalog v4")
	}
	if err := ValidateCatalogConditions0244(cat); err != nil {
		return nil, err
	}
	modified := cat
	modified.Components = append([]CatalogComponent0241(nil), cat.Components...)
	explicit := preset != "" || cat.DefaultPreset != ""
	for i, c := range modified.Components {
		reason := unavailable0244(c.Conditions, env)
		if reason != "" {
			if c.Required {
				return nil, resolutionError0243("condition_unsatisfied", c.ID, "", "required component "+c.ID+": "+reason)
			}
			if !explicit {
				modified.Components[i].Default = false
			}
		}
	}
	selected, err := resolveCatalogGraph0243(modified, preset)
	if err != nil {
		return nil, err
	}
	index := make(map[string]CatalogComponent0241, len(cat.Components))
	for _, c := range cat.Components {
		index[c.ID] = c
	}
	for _, id := range selected {
		if why := unavailable0244(index[id].Conditions, env); why != "" {
			return nil, resolutionError0243("condition_unsatisfied", id, "", "selected/dependent component "+id+": "+why)
		}
	}
	return selected, nil
}
