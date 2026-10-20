package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const ManifestSchemaV3 = "3.0"
const ComponentCatalogSchema0241 = "1.0"
const ComponentCatalogSchema0242 = "2.0"

type CatalogCategory0242 struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ParentID    string `json:"parentId,omitempty"`
}
type CatalogGroup0242 struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ParentID    string `json:"parentId,omitempty"`
	CategoryID  string `json:"categoryId,omitempty"`
}
type CatalogPreset0242 struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Components  []string `json:"components"`
}

// ComponentCatalog0241 is the immutable, content-addressed list of components
// belonging to ONE signed release. Schema v1 installs all components.
// Schema v2 supports signed topology and named preset file selection;
// dependencies, conflicts and conditional rules are not part of v0.24.2.
// Never accept arbitrary file paths or executable actions from local selection.
type ComponentCatalog0241 struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Revision      uint64                 `json:"revision"`
	Digest        string                 `json:"digest"`
	Components    []CatalogComponent0241 `json:"components"`
	Categories    []CatalogCategory0242  `json:"categories,omitempty"`
	Groups        []CatalogGroup0242     `json:"groups,omitempty"`
	Presets       []CatalogPreset0242    `json:"presets,omitempty"`
	DefaultPreset string                 `json:"defaultPreset,omitempty"`
}
type CatalogComponent0241 struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Files       []string          `json:"files"`
	Description string            `json:"description,omitempty"`
	CategoryID  string            `json:"categoryId,omitempty"`
	GroupID     string            `json:"groupId,omitempty"`
	Required    bool              `json:"required,omitempty"`
	Default     bool              `json:"default,omitempty"`
	Visible     *bool             `json:"visible,omitempty"`
	Limited     bool              `json:"limited,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Canonical framing is language-independent (Go/Rust) and unambiguous:
// prefix, u32be component count, length-prefixed UTF-8 strings, u32be file
// count and length-prefixed paths. Array order is significant and signed.
func ComponentCatalogDigest0241(components []CatalogComponent0241) string {
	h := sha256.New()
	h.Write([]byte("neverlauncher.component-catalog.v1\x00"))
	var n [4]byte
	writeCount := func(x int) { binary.BigEndian.PutUint32(n[:], uint32(x)); h.Write(n[:]) }
	writeText := func(s string) { writeCount(len(s)); h.Write([]byte(s)) }
	writeCount(len(components))
	for _, c := range components {
		writeText(c.ID)
		writeText(c.Name)
		writeCount(len(c.Files))
		for _, file := range c.Files {
			writeText(file)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NewComponentCatalog0241(components []CatalogComponent0241, revision uint64) ComponentCatalog0241 {
	if components == nil {
		components = []CatalogComponent0241{}
	}
	return ComponentCatalog0241{SchemaVersion: ComponentCatalogSchema0241, Revision: revision,
		Digest: ComponentCatalogDigest0241(components), Components: components}
}

func validComponentID0241(id string) bool {
	if len(id) == 0 || len(id) > 128 || !(id[0] >= 'a' && id[0] <= 'z' || id[0] >= '0' && id[0] <= '9') {
		return false
	}
	for _, b := range []byte(id) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			return false
		}
	}
	return !strings.Contains(id, "..")
}

func ValidateComponentCatalog0241(m Manifest) error {
	if m.SchemaVersion != ManifestSchemaV3 {
		if m.ComponentCatalog != nil {
			return errors.New("componentCatalog is only valid in manifest v3")
		}
		return nil
	}
	cat := m.ComponentCatalog
	if cat == nil || (cat.SchemaVersion != ComponentCatalogSchema0241 && cat.SchemaVersion != ComponentCatalogSchema0242) || cat.Revision == 0 ||
		len(cat.Components) > 4096 || len(cat.Digest) != 64 || cat.Digest != ComponentCatalogDigest0242(*cat) {
		return errors.New("invalid v3 component catalog snapshot/digest")
	}
	if err := ValidateCatalogTopology0242(*cat); err != nil {
		return err
	}
	files := make(map[string]ManifestFile, len(m.Files))
	for _, f := range m.Files {
		files[strings.ToLower(f.Path)] = f
	}
	owners := make(map[string]string)
	ids := make(map[string]bool)
	for _, c := range cat.Components {
		if !validComponentID0241(c.ID) || ids[c.ID] ||
			strings.TrimSpace(c.Name) == "" || len(c.Name) > 256 || strings.ContainsAny(c.Name, "\x00\r\n") ||
			len(c.Files) == 0 || len(c.Files) > 8192 {
			return fmt.Errorf("invalid/duplicate v3 component id, name or files: %q", c.ID)
		}
		ids[c.ID] = true
		for _, path := range c.Files {
			if !validFilePolicyPath0224(path, false) {
				return fmt.Errorf("unsafe component path %q", path)
			}
			key := strings.ToLower(path)
			if owner, exists := owners[key]; exists {
				return fmt.Errorf("component file %q already owned by %q", path, owner)
			}
			f, ok := files[key]
			if !ok || f.Path != path || f.Required || FileOwnership0224(f) != "optional" {
				return fmt.Errorf("component %q must reference a signed optional file: %q", c.ID, path)
			}
			owners[key] = c.ID
		}
	}
	for _, f := range m.Files {
		if FileOwnership0224(f) == "optional" && owners[strings.ToLower(f.Path)] == "" {
			return fmt.Errorf("v3 optional file has no component owner: %q", f.Path)
		}
	}
	return nil
}

// v2 uses explicit framing for ALL topology metadata: serialization order,
// omitempty rules and local UI state cannot alter the catalog digest.
func ComponentCatalogDigest0242(cat ComponentCatalog0241) string {
	if cat.SchemaVersion == ComponentCatalogSchema0241 {
		return ComponentCatalogDigest0241(cat.Components)
	}
	h := sha256.New()
	h.Write([]byte("neverlauncher.component-catalog.v2\x00"))
	var n [4]byte
	count := func(v int) { binary.BigEndian.PutUint32(n[:], uint32(v)); h.Write(n[:]) }
	str := func(v string) { count(len(v)); h.Write([]byte(v)) }
	bit := func(v bool) {
		if v {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}
	count(len(cat.Components))
	for _, c := range cat.Components {
		str(c.ID)
		str(c.Name)
		count(len(c.Files))
		for _, p := range c.Files {
			str(p)
		}
		str(c.Description)
		str(c.CategoryID)
		str(c.GroupID)
		bit(c.Required)
		bit(c.Default)
		bit(c.Visible != nil && *c.Visible)
		bit(c.Limited)
		keys := make([]string, 0, len(c.Metadata))
		for k := range c.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		count(len(keys))
		for _, k := range keys {
			str(k)
			str(c.Metadata[k])
		}
	}
	count(len(cat.Categories))
	for _, c := range cat.Categories {
		str(c.ID)
		str(c.Name)
		str(c.Description)
		str(c.ParentID)
	}
	count(len(cat.Groups))
	for _, g := range cat.Groups {
		str(g.ID)
		str(g.Name)
		str(g.Description)
		str(g.ParentID)
		str(g.CategoryID)
	}
	count(len(cat.Presets))
	for _, p := range cat.Presets {
		str(p.ID)
		str(p.Name)
		str(p.Description)
		count(len(p.Components))
		for _, id := range p.Components {
			str(id)
		}
	}
	str(cat.DefaultPreset)
	return hex.EncodeToString(h.Sum(nil))
}
func NewComponentCatalog0242(c ComponentCatalog0241, revision uint64) ComponentCatalog0241 {
	c.SchemaVersion = ComponentCatalogSchema0242
	c.Revision = revision
	if c.Components == nil {
		c.Components = []CatalogComponent0241{}
	}
	for i := range c.Presets {
		if c.Presets[i].Components == nil {
			c.Presets[i].Components = []string{}
		}
	}
	c.Digest = ComponentCatalogDigest0242(c)
	return c
}
func validDisplay0242(name, description string) bool {
	return strings.TrimSpace(name) != "" && len(name) <= 256 && len(description) <= 2048 && !strings.ContainsAny(name+description, "\x00\r")
}
func ValidateCatalogTopology0242(cat ComponentCatalog0241) error {
	if cat.SchemaVersion == ComponentCatalogSchema0241 {
		if len(cat.Categories) > 0 || len(cat.Groups) > 0 || len(cat.Presets) > 0 || cat.DefaultPreset != "" {
			return errors.New("v1 catalog cannot contain v2 topology")
		}
		for _, c := range cat.Components {
			if c.Description != "" || c.CategoryID != "" || c.GroupID != "" || c.Required || c.Default || c.Visible != nil || c.Limited || len(c.Metadata) > 0 {
				return fmt.Errorf("v1 component %q has v2 fields", c.ID)
			}
		}
		return nil
	}
	if len(cat.Categories) > 256 || len(cat.Groups) > 1024 || len(cat.Presets) > 128 {
		return errors.New("catalog topology exceeds limits")
	}
	categories := make(map[string]CatalogCategory0242)
	for _, v := range cat.Categories {
		if !validComponentID0241(v.ID) || !validDisplay0242(v.Name, v.Description) {
			return fmt.Errorf("invalid category %q", v.ID)
		}
		if _, ok := categories[v.ID]; ok {
			return fmt.Errorf("duplicate category %q", v.ID)
		}
		categories[v.ID] = v
	}
	groups := make(map[string]CatalogGroup0242)
	for _, v := range cat.Groups {
		if !validComponentID0241(v.ID) || !validDisplay0242(v.Name, v.Description) {
			return fmt.Errorf("invalid group %q", v.ID)
		}
		if _, ok := groups[v.ID]; ok {
			return fmt.Errorf("duplicate group %q", v.ID)
		}
		groups[v.ID] = v
	}
	// Follow parent links, limiting depth and detecting cycles, not trusting input order.
	for id := range categories {
		seen := map[string]bool{}
		cur := id
		for depth := 0; cur != ""; depth++ {
			if depth >= 9 || seen[cur] {
				return fmt.Errorf("cyclic or too deep category %q", id)
			}
			seen[cur] = true
			v, ok := categories[cur]
			if !ok {
				return fmt.Errorf("unknown category %q", cur)
			}
			cur = v.ParentID
		}
	}
	for id := range groups {
		seen := map[string]bool{}
		cur := id
		var category string
		for depth := 0; cur != ""; depth++ {
			if depth >= 9 || seen[cur] {
				return fmt.Errorf("cyclic or too deep group %q", id)
			}
			seen[cur] = true
			v, ok := groups[cur]
			if !ok {
				return fmt.Errorf("unknown group %q", cur)
			}
			if v.CategoryID != "" {
				if _, ok = categories[v.CategoryID]; !ok {
					return fmt.Errorf("unknown group category %q", v.CategoryID)
				}
				if category != "" && category != v.CategoryID {
					return fmt.Errorf("inconsistent group category %q", id)
				}
				category = v.CategoryID
			}
			cur = v.ParentID
		}
	}
	ids := make(map[string]bool)
	for _, c := range cat.Components {
		if c.Visible == nil {
			return fmt.Errorf("component %q requires explicit visible boolean", c.ID)
		}
		if !validDisplay0242(c.Name, c.Description) || len(c.Metadata) > 32 {
			return fmt.Errorf("invalid component metadata %q", c.ID)
		}
		if c.CategoryID != "" {
			if _, ok := categories[c.CategoryID]; !ok {
				return fmt.Errorf("component %q unknown category", c.ID)
			}
		}
		if c.GroupID != "" {
			g, ok := groups[c.GroupID]
			if !ok {
				return fmt.Errorf("component %q unknown group", c.ID)
			}
			if g.CategoryID != "" && c.CategoryID != "" && g.CategoryID != c.CategoryID {
				return fmt.Errorf("component %q group category mismatch", c.ID)
			}
		}
		for k, v := range c.Metadata {
			if !validComponentID0241(k) || len(k) > 64 || len(v) > 1024 || strings.ContainsAny(v, "\x00\r") {
				return fmt.Errorf("component %q invalid metadata key/value", c.ID)
			}
		}
		ids[c.ID] = true
	}
	presets := make(map[string]bool)
	for _, p := range cat.Presets {
		if !validComponentID0241(p.ID) || !validDisplay0242(p.Name, p.Description) || presets[p.ID] || len(p.Components) > 4096 {
			return fmt.Errorf("invalid/duplicate preset %q", p.ID)
		}
		presets[p.ID] = true
		seen := make(map[string]bool)
		for _, id := range p.Components {
			if !ids[id] || seen[id] {
				return fmt.Errorf("preset %q invalid/duplicate component %q", p.ID, id)
			}
			seen[id] = true
		}
	}
	if cat.DefaultPreset != "" && !presets[cat.DefaultPreset] {
		return fmt.Errorf("unknown default preset %q", cat.DefaultPreset)
	}
	return nil
}

// ResolveCatalogPreset0242 is the operational default/preset selector shared
// with native clients. O03 dependency/conflict solving is intentionally NOT
// represented as supported: this resolves only signed 0.24.2 topology.
func ResolveCatalogPreset0242(cat ComponentCatalog0241, preset string) ([]string, error) {
	if err := ValidateCatalogTopology0242(cat); err != nil {
		return nil, err
	}
	if cat.SchemaVersion == ComponentCatalogSchema0241 {
		out := make([]string, 0, len(cat.Components))
		for _, c := range cat.Components {
			out = append(out, c.ID)
		}
		return out, nil
	}
	if preset == "" {
		preset = cat.DefaultPreset
	}
	chosen := make(map[string]bool)
	if preset != "" {
		found := false
		for _, p := range cat.Presets {
			if p.ID == preset {
				found = true
				for _, id := range p.Components {
					chosen[id] = true
				}
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown component preset %q", preset)
		}
	} else {
		for _, c := range cat.Components {
			if c.Default {
				chosen[c.ID] = true
			}
		}
	}
	out := make([]string, 0, len(cat.Components))
	for _, c := range cat.Components {
		if c.Required || chosen[c.ID] {
			out = append(out, c.ID)
		}
	}
	return out, nil
}
