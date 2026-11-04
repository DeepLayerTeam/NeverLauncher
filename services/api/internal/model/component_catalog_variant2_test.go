package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func b0242(v bool) *bool { return &v }
func topologyFixture0242() Manifest {
	m := validSignedV3Catalog0241()
	m.Files = append(m.Files, ManifestFile{Path: "mods/core.jar", Size: 1, SHA256: strings.Repeat("c", 64), URL: "https://example.invalid/core", Ownership: "optional"})
	m.Files = append(m.Files, ManifestFile{Path: "mods/shader.jar", Size: 1, SHA256: strings.Repeat("d", 64), URL: "https://example.invalid/shader", Ownership: "optional"})
	c := ComponentCatalog0241{
		Components: []CatalogComponent0241{
			{ID: "core", Name: "Core", Files: []string{"mods/core.jar"}, Required: true, Visible: b0242(false)},
			{ID: "performance.sodium", Name: "Sodium & friends", Description: "Performance", Files: []string{"mods/sodium.jar", "mods/indium.jar"}, CategoryID: "performance", GroupID: "performance.optimization", Default: true, Visible: b0242(true), Metadata: map[string]string{"author": "A", "url": "https://example.org"}},
			{ID: "shaders", Name: "Shader", Files: []string{"mods/shader.jar"}, CategoryID: "visual", GroupID: "visual.shaders", Visible: b0242(true), Limited: true},
		},
		Categories:    []CatalogCategory0242{{ID: "visual", Name: "Visual"}, {ID: "performance", Name: "Performance", ParentID: "visual"}},
		Groups:        []CatalogGroup0242{{ID: "visual.quality", Name: "Quality", CategoryID: "visual"}, {ID: "visual.shaders", Name: "Shaders", ParentID: "visual.quality", CategoryID: "visual"}, {ID: "performance.optimization", Name: "Performance", CategoryID: "performance"}},
		Presets:       []CatalogPreset0242{{ID: "minimal", Name: "Minimal", Components: []string{}}, {ID: "optimized", Name: "Optimized", Components: []string{"performance.sodium"}}, {ID: "quality", Name: "Quality", Components: []string{"shaders"}}},
		DefaultPreset: "optimized",
	}
	created := NewComponentCatalog0242(c, 1)
	m.ComponentCatalog = &created
	return m
}
func TestComponentCatalogTopologyOperational0242(t *testing.T) {
	m := topologyFixture0242()
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		preset string
		ids    []string
	}{{"", []string{"core", "performance.sodium"}}, {"minimal", []string{"core"}}, {"quality", []string{"core", "shaders"}}}
	for _, tc := range tests {
		actual, err := ResolveCatalogPreset0242(*m.ComponentCatalog, tc.preset)
		if err != nil || !reflect.DeepEqual(actual, tc.ids) {
			t.Fatalf("preset %q: %v %v", tc.preset, actual, err)
		}
	}
	if _, err := ResolveCatalogPreset0242(*m.ComponentCatalog, "does-not-exist"); err == nil {
		t.Fatal("unknown preset accepted")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var parsed Manifest
	if err = json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestSchema(parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.ComponentCatalog.Digest != m.ComponentCatalog.Digest {
		t.Fatal("json roundtrip digest changed")
	}
	t.Logf("v2 Go digest fixture: %s", m.ComponentCatalog.Digest)
}
func TestComponentTopologyTamperAndCycles0242(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ComponentCatalog0241)
	}{
		{"category cycle", func(c *ComponentCatalog0241) { c.Categories[0].ParentID = "performance" }},
		{"group cycle", func(c *ComponentCatalog0241) { c.Groups[0].ParentID = "visual.shaders" }},
		{"dangling preset", func(c *ComponentCatalog0241) { c.Presets[0].Components = []string{"other"} }},
		{"duplicate preset member", func(c *ComponentCatalog0241) { c.Presets[0].Components = []string{"core", "core"} }},
		{"unknown category", func(c *ComponentCatalog0241) { c.Components[0].CategoryID = "unknown" }},
		{"missing visible", func(c *ComponentCatalog0241) { c.Components[0].Visible = nil }},
		{"inconsistent group", func(c *ComponentCatalog0241) { c.Components[1].GroupID = "visual.shaders" }},
		{"oversized metadata", func(c *ComponentCatalog0241) {
			c.Components[0].Metadata = map[string]string{"data": strings.Repeat("x", 1025)}
		}},
		{"duplicate group", func(c *ComponentCatalog0241) { c.Groups = append(c.Groups, c.Groups[0]) }},
		{"default preset unknown", func(c *ComponentCatalog0241) { c.DefaultPreset = "absent" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := topologyFixture0242()
			tc.mutate(m.ComponentCatalog)
			m.ComponentCatalog.Digest = ComponentCatalogDigest0242(*m.ComponentCatalog)
			if err := ValidateManifestSchema(m); err == nil {
				t.Fatal("invalid topology accepted with refreshed digest")
			}
		})
	}
	m := topologyFixture0242()
	m.ComponentCatalog.Components[1].Name = "Modified"
	if err := ValidateManifestSchema(m); err == nil {
		t.Fatal("metadata mutation accepted with stale signed digest")
	}
	m = topologyFixture0242()
	m.ComponentCatalog.Presets[2].Components = []string{"core"}
	if err := ValidateManifestSchema(m); err == nil {
		t.Fatal("preset mutation accepted with stale digest")
	}
}
