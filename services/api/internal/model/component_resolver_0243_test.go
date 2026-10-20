package model

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func dependencyFixture0243() Manifest {
	m := topologyFixture0242()
	for i := range m.ComponentCatalog.Components {
		m.ComponentCatalog.Components[i].Version = []string{"1.0.0", "0.5.2", "2.1.0"}[i]
	}
	m.ComponentCatalog.Components[1].Dependencies = []ComponentRequirement0243{{ID: "core", VersionRange: ">=1.0.0 <2.0.0"}}
	m.ComponentCatalog.Components[2].Dependencies = []ComponentRequirement0243{{ID: "performance.sodium", VersionRange: "^0.5.0"}}
	m.ComponentCatalog.Components[1].ExclusiveGroup = "performance-engine"
	c := NewComponentCatalog0243(*m.ComponentCatalog, 4)
	m.ComponentCatalog = &c
	return m
}
func TestComponentResolverOperational0243(t *testing.T) {
	m := dependencyFixture0243()
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		preset   string
		expected []string
	}{
		{"minimal", []string{"core"}},
		{"optimized", []string{"core", "performance.sodium"}},
		{"quality", []string{"core", "performance.sodium", "shaders"}},
		{"", []string{"core", "performance.sodium"}},
	}
	for _, tc := range cases {
		ids, err := ResolveCatalogPreset0242(*m.ComponentCatalog, tc.preset)
		if err != nil || !reflect.DeepEqual(ids, tc.expected) {
			t.Fatalf("preset %q: %v %v", tc.preset, ids, err)
		}
	}
	if _, err := ResolveCatalogPreset0242(*m.ComponentCatalog, "missing"); err == nil {
		t.Fatal("unknown preset accepted")
	}
	// Catalog v3 is a signed superset of v2 topology, not a mutable selection.
	raw, _ := json.Marshal(m)
	var decoded Manifest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestSchema(decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"versionRange":`) {
		t.Fatal("constraints are absent from signed JSON")
	}
	mutated := dependencyFixture0243()
	mutated.ComponentCatalog.Components[2].Dependencies[0].VersionRange = "^0.6.0"
	if err := ValidateManifestSchema(mutated); err == nil {
		t.Fatal("tampering with constraints did not invalidate digest")
	}
}
func TestDependencyResolverRejectsImpossible0243(t *testing.T) {
	cases := []struct {
		name, code string
		modify     func(*ComponentCatalog0241)
	}{
		{"cycle", "cycle", func(c *ComponentCatalog0241) {
			c.Components[0].Dependencies = []ComponentRequirement0243{{ID: "shaders"}}
		}},
		{"missing dependency", "invalid_reference", func(c *ComponentCatalog0241) {
			c.Components[2].Dependencies = []ComponentRequirement0243{{ID: "unknown"}}
		}},
		{"self dependency", "invalid_reference", func(c *ComponentCatalog0241) {
			c.Components[2].Dependencies = []ComponentRequirement0243{{ID: "shaders"}}
		}},
		{"invalid version", "invalid_version", func(c *ComponentCatalog0241) { c.Components[0].Version = "1.0" }},
		{"invalid range", "invalid_range", func(c *ComponentCatalog0241) { c.Components[2].Dependencies[0].VersionRange = ">=bad" }},
		{"mismatched dependency", "version_mismatch", func(c *ComponentCatalog0241) { c.Components[2].Dependencies[0].VersionRange = ">=0.6.0" }},
		{"transitive conflict", "conflict", func(c *ComponentCatalog0241) { c.Components[2].Conflicts = []ComponentRequirement0243{{ID: "core"}} }},
		{"exclusive group", "exclusive_group", func(c *ComponentCatalog0241) { c.Components[2].ExclusiveGroup = "performance-engine" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := dependencyFixture0243()
			tc.modify(m.ComponentCatalog)
			m.ComponentCatalog.Digest = ComponentCatalogDigest0243(*m.ComponentCatalog)
			err := ValidateManifestSchema(m)
			if err == nil || !strings.Contains(err.Error(), tc.code) {
				t.Fatalf("want explanatory %s, got %v", tc.code, err)
			}
		})
	}
}
func TestVersionRanges0243(t *testing.T) {
	cases := []struct {
		v, expr string
		match   bool
	}{
		{"1.2.3", ">=1.0.0 <2.0.0", true},
		{"2.0.0", ">=1.0.0 <2.0.0", false},
		{"0.5.2", "^0.5.0", true},
		{"0.6.0", "^0.5.0", false},
		{"0.0.5", "^0.0.4", false},
		{"1.5.1", "~1.5.0", true},
		{"1.6.0", "~1.5.0", false},
		{"1.3.0", "<1.0.0 || >=1.3.0", true},
		{"1.2.3-alpha.1", "<1.2.3", true},
		{"1.2.3", "=1.2.3+metadata", true},
	}
	for _, tc := range cases {
		got, err := matchRange0243(tc.v, tc.expr)
		if err != nil || got != tc.match {
			t.Errorf("%s %s => %v, %v", tc.v, tc.expr, got, err)
		}
	}
	for _, expr := range []string{">=foo", "^1.2", "=>1.2.0", "", "   ||  >1.2.0"} {
		if expr == "" {
			continue
		}
		if _, err := matchRange0243("1.2.3", expr); err == nil {
			t.Errorf("invalid range accepted: %q", expr)
		}
	}
}
func TestResolutionErrorTyped0243(t *testing.T) {
	m := dependencyFixture0243()
	_, err := ResolveCatalogPreset0242(*m.ComponentCatalog, "does-not-exist")
	var explanation *ResolutionError0243
	if !errors.As(err, &explanation) || explanation.Code != "unknown_preset" {
		t.Fatalf("expected typed error; got %v", err)
	}
	m = topologyFixture0242()
	m.ComponentCatalog.Components[0].Version = "1.0.0"
	m.ComponentCatalog.Digest = ComponentCatalogDigest0242(*m.ComponentCatalog)
	if err = ValidateManifestSchema(m); err == nil || !strings.Contains(err.Error(), "unsigned v3 constraints") {
		t.Fatalf("unsigned rules accepted by legacy schema: %v", err)
	}
}

func TestGoSignedDependencyFixture0243(t *testing.T) {
	// Verify the actual Go publisher's encoding/json + crypto/ed25519 bytes,
	// also consumed by the native Rust cross-language fixture test.
	raw, err := os.ReadFile("../../../../runtime/neverruntime/tests/fixtures/catalog_dependency_0243_go_signed.json")
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(m.Signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(m.Signature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = nil
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		t.Fatal("signed v3 catalog fixture signature invalid")
	}
	if m.ComponentCatalog.Digest != "53fe27537e66b25479003cdca208f3272091ef78b9278e16009e5097d4281988" {
		t.Fatal("catalog digest changed")
	}
}
