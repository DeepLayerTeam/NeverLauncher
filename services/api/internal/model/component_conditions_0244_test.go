package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestConditionalResolverEndToEnd0244(t *testing.T) {
	m := dependencyFixture0243()
	c := m.ComponentCatalog
	c.DefaultPreset = "" // default components, rather than explicit preset
	perf := &c.Components[1]
	perf.Conditions = &ComponentConditions0244{
		SchemaVersion: "1.0", OS: []string{"linux"}, Arch: []string{"x86_64"},
		JavaMajorMin: 17, JavaMajorMax: 21, MinecraftVersions: []string{"1.21.1"},
		Loaders: []string{"fabric"}, Permissions: []string{"component.perf"},
	}
	updated := NewComponentCatalog0244(*c, 5)
	m.ComponentCatalog = &updated
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	env := ComponentEnvironment0244{OS: "linux", Arch: "x86_64", JavaMajor: 21, MinecraftVersion: "1.21.1", Loader: "fabric", VerifiedPermissions: map[string]bool{"component.perf": true}}
	selected, err := ResolveCatalogConditional0244(updated, "", env)
	if err != nil {
		t.Fatal(err)
	}
	// No preset/default selects performance; required Core only.
	if !reflect.DeepEqual(selected, []string{"core", "performance.sodium"}) {
		t.Fatalf("unexpected selection %v", selected)
	}
	selected, err = ResolveCatalogConditional0244(updated, "quality", env)
	if err != nil || !reflect.DeepEqual(selected, []string{"core", "performance.sodium", "shaders"}) {
		t.Fatalf("quality: %v %v", selected, err)
	}
	for _, modify := range []struct {
		name   string
		change func(*ComponentEnvironment0244)
	}{
		{"os", func(e *ComponentEnvironment0244) { e.OS = "windows" }},
		{"arch", func(e *ComponentEnvironment0244) { e.Arch = "aarch64" }},
		{"java", func(e *ComponentEnvironment0244) { e.JavaMajor = 8 }},
		{"minecraft", func(e *ComponentEnvironment0244) { e.MinecraftVersion = "1.20.1" }},
		{"loader", func(e *ComponentEnvironment0244) { e.Loader = "forge" }},
		{"permissions", func(e *ComponentEnvironment0244) { e.VerifiedPermissions = nil }},
	} {
		t.Run(modify.name, func(t *testing.T) {
			e := env
			modify.change(&e)
			_, err := ResolveCatalogConditional0244(updated, "quality", e)
			if err == nil || !strings.Contains(err.Error(), "condition_unsatisfied") {
				t.Fatalf("must block with explanation: %v", err)
			}
		})
	}
	before := updated.Digest
	updated.Components[1].Conditions.Permissions = []string{"admin"}
	if ComponentCatalogDigest0244(updated) == before {
		t.Fatal("permission mutation did not alter signed digest")
	}
	if ValidateManifestSchema(func() Manifest { m.ComponentCatalog = &updated; return m }()) == nil {
		t.Fatal("tampered catalog accepted")
	}
}
func TestImplicitDefaultsAreFilteredBeforeDownload0244(t *testing.T) {
	m := dependencyFixture0243()
	m.ComponentCatalog.DefaultPreset = ""
	m.ComponentCatalog.Components[1].Conditions = &ComponentConditions0244{SchemaVersion: "1.0", OS: []string{"linux"}}
	v4 := NewComponentCatalog0244(*m.ComponentCatalog, 6)
	env := ComponentEnvironment0244{OS: "windows"}
	ids, err := ResolveCatalogConditional0244(v4, "", env)
	if err != nil || !reflect.DeepEqual(ids, []string{"core"}) {
		t.Fatalf("unavailable implicit default must be skipped: %v %v", ids, err)
	}
	v4.Components[1].Required = true
	_, err = ResolveCatalogConditional0244(v4, "", env)
	if err == nil || !strings.Contains(err.Error(), "required component") {
		t.Fatalf("required bypass: %v", err)
	}
}

func TestConditionalSchemaFailClosed0244(t *testing.T) {
	m := dependencyFixture0243()
	m.ComponentCatalog.Components[1].Conditions = &ComponentConditions0244{SchemaVersion: "1.0", OS: []string{"linux"}}
	if err := ValidateManifestSchema(m); err == nil {
		t.Fatal("v3 must reject unsigned v4 fields")
	}
	for _, condition := range []ComponentConditions0244{
		{SchemaVersion: "2.0"}, {SchemaVersion: "1.0", OS: []string{"unsupported"}},
		{SchemaVersion: "1.0", OS: []string{"linux", "linux"}},
		{SchemaVersion: "1.0", JavaMajorMin: 21, JavaMajorMax: 17},
		{SchemaVersion: "1.0", LoaderVersionRange: "not-semver"},
	} {
		c := *m.ComponentCatalog
		c.Components = append([]CatalogComponent0241(nil), c.Components...)
		cc := condition
		c.Components[1].Conditions = &cc
		c = NewComponentCatalog0244(c, 5)
		if err := ValidateCatalogConditions0244(c); err == nil {
			t.Fatalf("invalid conditions accepted %+v", condition)
		}
	}
}
func TestConditionalVersionRanges0244(t *testing.T) {
	v := &ComponentConditions0244{SchemaVersion: "1.0", MinecraftVersionRange: ">=1.20.0 <1.22.0", LoaderVersionRange: "^0.16.0"}
	env := ComponentEnvironment0244{MinecraftVersion: "1.21.1", LoaderVersion: "0.16.2"}
	if why := unavailable0244(v, env); why != "" {
		t.Fatalf("compatible: %s", why)
	}
	env.MinecraftVersion = "1.19.4"
	if why := unavailable0244(v, env); why == "" {
		t.Fatal("unsupported game version accepted")
	}
	env.MinecraftVersion = "24w12a"
	if why := unavailable0244(v, env); why == "" {
		t.Fatal("snapshot incorrectly matched semver condition")
	}
}
