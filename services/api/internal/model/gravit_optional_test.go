package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func gravitOptionalFiles02411() []ManifestFile {
	return []ManifestFile{
		{Path: "mods/nei.jar", Ownership: "optional", Size: 4, SHA256: strings.Repeat("a", 64)},
		{Path: "mods/waila.jar", Ownership: "optional", Size: 4, SHA256: strings.Repeat("b", 64)},
	}
}
func gravitOptionalSource02411() []byte {
	return []byte(`{"title":"Example","updateOptional":[
 {"name":"NotEnoughItems","info":"Recipes","category":"Interface","mark":true,"visible":true,"actions":[{"type":"file","files":{"mods/nei.jar":""}}],"triggersList":[{"type":"os","os":"MUSTDIE","required":true,"inverted":false}]},
 {"name":"Waila","dependenciesFile":[{"name":"NotEnoughItems"}],"conflictFile":[],"actions":[{"type":"file","files":{"mods/waila.jar":""}},{"type":"jvmArgs","args":["-XX:+UseG1GC"]}]}]}`)
}
func TestGravitOptionalMigrationRealCatalog02411(t *testing.T) {
	base := NewComponentCatalog0245(ComponentCatalog0241{}, 1)
	result, err := ConvertGravitOptionalView02411(gravitOptionalSource02411(), base, gravitOptionalFiles02411())
	if err != nil || !result.Ready {
		t.Fatalf("migration: %v %+v", err, result.Fields)
	}
	if len(result.Catalog.Components) != 2 || len(result.Catalog.Categories) != 1 {
		t.Fatalf("bad topology %+v", result.Catalog)
	}
	a, b := result.Catalog.Components[0], result.Catalog.Components[1]
	if !a.Default || len(a.Actions) != 1 || a.Actions[0].Type != "File" || a.Conditions == nil || a.Conditions.OS[0] != "windows" {
		t.Fatalf("mapped optional invalid %+v", a)
	}
	if len(b.Dependencies) != 1 || b.Dependencies[0].ID != a.ID || len(b.Actions) != 2 {
		t.Fatalf("relation/actions invalid %+v", b)
	}
	m := validSignedV3Catalog0241()
	m.Files = gravitOptionalFiles02411()
	m.ComponentCatalog = &result.Catalog
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatalf("not a publishable catalog: %v", err)
	}
	ids, err := ResolveCatalogConditional0244(result.Catalog, "", ComponentEnvironment0244{OS: "windows", JavaMajor: 17})
	if err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("resolution %+v %v", ids, err)
	}
	again, _ := ConvertGravitOptionalView02411(gravitOptionalSource02411(), base, gravitOptionalFiles02411())
	if result.Catalog.Digest != again.Catalog.Digest || a.ID != again.Catalog.Components[0].ID {
		t.Fatal("nondeterministic import")
	}
	encoded, _ := json.Marshal(result.Catalog)
	if !strings.Contains(string(encoded), `"schemaVersion":"5.0"`) {
		t.Fatal("not real v5 catalog")
	}
}
func TestGravitOptionalMigrationRejectUnsupported02411(t *testing.T) {
	base := NewComponentCatalog0245(ComponentCatalog0241{}, 1)
	cases := []struct {
		name   string
		source string
		files  []ManifestFile
	}{
		{"foreign rename", `[{"name":"A","actions":[{"type":"file","files":{"mods/nei.jar":"mods/evil.jar"}}]}]`, gravitOptionalFiles02411()},
		{"unsafe JVM", `[{"name":"A","actions":[{"type":"file","files":{"mods/nei.jar":""}},{"type":"jvmArgs","args":["-javaagent:/tmp/evil.jar"]}]}]`, gravitOptionalFiles02411()},
		{"unverified file", `[{"name":"A","actions":[{"type":"file","files":{"mods/evil.jar":""}}]}]`, gravitOptionalFiles02411()},
		{"legacy inverted trigger", `[{"name":"A","actions":[{"type":"file","files":{"mods/nei.jar":""}}],"triggersList":[{"type":"os","os":"MACOSX","required":true,"inverted":true}]}]`, gravitOptionalFiles02411()[:1]},
		{"permissions", `[{"name":"A","permissions":2,"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`, gravitOptionalFiles02411()[:1]},
		{"missing dependency", `[{"name":"A","dependenciesFile":[{"name":"Missing"}],"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`, gravitOptionalFiles02411()[:1]},
		{"unknown field", `[{"name":"A","execute":"evil","actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`, gravitOptionalFiles02411()[:1]},
		{"no files", `[{"name":"A","actions":[{"type":"jvmArgs","args":["-XX:+UseG1GC"]}]}]`, nil},
		{"unsupported visual nesting", `[{"name":"A","subTreeLevel":2,"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`, gravitOptionalFiles02411()[:1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ConvertGravitOptionalView02411([]byte(tc.source), base, tc.files)
			if err != nil {
				t.Fatal(err)
			}
			if r.Ready || r.Summary["blocked"]+r.Summary["manual"] == 0 {
				t.Fatalf("silently accepted %+v", r)
			}
		})
	}
}
func TestGravitOptionalRejectDuplicatesAndTamper02411(t *testing.T) {
	base := NewComponentCatalog0245(ComponentCatalog0241{}, 1)
	for _, source := range []string{`[{"name":"A","name":"B"}]`, `[{"name":"A","actions":[{"type":"file","files":{"mods/nei.jar":"","mods/nei.jar":""}}]}]`} {
		r, e := ConvertGravitOptionalView02411([]byte(source), base, gravitOptionalFiles02411()[:1])
		if e == nil && r.Ready {
			t.Fatal("duplicate JSON key accepted")
		}
	}
	r, e := ConvertGravitOptionalView02411([]byte(`[{"name":"A","actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`), base, gravitOptionalFiles02411()[:1])
	if e != nil || !r.Ready {
		t.Fatalf("import %+v %v", r.Fields, e)
	}
	m := validSignedV3Catalog0241()
	m.Files = gravitOptionalFiles02411()[:1]
	m.ComponentCatalog = &r.Catalog
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	m.ComponentCatalog.Components[0].Actions[0].Path = "mods/evil.jar"
	if ValidateManifestSchema(m) == nil {
		t.Fatal("unsigned action mutation accepted")
	}
}

func TestGravitOptionalClassPathAndBoundedJava02411(t *testing.T) {
	source := `[{"name":"Library","actions":[{"type":"classpath","args":["mods/nei.jar"],"useAltClasspath":false},{"type":"file","files":{"mods/nei.jar":""}}],"triggersList":[{"type":"java","minVersion":17,"maxVersion":21,"required":true,"inverted":false},{"type":"arch","arch":"X86_64","required":true,"inverted":false}]}]`
	base := NewComponentCatalog0245(ComponentCatalog0241{}, 1)
	r, e := ConvertGravitOptionalView02411([]byte(source), base, gravitOptionalFiles02411()[:1])
	if e != nil || !r.Ready {
		t.Fatalf("classpath migration: %v %+v", e, r.Fields)
	}
	c := r.Catalog.Components[0]
	if len(c.Actions) != 2 || c.Actions[1].Type != "ClassPath" || c.Conditions.JavaMajorMax != 21 || c.Conditions.Arch[0] != "x86_64" {
		t.Fatalf("unexpected classpath/trigger %+v", c)
	}
	m := validSignedV3Catalog0241()
	m.Files = gravitOptionalFiles02411()[:1]
	m.ComponentCatalog = &r.Catalog
	if e := ValidateManifestSchema(m); e != nil {
		t.Fatal(e)
	}
	for _, src := range []string{
		`[{"name":"Library","actions":[{"type":"classpath","args":["mods/nei.jar"],"useAltClasspath":true},{"type":"file","files":{"mods/nei.jar":""}}]}]`,
		`[{"name":"Library","groupFile":[{"name":"Another"}],"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`,
		`[{"name":"Library","isPreset":true,"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]`,
	} {
		r, e := ConvertGravitOptionalView02411([]byte(src), base, gravitOptionalFiles02411()[:1])
		if e == nil && r.Ready {
			t.Fatalf("unsafe structure accepted: %s", src)
		}
	}
}

func TestGravitOptionalNullableCollections02411(t *testing.T) {
	base := NewComponentCatalog0245(ComponentCatalog0241{}, 1)
	source := `{"updateOptional":[{"name":"Sample","info":null,"category":null,"dependenciesFile":null,"conflictFile":null,"groupFile":null,"triggersList":null,"triggers":null,"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]}`
	r, e := ConvertGravitOptionalView02411([]byte(source), base, gravitOptionalFiles02411()[:1])
	if e != nil || !r.Ready {
		t.Fatalf("nullable collections %+v %v", r.Fields, e)
	}
}
