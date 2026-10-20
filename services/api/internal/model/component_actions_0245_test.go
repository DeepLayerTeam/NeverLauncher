package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func signedActionsFixture0245() Manifest {
	m := dependencyFixture0243()
	m.ComponentCatalog.Components[1].Actions = []ComponentAction0245{
		{Type: "File", Path: m.ComponentCatalog.Components[1].Files[0]},
		{Type: "ClassPath", Path: m.ComponentCatalog.Components[1].Files[0]},
		{Type: "JvmArgs", Args: []string{"-Dfabric.log.level=debug", "-XX:MaxGCPauseMillis=200"}},
		{Type: "ClientArgs", Args: []string{"--never-optional-debug=1"}},
	}
	v5 := NewComponentCatalog0245(*m.ComponentCatalog, 7)
	m.ComponentCatalog = &v5
	return m
}
func TestSignedOptionalActionsEndToEnd0245(t *testing.T) {
	m := signedActionsFixture0245()
	if err := ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"type":"ClassPath"`) {
		t.Fatal("action missing from signing payload")
	}
	for _, preset := range []string{"minimal", "optimized", "quality"} {
		if _, err := ResolveCatalogPreset0242(*m.ComponentCatalog, preset); err != nil {
			t.Fatalf("preset %s %v", preset, err)
		}
	}
	m.ComponentCatalog.Components[1].Actions[2].Args[0] = "-Dfabric.log.level=trace"
	if ValidateManifestSchema(m) == nil {
		t.Fatal("tampered optional JVM arguments accepted")
	}
}
func TestSignedOptionalActionsRejectUnsignedUnsafe0245(t *testing.T) {
	dangerous := []ComponentAction0245{
		{Type: "ClassPath", Path: "mods/unsigned.jar"},
		{Type: "File", Path: "../evil.jar"},
		{Type: "JvmArgs", Args: []string{"-javaagent:bad.jar"}},
		{Type: "JvmArgs", Args: []string{"-Xmx999g"}},
		{Type: "JvmArgs", Args: []string{"-Djava.library.path=/tmp"}},
		{Type: "JvmArgs", Args: []string{"@malicious-args.txt"}},
		{Type: "ClientArgs", Args: []string{"--accessToken=stolen"}},
		{Type: "ClientArgs", Args: []string{"--gameDir=/tmp"}},
		{Type: "ClientArgs", Args: []string{"--version=evil"}},
		{Type: "ClientArgs", Args: []string{"--server=evil"}},
		{Type: "JvmArgs", Args: []string{"-cp"}},
		{Type: "Execute", Path: "mods/a.jar"},
		{Type: "File", Path: ""},
		{Type: "ClassPath", Path: "mods/config.json"},
	}
	for _, action := range dangerous {
		m := signedActionsFixture0245()
		m.ComponentCatalog.Components[1].Actions = []ComponentAction0245{action}
		v5 := NewComponentCatalog0245(*m.ComponentCatalog, 8)
		m.ComponentCatalog = &v5
		if err := ValidateManifestSchema(m); err == nil {
			t.Fatalf("unsafe action accepted: %+v", action)
		}
	}
	m := signedActionsFixture0245()
	v4 := NewComponentCatalog0244(*m.ComponentCatalog, 9)
	m.ComponentCatalog = &v4
	if err := ValidateManifestSchema(m); err == nil {
		t.Fatal("actions in schema 4.0 accepted unsigned")
	}
}
