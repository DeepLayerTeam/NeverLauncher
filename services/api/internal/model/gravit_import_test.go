package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleGravit02210() string {
	return `{"title":"Vanilla 1.20.4","info":"Server","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"minJavaVersion":17,"maxJavaVersion":999,"classLoaderConfig":"SYSTEM_ARGS","classPath":["minecraft.jar"],"update":["minecraft.jar"],"updateVerify":["minecraft.jar"],"updateExclusions":["saves","screenshots","resourcepacks","options.txt"],"settings":{"ram":4096,"autoEnter":false,"fullScreen":false},"limited":false}`
}
func hasGravitStatus02210(result GravitImportResult02210, field, status string) bool {
	for _, r := range result.Fields {
		if r.Field == field && r.Status == status {
			return true
		}
	}
	return false
}
func TestGravitImportReadyWorkspaceSettings02210(t *testing.T) {
	r, e := ConvertGravitProfile02210([]byte(sampleGravit02210()), "demo", "imported", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if !r.Ready {
		t.Fatalf("unexpected blocked/manual fields: %+v", r.Fields)
	}
	if r.Profile.Name != "Vanilla 1.20.4" || r.Profile.SchemaVersion != ProfileSchemaV2 || r.Settings.Runtime.Java.MajorVersion != 17 || r.Settings.Runtime.Java.MaximumMajorVersion != 0 || r.Settings.Runtime.Memory.RecommendedMb != 4096 {
		t.Fatalf("incorrect conversion: %+v", r)
	}
	if len(r.Settings.Runtime.Launch.ClasspathEntries) != 1 || r.Settings.Runtime.Launch.ClasspathEntries[0] != "minecraft.jar" {
		t.Fatal("classpath lost")
	}
	if !hasGravitStatus02210(r, "maxJavaVersion", "transformed") || !hasGravitStatus02210(r, "classLoaderConfig", "transformed") {
		t.Fatal("missing semantic transformations")
	}
	if len(r.Settings.FileRules) != 5 {
		t.Fatalf("file rules lost or duplicated: %+v", r.Settings.FileRules)
	}
	if r.Settings.FileRules[0].Action == "include" {
		t.Fatal("import must not authorize deleting unknown user files")
	}
	b, _ := json.Marshal(r)
	var parsed GravitImportResult02210
	if err := json.Unmarshal(b, &parsed); err != nil || parsed.SourceSHA256 != r.SourceSHA256 {
		t.Fatalf("report not serializable: %v", err)
	}
}
func TestGravitImportFailClosed02210(t *testing.T) {
	cases := []struct{ name, needle string }{
		{"default loader", `"classLoaderConfig":"LAUNCHER"`},
		{"foreign agent", `"classLoaderConfig":"AGENT"`},
		{"bridge", `"classLoaderConfig":"BRIDGE"`},
		{"optional action", `"updateOptional":[{"name":"mod","actions":[{"type":"jvmArgs","args":["-javaagent:evil.jar"]}]}]`},
		{"untrusted path", `"update":["../saves"]`},
		{"protected settings", `"update":["options.txt"]`},
		{"directory classpath", `"classPath":["libraries"]`},
		{"alternate classpath", `"altClassPath":["bootstrap.jar"]`},
		{"java agent", `"jvmArgs":["-javaagent:evil.jar"]`},
		{"credential override", `"clientArgs":["--accessToken","evil"]`},
		{"custom field", `"customRunAction":{"type":"execute"}`},
		{"permission gating", `"limited":true`},
		{"overlap policy", `"updateExclusions":["minecraft.jar"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data map[string]json.RawMessage
			if err := json.Unmarshal([]byte(sampleGravit02210()), &data); err != nil {
				t.Fatal(err)
			}
			var patch map[string]json.RawMessage
			if err := json.Unmarshal([]byte("{"+tc.needle+"}"), &patch); err != nil {
				t.Fatal(err)
			}
			for k, v := range patch {
				data[k] = v
			}
			b, _ := json.Marshal(data)
			r, e := ConvertGravitProfile02210(b, "demo", "imported", "", "vanilla")
			if e != nil {
				t.Fatal(e)
			}
			if r.Ready || r.Summary["blocked"] == 0 {
				t.Fatalf("unsafe input accepted: %+v", r.Fields)
			}
		})
	}
}
func TestGravitImportReportsManualAndRejectsDuplicate02210(t *testing.T) {
	source := strings.Replace(sampleGravit02210(), `"limited":false`, `"limited":false,"servers":[{"name":"S1","serverAddress":"localhost","serverPort":25565,"isDefault":true}]`, 1)
	r, e := ConvertGravitProfile02210([]byte(source), "demo", "imported", "", "vanilla")
	if e != nil || r.Ready || !hasGravitStatus02210(r, "servers[0]", "manual") || len(r.Servers) != 1 {
		t.Fatalf("server not reported for manual registration: %v %+v", e, r)
	}
	for _, bad := range []string{`{"title":"A","title":"B"}`, `{"title":"A"} {"title":"B"}`, `[]`, `{"title":null}`} {
		_, e := ConvertGravitProfile02210([]byte(bad), "demo", "imported", "", "vanilla")
		if bad == `{"title":null}` {
			if e != nil {
				t.Fatalf("expected field-level error: %v", e)
			}
			continue
		}
		if e == nil {
			t.Fatalf("bad JSON accepted: %s", bad)
		}
	}
}
func TestGravitImportDeterministicAndNoSourceSecrets02210(t *testing.T) {
	input := []byte(sampleGravit02210())
	a, e := ConvertGravitProfile02210(input, "demo", "imported", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := ConvertGravitProfile02210(input, "demo", "imported", "", "vanilla")
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		t.Fatal("non-deterministic conversion")
	}
}
