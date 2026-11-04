package model

import (
	"strings"
	"testing"
)

func runtimeFixture0223() Manifest {
	return Manifest{SchemaVersion: ManifestSchemaV2, Minecraft: MinecraftInfo{GameArgs: []string{"--demo", "value with spaces"}}, Runtime: RuntimeInfo{
		Java:    JavaInfo{MajorVersion: 21, MinimumMajorVersion: 17, RecommendedMajorVersion: 21, MaximumMajorVersion: 25},
		JVMArgs: []string{"-Xms2G", "-Xmx4G", "-Dexample=hello world"},
		Memory:  MemoryInfo{MinimumMb: 1024, RecommendedMb: 4096, MaximumMb: 8192},
		Launch:  RuntimeLaunch{ClasspathStrategy: "manifest", ClasspathEntries: []string{"libraries/client.jar"}, EnvironmentAllowlist: []string{"LANG", "DISPLAY"}},
	}, Files: []ManifestFile{{Path: "libraries/client.jar", Required: true}, {Path: "libraries/other.jar", Required: true}}}
}

func TestRuntimeConstraints0223AcceptsRunnableAndModule(t *testing.T) {
	m := runtimeFixture0223()
	if err := ValidateRuntimeConstraints0223(m); err != nil {
		t.Fatalf("valid runtime refused: %v", err)
	}
	m.Runtime.Launch.ModulepathEntries = []string{"libraries/other.jar"}
	m.Runtime.Launch.MainModule = "net.example.client/net.example.Main"
	if err := ValidateRuntimeConstraints0223(m); err != nil {
		t.Fatalf("valid module runtime refused: %v", err)
	}
}

func TestRuntimeConstraints0223RejectsUnsafeLaunch(t *testing.T) {
	tests := map[string]func(*Manifest){
		"java order":         func(m *Manifest) { m.Runtime.Java.MinimumMajorVersion = 25 },
		"java recommended":   func(m *Manifest) { m.Runtime.Java.RecommendedMajorVersion = 26 },
		"memory order":       func(m *Manifest) { m.Runtime.Memory.MaximumMb = 512 },
		"heap overflow":      func(m *Manifest) { m.Runtime.JVMArgs = append(m.Runtime.JVMArgs, "-Xmx999G") },
		"heap duplicate":     func(m *Manifest) { m.Runtime.JVMArgs = append(m.Runtime.JVMArgs, "-Xmx5G") },
		"heap min-max":       func(m *Manifest) { m.Runtime.JVMArgs = []string{"-Xms4G", "-Xmx2G"} },
		"classpath override": func(m *Manifest) { m.Runtime.JVMArgs = append(m.Runtime.JVMArgs, "-cp") },
		"unsafe agent":       func(m *Manifest) { m.Runtime.JVMArgs = append(m.Runtime.JVMArgs, "-javaagent:/tmp/agent.jar") },
		"unknown strategy":   func(m *Manifest) { m.Runtime.Launch.ClasspathStrategy = "unknown" },
		"unsigned jar":       func(m *Manifest) { m.Runtime.Launch.ClasspathEntries = []string{"libraries/unsigned.jar"} },
		"optional jar":       func(m *Manifest) { m.Files[0].Required = false },
		"unsafe path":        func(m *Manifest) { m.Runtime.Launch.ClasspathEntries = []string{"../client.jar"} },
		"duplicate jar": func(m *Manifest) {
			m.Runtime.Launch.ClasspathEntries = []string{"libraries/client.jar", "libraries/client.jar"}
		},
		"module needs path": func(m *Manifest) { m.Runtime.Launch.MainModule = "net.example" },
		"invalid module": func(m *Manifest) {
			m.Runtime.Launch.MainModule = "-bad"
			m.Runtime.Launch.ModulepathEntries = []string{"libraries/other.jar"}
		},
		"env code injection": func(m *Manifest) { m.Runtime.Launch.EnvironmentAllowlist = []string{"JAVA_TOOL_OPTIONS"} },
		"env duplicate":      func(m *Manifest) { m.Runtime.Launch.EnvironmentAllowlist = []string{"PATH", "path"} },
		"invalid game args":  func(m *Manifest) { m.Minecraft.GameArgs = []string{"hello\x00world"} },
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			m := runtimeFixture0223()
			edit(&m)
			if err := ValidateRuntimeConstraints0223(m); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestRuntimeConstraints0223PreservesUnconfiguredV2Draft(t *testing.T) {
	m := Manifest{SchemaVersion: ManifestSchemaV2}
	if err := ValidateRuntimeConstraints0223(m); err != nil {
		t.Fatal(err)
	}
	m.Runtime.Java.MajorVersion = 21
	m.Runtime.Launch.ClasspathEntries = []string{"bad.jar"}
	if err := ValidateRuntimeConstraints0223(m); err == nil || !strings.Contains(err.Error(), "not a required") {
		t.Fatalf("must reject undeclared classpath: %v", err)
	}
}
