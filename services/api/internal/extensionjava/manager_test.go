package extensionjava

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture0305(t *testing.T, major uint16, mainClass string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "host.jar")
	out, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(out)
	add := func(name string, buf []byte) {
		f, e := writer.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(buf); e != nil {
			t.Fatal(e)
		}
	}
	add("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\nMain-Class: "+mainClass+"\r\nLauncher-Extension-Class: example.Plugin\r\n\r\n"))
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header, 0xCAFEBABE)
	binary.BigEndian.PutUint16(header[6:], major)
	add("example/Plugin.class", header)
	add("ru/launcher/sdk/host/JavaExtensionHost.class", header)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestJavaJarInspection0305(t *testing.T) {
	file := fixture0305(t, 61, HostMain)
	result, err := Inspect(file)
	if err != nil {
		t.Fatal(err)
	}
	if result.MinimumJava != 17 || result.ClassFiles != 2 || result.EntrypointClass != "example.Plugin" {
		t.Fatalf("unexpected inspection %+v", result)
	}
	if err := os.WriteFile(file, []byte("not a jar"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(file); err == nil {
		t.Fatal("corrupt JAR accepted")
	}
}
func TestJavaJarMainClassAndRuntimeMinimum0305(t *testing.T) {
	if _, err := Inspect(fixture0305(t, 61, "example.WrongMain")); err == nil {
		t.Fatal("invalid Main-Class accepted")
	}
	info, err := Inspect(fixture0305(t, 65, HostMain))
	if err != nil {
		t.Fatal(err)
	}
	if info.MinimumJava != 21 {
		t.Fatalf("expected Java 21: %+v", info)
	}
	if _, err := Inspect(fixture0305(t, 110, HostMain)); err == nil {
		t.Fatal("unknown bytecode version accepted")
	}
}
func TestJavaJarSymlinkRejected0305(t *testing.T) {
	file := fixture0305(t, 61, HostMain)
	symlink := filepath.Join(t.TempDir(), "alias.jar")
	if err := os.Symlink(file, symlink); err != nil {
		t.Skip(err)
	}
	if _, err := Inspect(symlink); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestJavaRuntimeProbe0305(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell runtime fixture")
	}
	java := filepath.Join(t.TempDir(), "java")
	write := func(version string) {
		t.Helper()
		err := os.WriteFile(java, []byte("#!/bin/sh\nprintf '%s\\n' 'openjdk version \""+version+"\"'\n"), 0755)
		if err != nil {
			t.Fatal(err)
		}
	}
	write("21.0.1")
	got, err := ProbeRuntime(context.Background(), java, 17)
	if err != nil {
		t.Fatal(err)
	}
	if got.Feature != 21 {
		t.Fatalf("version=%d", got.Feature)
	}
	if _, err := ProbeRuntime(context.Background(), java, 22); err == nil {
		t.Fatal("higher required runtime incorrectly accepted")
	}
	write("11.0.20")
	if _, err := ProbeRuntime(context.Background(), java, 17); err == nil {
		t.Fatal("Java 11 accepted")
	}
	if _, err := ProbeRuntime(context.Background(), "relative-java", 17); err == nil {
		t.Fatal("relative binary path accepted")
	}
	write("21.0.1")
	if err := os.WriteFile(java, []byte("#!/bin/sh\necho unsupported\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeRuntime(context.Background(), java, 17); err == nil {
		t.Fatal("unrecognised JVM accepted")
	}
	if _, err := ProbeRuntime(context.Background(), strings.Repeat("/", 10000)+"java", 17); err == nil {
		t.Fatal("missing JVM accepted")
	}
}

// Runs against the real SDK-built host JAR in CI (no fake class bytes).
func TestRealJavaHostArtifact0305(t *testing.T) {
	source := os.Getenv("LAUNCHER_TEST_JAVA_HOST_JAR")
	if source == "" {
		t.Skip("JAR fixture not provided")
	}
	info, err := Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if info.ClassFiles < 10 {
		t.Fatalf("missing compiled SDK classes: %+v", info)
	}
	runtime, err := ProbeRuntime(context.Background(), "", info.MinimumJava)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Java host class %s on JVM %d", info.EntrypointClass, runtime.Feature)
}
