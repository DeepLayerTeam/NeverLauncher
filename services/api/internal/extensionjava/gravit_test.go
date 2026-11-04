package extensionjava

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gravitJar0307(t *testing.T, ext, ported string, include bool) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "compat.jar")
	fd, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(fd)
	add := func(name string, data []byte) {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	add("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\nMain-Class: "+HostMain+"\r\nLauncher-Extension-Class: "+ext+"\r\nLauncher-Gravit-Module-Class: "+ported+"\r\n\r\n"))
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header, 0xCAFEBABE)
	binary.BigEndian.PutUint16(header[6:], 61)
	for _, name := range []string{"ru/launcher/sdk/host/JavaExtensionHost.class", "ru/launcher/sdk/gravit/GravitCompatExtension.class", "example/Other.class"} {
		add(name, header)
	}
	if include {
		add(strings.ReplaceAll(ported, ".", "/")+".class", header)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	if e := fd.Close(); e != nil {
		t.Fatal(e)
	}
	return file
}
func TestGravitOptInValidation0307(t *testing.T) {
	const entry = "ru.launcher.sdk.gravit.GravitCompatExtension"
	good := gravitJar0307(t, entry, "example.Ported", true)
	result, err := Inspect(good)
	if err != nil {
		t.Fatal(err)
	}
	if result.GravitModuleClass != "example.Ported" {
		t.Fatalf("wrong module: %+v", result)
	}
	for _, f := range []string{
		gravitJar0307(t, entry, "example.NotFound", false),
		gravitJar0307(t, entry, "pro.gravit.launcher.LaunchServer", true),
		gravitJar0307(t, "example.Other", "example.Ported", true),
	} {
		if _, err := Inspect(f); err == nil {
			t.Fatalf("accepted incompatible module %s", f)
		}
	}
}
func TestRealGravitPortJar0307(t *testing.T) {
	file := os.Getenv("LAUNCHER_TEST_GRAVIT_PORT_JAR")
	if file == "" {
		t.Skip("real JAR not provided")
	}
	info, err := Inspect(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.GravitModuleClass != "ru.example.gravit.PortedModule" || info.ClassFiles < 20 {
		t.Fatalf("invalid JAR: %+v", info)
	}
}
