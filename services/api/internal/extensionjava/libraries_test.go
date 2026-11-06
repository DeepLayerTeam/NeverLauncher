package extensionjava

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func class0482(major uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, 0xcafebabe)
	binary.BigEndian.PutUint16(b[6:], major)
	return b
}
func zip0482(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var bytesOut bytes.Buffer
	z := zip.NewWriter(&bytesOut)
	for name, data := range entries {
		out, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return bytesOut.Bytes()
}
func makeFixture0482(t *testing.T, libraryBytes []byte, api string) string {
	t.Helper()
	name := "META-INF/launcher/libs/test-1.2.3.jar"
	checksum := sha256.Sum256(libraryBytes)
	lock := name + "\ttest:dep\t1.2.3\t" + hex.EncodeToString(checksum[:]) + "\t" + api + "\n"
	host := zip0482(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                         []byte("Manifest-Version: 1.0\r\nMain-Class: " + HostMain + "\r\nLauncher-Extension-Class: example.Plugin\r\n\r\n"),
		"example/Plugin.class":                         class0482(61),
		"ru/launcher/sdk/host/JavaExtensionHost.class": class0482(61),
		name:            libraryBytes,
		libraryLock0482: []byte(lock),
	})
	file := filepath.Join(t.TempDir(), "host.jar")
	if err := os.WriteFile(file, host, 0600); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestActualCompiledDependencyHost0482(t *testing.T) {
	file := os.Getenv("LAUNCHER_TEST_JAVA_DEPENDENCY_JAR")
	if file == "" {
		t.Skip("Не предоставлено тестовое окружение зависимостей Java с подписанной структурой")
	}
	info, err := Inspect(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.ClassFiles < 3 || len(info.Libraries) != 1 || info.Libraries[0].Version != "1.2.3" || info.EntrypointClass != "example.extension.DependencyExtension" {
		t.Fatalf("Неожиданный пакет фактической среды выполнения: %+v", info)
	}
}

func TestPinnedLibraryJarInspect0482(t *testing.T) {
	lib := zip0482(t, map[string][]byte{"example/deps/Greeter.class": class0482(65), "META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\n\r\n")})
	jar, err := Inspect(makeFixture0482(t, lib, ">=1.0 <2.0"))
	if err != nil {
		t.Fatal(err)
	}
	if jar.MinimumJava != 21 || jar.ClassFiles != 3 || len(jar.Libraries) != 1 || jar.Libraries[0].Coordinate != "test:dep" {
		t.Fatalf("Некорректный набор библиотек: %+v", jar)
	}
}

func TestConflictingDependencyLibrariesRejected0482(t *testing.T) {
	libA := zip0482(t, map[string][]byte{"org/example/Utility.class": class0482(61)})
	libB := zip0482(t, map[string][]byte{"org/example/Utility.class": class0482(65)})
	paths := []string{"META-INF/launcher/libs/alpha-1.0.0.jar", "META-INF/launcher/libs/beta-2.0.0.jar"}
	sums := make([]string, 2)
	for i, blob := range [][]byte{libA, libB} {
		sum := sha256.Sum256(blob)
		sums[i] = hex.EncodeToString(sum[:])
	}
	index := paths[0] + "\torg.example:alpha\t1.0.0\t" + sums[0] + "\t>=1.0 <2.0\n" +
		paths[1] + "\torg.example:beta\t2.0.0\t" + sums[1] + "\t>=1.0 <2.0\n"
	host := zip0482(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                         []byte("Manifest-Version: 1.0\r\nMain-Class: " + HostMain + "\r\nLauncher-Extension-Class: example.Plugin\r\n\r\n"),
		"example/Plugin.class":                         class0482(61),
		"ru/launcher/sdk/host/JavaExtensionHost.class": class0482(61),
		paths[0]: libA, paths[1]: libB, libraryLock0482: []byte(index),
	})
	jar := filepath.Join(t.TempDir(), "conflict.jar")
	if err := os.WriteFile(jar, host, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(jar); err == nil || !strings.Contains(err.Error(), "class conflict") {
		t.Fatalf("Ошибочно принят повторяющийся класс сторонней библиотеки: %v", err)
	}
	// Разные ID зависимостей могут сосуществовать, но две версии одних и тех же координат —
	// нет.
	index = strings.Replace(index, "org.example:beta", "org.example:alpha", 1)
	host = zip0482(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                         []byte("Manifest-Version: 1.0\r\nMain-Class: " + HostMain + "\r\nLauncher-Extension-Class: example.Plugin\r\n\r\n"),
		"example/Plugin.class":                         class0482(61),
		"ru/launcher/sdk/host/JavaExtensionHost.class": class0482(61),
		paths[0]: libA, paths[1]: libB, libraryLock0482: []byte(index),
	})
	if err := os.WriteFile(jar, host, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(jar); err == nil || !strings.Contains(err.Error(), "duplicate dependency") {
		t.Fatalf("Ошибочно приняты повторяющиеся координаты зависимостей: %v", err)
	}
}

func TestDuplicateJarClassesRejected0482(t *testing.T) {
	for _, bad := range []string{"example/Plugin.class", "ru/launcher/sdk/core/HostSession.class", "java/lang/String.class"} {
		lib := zip0482(t, map[string][]byte{bad: class0482(61)})
		if _, err := Inspect(makeFixture0482(t, lib, ">=1.0 <2.0")); err == nil {
			t.Fatalf("Ошибочно принят конфликт %s", bad)
		}
	}
}
func TestUnsafeAndLockedDependencyRejected0482(t *testing.T) {
	for _, contents := range []map[string][]byte{
		{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nClass-Path: /tmp/evil.jar\r\n\r\n"), "lib/Safe.class": class0482(61)},
		{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"), "lib/Safe.class": class0482(61)},
		{"../escape.class": class0482(61)},
		{"lib/Preview.class": []byte{0xca, 0xfe, 0xba, 0xbe, 0xff, 0xff, 0, 61}},
	} {
		if _, err := Inspect(makeFixture0482(t, zip0482(t, contents), ">=1.0 <2.0")); err == nil {
			t.Fatal("Ошибочно принят повреждённый встроенный JAR")
		}
	}
	badHash := makeFixture0482(t, zip0482(t, map[string][]byte{"lib/Safe.class": class0482(61)}), ">=1.0 <2.0")
	raw, err := os.ReadFile(badHash)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	parts := map[string][]byte{}
	for _, file := range zr.File {
		data, err := func() ([]byte, error) {
			r, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer r.Close()
			var out bytes.Buffer
			_, err = out.ReadFrom(r)
			return out.Bytes(), err
		}()
		if err != nil {
			t.Fatal(err)
		}
		if file.Name == libraryLock0482 {
			data = []byte(strings.Replace(string(data), "test:dep", "test:DEP", 1))
			data = []byte(strings.Replace(string(data), "\t", " ", 1))
		}
		parts[file.Name] = data
	}
	if err := os.WriteFile(badHash, zip0482(t, parts), 0600); err != nil {
		t.Fatal(err)
	}
	// Некорректные контрольные суммы и неожиданное содержимое индекса всегда
	// вызывают отказ.
	if _, err := Inspect(badHash); err == nil {
		t.Fatal("Ошибочно принят изменённый файл блокировки")
	}
}
