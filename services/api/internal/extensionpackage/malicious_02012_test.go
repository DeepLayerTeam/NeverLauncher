package extensionpackage

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func maliciousArchive02012(t *testing.T, entries []struct {
	name string
	mode os.FileMode
	data []byte
}) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "malicious.nlext")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMaliciousPackagesRejectedBeforeMetadataParsing02012(t *testing.T) {
	cases := []struct {
		name    string
		entries []struct {
			name string
			mode os.FileMode
			data []byte
		}
	}{
		{name: "traversal", entries: []struct {
			name string
			mode os.FileMode
			data []byte
		}{{"payload/../../escape", 0o644, []byte("x")}}},
		{name: "absolute", entries: []struct {
			name string
			mode os.FileMode
			data []byte
		}{{"/etc/passwd", 0o644, []byte("x")}}},
		{name: "windows-device", entries: []struct {
			name string
			mode os.FileMode
			data []byte
		}{{"payload/CON", 0o644, []byte("x")}}},
		{name: "symlink", entries: []struct {
			name string
			mode os.FileMode
			data []byte
		}{{"payload/link", os.ModeSymlink | 0o777, []byte("../../outside")}}},
		{name: "case-collision", entries: []struct {
			name string
			mode os.FileMode
			data []byte
		}{{"payload/a", 0o644, []byte("x")}, {"PAYLOAD/A", 0o644, []byte("x")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := maliciousArchive02012(t, tc.entries)
			analysis, err := analyze0203(p)
			if analysis != nil {
				_ = analysis.close()
			}
			if err == nil {
				t.Fatalf("malicious archive %s was accepted", tc.name)
			}
		})
	}
}

func TestArchivePathControlAndCrossPlatformAliasesRejected02012(t *testing.T) {
	for _, name := range []string{"payload/a\\b", "payload/a\x01b", "payload/trailing. ", "payload/LPT1.txt", "../payload/x", "payload/a/../x", strings.Repeat("a", 256)} {
		if err := validateArchivePath0203(name); err == nil {
			t.Fatalf("unsafe archive path accepted: %q", name)
		}
	}
}
