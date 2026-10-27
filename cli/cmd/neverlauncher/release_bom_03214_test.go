package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func bomFixtures03214(t *testing.T) (source, dir string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
	source = t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "VERSION"), []byte("0.32.14\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, rel := range bomSources03214() {
		input, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(source, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, input, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir = t.TempDir()
	for _, name := range releaseArtifacts("0.32.14") {
		if name == releaseBOMFile03214 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "BUILD_NOTES.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return
}
func TestReleaseBOM03214ExactCohort(t *testing.T) {
	source, dir := bomFixtures03214(t)
	if err := writeReleaseBOM03214(dir, source, "0.32.14"); err != nil {
		t.Fatal(err)
	}
	// These two files are created after generation as part of signing.
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte("signed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PROVENANCE.json.sig"), []byte("signed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseBOM03214(dir, "0.32.14"); err != nil {
		t.Fatal(err)
	}
}
func TestReleaseBOM03214TamperBlocks(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(t *testing.T, dir string)
	}{
		{"modified backend binary", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, "neverlauncher-api-linux-x64"), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted plugin", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "neverlauncher-velocity-bridge-0.32.14.jar")); err != nil {
				t.Fatal(err)
			}
		}},
		{"injected artifact", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, "unexpected"), []byte("unsigned"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"modified BOM version", func(t *testing.T, dir string) {
			t.Helper()
			p := filepath.Join(dir, releaseBOMFile03214)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			m["productVersion"] = "0.32.13"
			b, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing component", func(t *testing.T, dir string) {
			t.Helper()
			p := filepath.Join(dir, releaseBOMFile03214)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var m releaseBOM03214
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			m.Components = m.Components[1:]
			b, _ = json.Marshal(m)
			if err := os.WriteFile(p, b, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate source", func(t *testing.T, dir string) {
			t.Helper()
			p := filepath.Join(dir, releaseBOMFile03214)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var m releaseBOM03214
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			m.Components[1] = m.Components[0]
			b, _ = json.Marshal(m)
			if err := os.WriteFile(p, b, 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source, dir := bomFixtures03214(t)
			if err := writeReleaseBOM03214(dir, source, "0.32.14"); err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, dir)
			if err := verifyReleaseBOM03214(dir, "0.32.14"); err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}
func TestReleaseBOM03214VersionAndSymlinkSafety(t *testing.T) {
	source, dir := bomFixtures03214(t)
	if err := os.WriteFile(filepath.Join(source, "VERSION"), []byte("0.32.13\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeReleaseBOM03214(dir, source, "0.32.14"); err == nil {
		t.Fatal("version drift accepted")
	}
	if err := os.WriteFile(filepath.Join(source, "VERSION"), []byte("0.32.14\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "foreign.bin")
	if err := os.Symlink(filepath.Join(dir, "BUILD_NOTES.txt"), bad); err != nil {
		t.Skipf("symlink unsupported: %s", err)
	}
	if err := writeReleaseBOM03214(dir, source, "0.32.14"); err == nil {
		t.Fatal("symlinked artifact accepted")
	}
}
func TestReleaseBOM03214SourcePin(t *testing.T) {
	source, dir := bomFixtures03214(t)
	p := filepath.Join(source, "apps/admin/package-lock.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(raw), `"version": "0.32.14"`, `"version": "0.32.13"`, 1)
	if updated == string(raw) {
		t.Fatal("fixture did not contain version")
	}
	if err := os.WriteFile(p, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeReleaseBOM03214(dir, source, "0.32.14"); err == nil {
		t.Fatal("package lock drift accepted")
	}
}

func TestReleaseBOM03214SignedBoundary(t *testing.T) {
	source, dir := bomFixtures03214(t)
	if err := writeReleaseBOM03214(dir, source, "0.32.14"); err != nil {
		t.Fatal(err)
	}
	digest, _, err := hashFile(filepath.Join(dir, releaseBOMFile03214))
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"version":       "0.32.14",
		"requiredFiles": []string{releaseBOMFile03214},
		"artifacts":     []map[string]any{{"name": releaseBOMFile03214, "required": true, "status": "present", "sha256": digest}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "RELEASE_MANIFEST.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	sums := digest + "  " + releaseBOMFile03214 + "\n" + strings.Repeat("a", 64) + "  RELEASE_MANIFEST.json\n"
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseBOMBinding03214(dir, "0.32.14"); err != nil {
		t.Fatalf("valid signed boundary rejected: %v", err)
	}
	for name, changed := range map[string]string{
		"dropped bom checksum":    strings.Repeat("a", 64) + "  RELEASE_MANIFEST.json\n",
		"duplicated bom checksum": sums + digest + "  " + releaseBOMFile03214 + "\n",
		"altered bom checksum":    strings.Repeat("f", 64) + "  " + releaseBOMFile03214 + "\n" + strings.Repeat("a", 64) + "  RELEASE_MANIFEST.json\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyReleaseBOMBinding03214(dir, "0.32.14"); err == nil {
				t.Fatal("unsigned BOM accepted")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0600); err != nil {
		t.Fatal(err)
	}
	manifest["requiredFiles"] = []string{}
	raw, _ = json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "RELEASE_MANIFEST.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseBOMBinding03214(dir, "0.32.14"); err == nil {
		t.Fatal("non-required BOM accepted")
	}
}
