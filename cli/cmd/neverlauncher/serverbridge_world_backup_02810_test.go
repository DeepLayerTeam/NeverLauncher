package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeWorldFixture02810(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"server.properties":  "level-name=survival\nonline-mode=true\n",
		"survival/level.dat": "NBT-fixture",
		"survival/playerdata/01234567-89ab-cdef-0123-456789abcdef.dat":         "inventory-with-diamonds",
		"survival/stats/01234567-89ab-cdef-0123-456789abcdef.json":             "{\"stat\":13}",
		"survival_nether/DIM-1/region/r.0.0.mca":                               "nether-region",
		"survival_the_end/DIM1/region/r.0.0.mca":                               "end-region",
		"plugins/Essentials/userdata/01234567-89ab-cdef-0123-456789abcdef.yml": "balance: 1200\n",
		"config/custom.toml": "enabled = true\n",
		"ops.json":           "[]",
	}
	for rel, data := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestWorldBackupCreateVerifyRestore02810(t *testing.T) {
	root := writeWorldFixture02810(t)
	store := filepath.Join(t.TempDir(), "backups")
	if err := worldBackupPrivateDir02810(store); err != nil {
		t.Fatal(err)
	}
	worlds, err := worldBackupWorlds02810(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(worlds, ",") != "survival,survival_nether,survival_the_end" {
		t.Fatalf("worlds: %v", worlds)
	}
	m, err := worldBackupCreate02810(root, store, nil, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalBytes == 0 || m.Consistency != "confirmed-stopped" {
		t.Fatalf("manifest: %+v", m)
	}
	source := filepath.Join(store, m.ID)
	if _, err := worldBackupVerify02810(source); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "recovered-world")
	if err := worldBackupRestore02810(root, store, m, source, dest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"survival/playerdata/01234567-89ab-cdef-0123-456789abcdef.dat", "plugins/Essentials/userdata/01234567-89ab-cdef-0123-456789abcdef.yml", "survival_the_end/DIM1/region/r.0.0.mca", "server.properties"} {
		from, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		to, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(from) != string(to) {
			t.Fatalf("restore mismatch for %s", name)
		}
	}
	if err := worldBackupRestore02810(root, store, m, source, dest); err == nil {
		t.Fatal("existing restore destination overwritten")
	}
	if err := os.WriteFile(filepath.Join(source, "payload", "survival", "level.dat"), []byte("CORRUPT"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := worldBackupVerify02810(source); err == nil {
		t.Fatal("corrupt snapshot verified")
	}
	if err := worldBackupRestore02810(root, store, m, source, filepath.Join(t.TempDir(), "should-not-restore")); err == nil {
		t.Fatal("corrupt snapshot restored")
	}
}
func TestWorldBackupSymlinksAndTraversal02810(t *testing.T) {
	root := writeWorldFixture02810(t)
	if worldBackupValidRelative02810("../escape") || worldBackupValidRelative02810("/absolute") || worldBackupValidRelative02810("a/../../b") || worldBackupValidRelative02810("a\\evil") {
		t.Fatal("path traversal permitted")
	}
	if _, err := worldBackupLocation02810(root, filepath.Join(root, "nested")); err == nil {
		t.Fatal("nested backup store allowed")
	}
	if _, err := worldBackupLocation02810(root, filepath.Dir(root)); err == nil {
		t.Fatal("backup store ancestor of root allowed")
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(root, "survival"), filepath.Join(root, "plugins", "wrong-link")); err != nil {
			t.Fatal(err)
		}
		src, err := worldBackupSources02810(root, []string{"survival"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := worldBackupCollect02810(root, src); err == nil {
			t.Fatal("symlink in plugin data accepted")
		}
	}
}
func TestWorldBackupRequiresStoppedHost02810(t *testing.T) {
	root := writeWorldFixture02810(t)
	paths := hostPaths01910(root)
	if err := os.MkdirAll(paths["dir"], 0700); err != nil {
		t.Fatal(err)
	}
	state := serverBridgeHostRuntime01910{SchemaVersion: "1.0", Status: "running", ProcessPID: os.Getpid(), ProcessIdentity: hostOwnIdentity0282()}
	if err := atomicWriteJSON01910(paths["runtime"], state, 0600); err != nil {
		t.Fatal(err)
	}
	if err := worldBackupQuiesce02810(root, "stopped"); err == nil {
		t.Fatal("active server not rejected")
	}
	if err := worldBackupQuiesce02810(root, "stop"); err == nil {
		t.Fatal("unverified supervisor accepted")
	}
}
func TestWorldBackupRejectsForgedManifest02810(t *testing.T) {
	m := worldBackupManifest02810{Schema: worldBackupSchema02810, ID: strings.Repeat("a", 32), Consistency: "confirmed-stopped", Worlds: []string{"world"}, Entries: []worldBackupEntry02810{{Path: "world", Type: "dir"}, {Path: "world/../../outside", Type: "file", SHA256: strings.Repeat("a", 64)}}}
	if worldBackupManifestValid02810(m) == nil {
		t.Fatal("malicious manifest accepted")
	}
	m.Entries[1].Path = "world/playerdata.dat"
	m.Entries[1].Size = 10
	m.TotalBytes = 10
	if err := worldBackupManifestValid02810(m); err != nil {
		t.Fatal(err)
	}
	m.Entries = append(m.Entries, m.Entries[1])
	if worldBackupManifestValid02810(m) == nil {
		t.Fatal("duplicate entry accepted")
	}
}
