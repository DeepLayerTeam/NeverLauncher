package extensionlifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJavaRollbackPayloadDigest0305(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	for _, root := range []string{a, b} {
		if err := os.MkdirAll(filepath.Join(root, "backend"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "backend", "extension.jar"), []byte("trusted host"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	expected, e := digestPayload0305(a)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := digestPayload0305(b)
	if e != nil {
		t.Fatal(e)
	}
	if expected != actual {
		t.Fatal("equal payloads have different digests")
	}
	if e := os.WriteFile(filepath.Join(b, "backend", "extension.jar"), []byte("untrusted host"), 0600); e != nil {
		t.Fatal(e)
	}
	changed, e := digestPayload0305(b)
	if e != nil {
		t.Fatal(e)
	}
	if changed == expected {
		t.Fatal("changed backup passed digest verification")
	}
	if e := os.Symlink(filepath.Join(a, "backend", "extension.jar"), filepath.Join(b, "link")); e == nil {
		if _, e := digestPayload0305(b); e == nil {
			t.Fatal("symlink was allowed in backup")
		}
	}
}
