package extensionpackage

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A sandbox policy is authenticated by the existing Ed25519 package signature;
// no separate unsigned policy file or bypassable "trusted" marker is used.
func TestSignedManifestSandboxPolicy0318(t *testing.T) {
	filename, key := buildRegistryTestPackage0203(t, "0.31.8")
	verified, err := VerifyFile(filename, key)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.Sandbox == nil || verified.Manifest.Sandbox.Mode != "trusted" {
		t.Fatalf("signed sandbox policy not preserved: %+v", verified.Manifest.Sandbox)
	}
	original, err := zip.OpenReader(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	corrupt := filepath.Join(t.TempDir(), "tampered.nlext")
	file, err := os.Create(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	changed := false
	for _, entry := range original.File {
		in, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(in)
		_ = in.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == manifestName0203 {
			altered := bytes.Replace(contents, []byte(`"mode": "trusted"`), []byte(`"mode": "isolated"`), 1)
			if bytes.Equal(altered, contents) {
				t.Fatal("sandbox policy not serialized into signed manifest")
			}
			contents = altered
			changed = true
		}
		h := entry.FileHeader
		out, err := zw.CreateHeader(&h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = out.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if !changed {
		t.Fatal("manifest missing")
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyFile(corrupt, key); err == nil {
		t.Fatal("tampered sandbox policy accepted despite package signature")
	}
}
