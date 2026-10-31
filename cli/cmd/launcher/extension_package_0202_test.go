package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeExtensionFixture0202(t *testing.T, root string) {
	t.Helper()
	manifest := CanonicalExtensionManifest0201{
		SchemaVersion: "2.0",
		ID:            "ru.example.package",
		Name:          "Package Extension",
		Version:       "1.2.3",
		Publisher:     "Example Publisher",
		API:           "3.7",
		Targets: []CanonicalExtensionTarget0201{
			{Kind: "backend", Entrypoint: "bin/backend"},
			{Kind: "admin", Entrypoint: "admin/index.js"},
		},
		Permissions: []string{"release:read", "ui:extend"},
	}
	if err := writeJSONFile(filepath.Join(root, canonicalExtensionManifestName0201), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "backend"), []byte("#!/bin/sh\necho package\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin", "index.js"), []byte("export const ready = true;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.txt"), []byte("payload asset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionPackageDeterministicPack0202(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExtensionFixture0202(t, source)
	first := filepath.Join(base, "first.nlext")
	second := filepath.Join(base, "second.nlext")
	one, err := packExtensionPackage0202(source, first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := packExtensionPackage0202(source, second)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("deterministic packaging produced different bytes")
	}
	if one["packageIdentity"] != two["packageIdentity"] || one["sha256"] != two["sha256"] {
		t.Fatalf("deterministic identities mismatch: %#v %#v", one, two)
	}
	analysis, err := analyzeExtensionPackage0202(first)
	if err != nil {
		t.Fatal(err)
	}
	defer analysis.Close()
	if analysis.Descriptor.Payload.FileCount != 3 || analysis.Signature != nil {
		t.Fatalf("unexpected package analysis: %#v", analysis.Descriptor)
	}
	if _, ok := analysis.Entries[extensionPackageSBOMName0202]; !ok {
		t.Fatal("SBOM missing")
	}
	if _, ok := analysis.Entries[extensionPackageChecksumsName0202]; !ok {
		t.Fatal("checksums missing")
	}
}

func TestExtensionPackageSignVerifyInspect0202(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExtensionFixture0202(t, source)
	pkg := filepath.Join(base, "extension.nlext")
	packed, err := packExtensionPackage0202(source, pkg)
	if err != nil {
		t.Fatal(err)
	}
	unsignedDigest := packed["sha256"]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(base, "private.key")
	publicPath := filepath.Join(base, "public.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		t.Fatal(err)
	}

	signed, err := signExtensionPackage0202(pkg, pkg, privatePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if signed["packageIdentity"] != packed["packageIdentity"] {
		t.Fatal("signing changed immutable package identity")
	}
	if signed["sha256"] == unsignedDigest {
		t.Fatal("signed archive digest must differ from unsigned archive digest")
	}
	verified, err := verifyExtensionPackage0202(pkg, publicPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if verified["status"] != "signature-verified" || verified["packageIdentity"] != packed["packageIdentity"] {
		t.Fatalf("unexpected verify result: %#v", verified)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublicPath := filepath.Join(base, "wrong-public.key")
	if err := os.WriteFile(wrongPublicPath, []byte(hex.EncodeToString(wrongPub)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyExtensionPackage0202(pkg, wrongPublicPath, false); err == nil || !strings.Contains(err.Error(), "key mismatch") {
		t.Fatalf("expected trusted-key mismatch, got %v", err)
	}
	inspected, err := inspectExtensionPackage0202(pkg, true)
	if err != nil {
		t.Fatal(err)
	}
	if inspected["signed"] != true || inspected["files"] == nil {
		t.Fatalf("unexpected inspect result: %#v", inspected)
	}
	if _, err := signExtensionPackage0202(pkg, pkg, privatePath, false); err == nil || !strings.Contains(err.Error(), "уже подписан") {
		t.Fatalf("expected existing-signature protection, got %v", err)
	}
	firstSignedBytes, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signExtensionPackage0202(pkg, pkg, privatePath, true); err != nil {
		t.Fatal(err)
	}
	secondSignedBytes, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstSignedBytes, secondSignedBytes) {
		t.Fatal("re-signing the same package with the same key is not deterministic")
	}
}

func TestExtensionPackageRejectsMissingEntrypoint0202(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := CanonicalExtensionManifest0201{
		SchemaVersion: "2.0", ID: "ru.example.missing", Name: "Missing", Version: "1.0.0", Publisher: "Example", API: "3.7",
		Targets: []CanonicalExtensionTarget0201{{Kind: "backend", Entrypoint: "bin/missing"}},
	}
	if err := writeJSONFile(filepath.Join(source, canonicalExtensionManifestName0201), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "asset.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := packExtensionPackage0202(source, filepath.Join(base, "missing.nlext"))
	if err == nil || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("expected missing entrypoint rejection, got %v", err)
	}
}

func TestExtensionPackageRejectsSourceSymlink0202(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges are environment-specific on Windows")
	}
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := CanonicalExtensionManifest0201{
		SchemaVersion: "2.0", ID: "ru.example.symlink", Name: "Symlink", Version: "1.0.0", Publisher: "Example", API: "3.7",
		Targets: []CanonicalExtensionTarget0201{{Kind: "backend", Entrypoint: "bin/backend"}},
	}
	if err := writeJSONFile(filepath.Join(source, canonicalExtensionManifestName0201), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(source, "bin", "backend")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := packExtensionPackage0202(source, filepath.Join(base, "symlink.nlext"))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestExtensionPackageRejectsTraversalDuplicateAndSymlinkArchive0202(t *testing.T) {
	cases := []struct {
		name    string
		entries []struct {
			name string
			mode os.FileMode
		}
		want string
	}{
		{name: "traversal", entries: []struct {
			name string
			mode os.FileMode
		}{{"../escape", 0o644}}, want: "unsafe"},
		{name: "duplicate", entries: []struct {
			name string
			mode os.FileMode
		}{{"payload/A.txt", 0o644}, {"payload/a.txt", 0o644}}, want: "duplicate"},
		{name: "symlink", entries: []struct {
			name string
			mode os.FileMode
		}{{"payload/link", os.ModeSymlink | 0o777}}, want: "symlink"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := filepath.Join(t.TempDir(), tc.name+".nlext")
			f, err := os.Create(pkg)
			if err != nil {
				t.Fatal(err)
			}
			zw := zip.NewWriter(f)
			for _, item := range tc.entries {
				h := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
				h.SetMode(item.mode)
				h.SetModTime(time.Unix(1700000000, 0).UTC())
				w, err := zw.CreateHeader(h)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = analyzeExtensionPackage0202(pkg)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestExtensionPackageTamperBreaksImmutableIdentity0202(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExtensionFixture0202(t, source)
	original := filepath.Join(base, "original.nlext")
	if _, err := packExtensionPackage0202(source, original); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(base, "tampered.nlext")
	if err := rewriteExtensionPackageEntryForTest0202(original, tampered, "payload/README.txt", []byte("tampered\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := analyzeExtensionPackage0202(tampered); err == nil {
		t.Fatal("tampered payload unexpectedly preserved package validity")
	}
}

func rewriteExtensionPackageEntryForTest0202(source, output, target string, replacement []byte) error {
	zr, err := zip.OpenReader(source)
	if err != nil {
		return err
	}
	defer zr.Close()
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	for _, entry := range zr.File {
		h := &zip.FileHeader{Name: entry.Name, Method: zip.Deflate}
		h.SetMode(entry.FileInfo().Mode())
		h.SetModTime(entry.Modified)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if entry.Name == target {
			if _, err := w.Write(replacement); err != nil {
				return err
			}
			continue
		}
		r, err := entry.Open()
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, r); err != nil {
			r.Close()
			return err
		}
		if err := r.Close(); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}
