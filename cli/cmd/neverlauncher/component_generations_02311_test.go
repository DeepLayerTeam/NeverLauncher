package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signComponentGenerationFixture02311(t *testing.T, dir string, m componentUpdateManifest0157, privateHex string) {
	t.Helper()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, componentUpdateManifestFile0157), raw, 0600); err != nil {
		t.Fatal(err)
	}
	pk, err := hex.DecodeString(privateHex)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	sig := componentSetSignature02310{SchemaVersion: "1.0", Algorithm: "ed25519", ManifestSHA256: hex.EncodeToString(digest[:]), Signature: hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(pk), raw))}
	body, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, componentSetSignatureFile02310), body, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestComponentGenerationRealUpdater02311(t *testing.T) {
	if !componentSecurityRequired02311("0.23.11") || componentSecurityRequired02311("0.23.10") {
		t.Fatal("version gate")
	}
	bundle, m, key, private := signedComponentFixture02310(t)
	prior := componentSetTrustedKey02310
	componentSetTrustedKey02310 = key
	t.Cleanup(func() { componentSetTrustedKey02310 = prior })
	root := t.TempDir()
	m.ProductVersion = "0.23.11"
	m.SecurityGeneration = 7
	signComponentGenerationFixture02311(t, bundle, m, private)
	if _, err := applyComponentPackage0157(bundle, "", "", root, "", 0, false, true); err != nil {
		t.Fatal(err)
	}
	floor, err := loadComponentWatermark02311(root)
	if err != nil || floor.Generation != 7 {
		t.Fatalf("floor=%+v %v", floor, err)
	}
	// A replay of exactly the installed signed set is safe (repair/idempotency).
	if err := checkComponentGeneration02311(root, m); err != nil {
		t.Fatal(err)
	}
	m.SecurityGeneration = 6
	signComponentGenerationFixture02311(t, bundle, m, private)
	if _, err := applyComponentPackage0157(bundle, "", "", root, "", 0, false, true); err == nil || !strings.Contains(err.Error(), "anti-rollback") {
		t.Fatalf("old signed set was accepted: %v", err)
	}
	m.SecurityGeneration = 7
	m.ProductVersion = "0.23.12"
	signComponentGenerationFixture02311(t, bundle, m, private)
	if _, err := applyComponentPackage0157(bundle, "", "", root, "", 0, false, true); err == nil {
		t.Fatal("same generation/different content accepted")
	}
	m.SecurityGeneration = 8
	signComponentGenerationFixture02311(t, bundle, m, private)
	if _, err := applyComponentPackage0157(bundle, "", "", root, "", 0, false, true); err != nil {
		t.Fatalf("next generation rejected: %v", err)
	}
	floor, err = loadComponentWatermark02311(root)
	if err != nil || floor.Generation != 8 {
		t.Fatalf("floor after update=%+v %v", floor, err)
	}
	// Crash after committed state but before watermark: recover advances floor
	// only after hashing ALL actual installed binaries.
	m.SecurityGeneration = 9
	m.ProductVersion = "0.23.13"
	signComponentGenerationFixture02311(t, bundle, m, private)
	body, err := componentStateBytes0157(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157)), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := reconcileInstalledComponentGeneration02311(root); err != nil {
		t.Fatal(err)
	}
	floor, err = loadComponentWatermark02311(root)
	if err != nil || floor.Generation != 9 {
		t.Fatalf("recovery floor=%+v %v", floor, err)
	}
	// Neither deleting nor rewriting an installed state to the older version
	// can pass the retained security watermark.
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))); err != nil {
		t.Fatal(err)
	}
	if err := reconcileInstalledComponentGeneration02311(root); err == nil {
		t.Fatal("missing installed state accepted")
	}
}

func TestCorruptedComponentGenerationFloor02311(t *testing.T) {
	root := t.TempDir()
	if err := writeComponentWatermark02311(root, componentGenerationRecord02311{Generation: 3, ManifestDigest: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, componentSecurityState02311+"-1.json"), []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadComponentWatermark02311(root); err == nil {
		t.Fatal("corrupted floor accepted")
	}
}
