package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func signedComponentFixture02310(t *testing.T) (string, componentUpdateManifest0157, string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("ELF integration fixture runs on Linux")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target, err := currentDeliveryTarget()
	if err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	rows := []struct{ role, file string }{{"desktop", "neverlauncher-desktop"}, {"guard", "guard"}, {"runtime", "neverruntime"}, {"updater", "neverlauncher-cli"}}
	manifest := componentUpdateManifest0157{SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: "0.23.10", Platform: target.Platform, Architecture: target.Architecture, Layout: "adjacent-files", TrustMode: "sha256-delivery"}
	for _, row := range rows {
		name := filepath.Join(bundle, row.file)
		if err := copyUpdaterSource0156(binary, name, 0o755); err != nil {
			t.Fatal(err)
		}
		hash, size, err := hashFile(name)
		if err != nil {
			t.Fatal(err)
		}
		item := componentUpdateArtifact0157{Component: row.role, SourcePath: row.file, TargetPath: row.file, SHA256: hash, Size: size, Executable: true}
		if row.role == "updater" {
			manifest.SupportFiles = append(manifest.SupportFiles, item)
		} else {
			manifest.Components = append(manifest.Components, item)
		}
	}
	manifest.ComponentSet = &componentSet02310{SchemaVersion: "1.0", Protocols: []componentProtocol02310{
		{Component: "desktop", Provides: map[string]uint32{"guard-ipc": 4}, Requires: []componentProtocolRequirement02310{{"guard", "guard-ipc", 4}, {"runtime", "guard-ipc", 4}, {"updater", "component-update", 2}}},
		{Component: "guard", Provides: map[string]uint32{"guard-ipc": 4}, Requires: []componentProtocolRequirement02310{{"runtime", "guard-ipc", 4}}},
		{Component: "runtime", Provides: map[string]uint32{"guard-ipc": 4}, Requires: []componentProtocolRequirement02310{{"guard", "guard-ipc", 4}}},
		{Component: "updater", Provides: map[string]uint32{"component-update": 2}, Requires: []componentProtocolRequirement02310{{"desktop", "guard-ipc", 4}}},
	}}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	sign := func(manifest componentUpdateManifest0157) {
		raw, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(bundle, componentUpdateManifestFile0157), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		envelope := componentSetSignature02310{SchemaVersion: "1.0", Algorithm: "ed25519", ManifestSHA256: hex.EncodeToString(digest[:]), Signature: hex.EncodeToString(ed25519.Sign(private, raw))}
		sig, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, componentSetSignatureFile02310), sig, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sign(manifest)
	return bundle, manifest, trust, hex.EncodeToString(private)
}

func TestSignedComponentSet02310(t *testing.T) {
	bundle, manifest, trust, _ := signedComponentFixture02310(t)
	old := componentSetTrustedKey02310
	componentSetTrustedKey02310 = trust
	t.Cleanup(func() { componentSetTrustedKey02310 = old })
	path := filepath.Join(bundle, componentUpdateManifestFile0157)
	if err := validateComponentUpdateManifest0157(manifest, bundle, false); err != nil {
		t.Fatal(err)
	}
	if err := verifySignedComponentSet02310(path, manifest, false); err != nil {
		t.Fatal(err)
	}
	// Signature is over exact bytes, not a normalized subset of JSON.
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySignedComponentSet02310(path, manifest, false); err == nil {
		t.Fatal("modified manifest accepted")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	componentSetTrustedKey02310 = strings.Repeat("0", 64)
	if err := verifySignedComponentSet02310(path, manifest, false); err == nil {
		t.Fatal("wrong trusted key accepted")
	}
	componentSetTrustedKey02310 = trust
	broken := manifest
	copySet := *manifest.ComponentSet
	copySet.Protocols = append([]componentProtocol02310{}, manifest.ComponentSet.Protocols...)
	copySet.Protocols[1].Provides = map[string]uint32{"guard-ipc": 3}
	broken.ComponentSet = &copySet
	if err := validateComponentProtocols02310(broken); err == nil {
		t.Fatal("mismatched guard protocol accepted")
	}
	broken = manifest
	copySet = *manifest.ComponentSet
	copySet.Protocols = append([]componentProtocol02310{}, manifest.ComponentSet.Protocols...)
	copySet.Protocols[0].Requires = nil
	broken.ComponentSet = &copySet
	if err := validateComponentProtocols02310(broken); err == nil {
		t.Fatal("missing required dependency accepted")
	}
	broken = manifest
	broken.SupportFiles = nil
	if err := validateComponentProtocols02310(broken); err == nil {
		t.Fatal("missing updater accepted")
	}
}

func TestCoordinatedPackageCommitAndFailure02310(t *testing.T) {
	bundle, manifest, trust, _ := signedComponentFixture02310(t)
	old := componentSetTrustedKey02310
	componentSetTrustedKey02310 = trust
	t.Cleanup(func() { componentSetTrustedKey02310 = old })
	installRoot := t.TempDir()
	for _, item := range append(append([]componentUpdateArtifact0157{}, manifest.Components...), manifest.SupportFiles...) {
		if err := os.WriteFile(filepath.Join(installRoot, item.TargetPath), []byte("old "+item.Component), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Inject a package-content error: the updater must reject before touching live binaries.
	payload := filepath.Join(bundle, manifest.Components[1].SourcePath)
	raw, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := applyComponentPackage0157(bundle, "", "", installRoot, "", 0, false, true); err == nil {
		t.Fatal("tampered component accepted")
	}
	body, err := os.ReadFile(filepath.Join(installRoot, "neverlauncher-desktop"))
	if err != nil || string(body) != "old desktop" {
		t.Fatal("failed package changed live Desktop")
	}
	if err := os.WriteFile(payload, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := applyComponentPackage0157(bundle, "", "", installRoot, "", 0, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if report["status"] != "committed" {
		t.Fatalf("status=%v", report)
	}
	for _, item := range append(append([]componentUpdateArtifact0157{}, manifest.Components...), manifest.SupportFiles...) {
		if err := verifyUpdaterFile0156(filepath.Join(installRoot, item.TargetPath), item.Size, item.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(installRoot, filepath.FromSlash(componentUpdateStateFile0157))); err != nil {
		t.Fatal(err)
	}
	// Produce a ZIP fixture too: extraction must retain detached Ed25519 signature.
	zipPath := filepath.Join(t.TempDir(), "update.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	for _, name := range []string{componentUpdateManifestFile0157, componentSetSignatureFile02310, "neverlauncher-desktop", "guard", "neverruntime", "neverlauncher-cli"} {
		b, e := os.ReadFile(filepath.Join(bundle, name))
		if e != nil {
			t.Fatal(e)
		}
		w, e := zw.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := applyComponentPackage0157(zipPath, "", "", installRoot, "", 0, false, true); err != nil {
		t.Fatal(err)
	}
}

func TestComponentSetInterruptedSwitchRecovery02310(t *testing.T) {
	root := t.TempDir()
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	oldFiles := map[string]string{"neverlauncher-desktop": "old-desktop", "guard": "old-guard", "neverruntime": "old-runtime", "neverlauncher-cli": "old-updater"}
	files := []updaterFileSpec0156{}
	for name, old := range oldFiles {
		if err := os.WriteFile(filepath.Join(root, name), []byte(old), 0o755); err != nil {
			t.Fatal(err)
		}
		body := []byte("new-" + name)
		digest := sha256.Sum256(body)
		files = append(files, updaterFileSpec0156{Path: name, Data: body, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), Executable: true})
	}
	if err := updater.acquireLock(false); err != nil {
		t.Fatal(err)
	}
	journal, err := updater.prepareLocked(updaterRequest0156{Root: root, Namespace: "desktop-guard-runtime", FromVersion: "0.23.9", ToVersion: "0.23.10", Files: files})
	if err != nil {
		t.Fatal(err)
	}
	journal.Phase = "committing"
	if err := updater.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	first := journal.Files[0]
	if err := os.WriteFile(filepath.Join(root, first.Path), []byte("new-"+first.Path), 0o755); err != nil {
		t.Fatal(err)
	}
	journal.Applied = append(journal.Applied, first.Path)
	if err := updater.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	updater.releaseLock()
	if _, err := updater.recover(false); err != nil {
		t.Fatal(err)
	}
	for name, old := range oldFiles {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != old {
			t.Fatalf("mixed active set %s = %q", name, body)
		}
	}
	if _, err := updater.recover(false); err != nil {
		t.Fatalf("recovery must be idempotent: %v", err)
	}
}
