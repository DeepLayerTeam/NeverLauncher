package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	prestarter "github.com/DeepLayerTeam/NeverLauncher/prestarter"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func artifact(data []byte) prestarter.Artifact {
	sum := sha256.Sum256(data)
	return prestarter.Artifact{URL: "https://cdn.example.test/file", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}
func signedBundle(t *testing.T, root string, offline bool) Options {
	t.Helper()
	bundle := filepath.Join(root, "bundle")
	if e := os.MkdirAll(bundle, 0700); e != nil {
		t.Fatal(e)
	}
	script := []byte("#!/bin/sh\nif [ -f \"$2\" ]; then :; fi\nprintf '%s\\n' \"$*\" >> \"" + filepath.Join(root, "invocations") + "\"\n")
	if runtime.GOOS == "windows" {
		t.Skip("POSIX script fixture; cross compile checked separately")
	}
	if e := os.WriteFile(filepath.Join(bundle, binaryName()), script, 0700); e != nil {
		t.Fatal(e)
	}
	componentData := []byte("component bytes")
	manifest := []byte("profile manifest")
	java := []byte("java manifest")
	tpath := prestarter.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}
	for _, role := range []string{"neverruntime", "desktop", "neverguard"} {
		tpath.Components = append(tpath.Components, prestarter.Component{Name: role, Artifact: artifact(componentData)})
	}
	cfg := prestarter.Config{SchemaVersion: "1.0", ProjectID: "Project", ProfileID: "profile", Channel: "stable", ProfilePublicKey: strings.Repeat("a", 64), Manifest: artifact(manifest), JavaManifest: artifact(java), Targets: []prestarter.Target{tpath}, Branding: &prestarter.Branding{DisplayName: "Project Launcher", Publisher: "Project"}, InstallerTargets: []prestarter.InstallerTarget{{OS: runtime.GOOS, Arch: runtime.GOARCH, Prestarter: artifact(script)}}}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	payload, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := prestarter.SignedEnvelope(payload, priv)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(bundle, "bootstrap.signed.json"), envelope, 0600); e != nil {
		t.Fatal(e)
	}
	if offline {
		for _, v := range [][]byte{componentData, manifest} {
			a := artifact(v)
			dir := filepath.Join(bundle, "objects")
			os.MkdirAll(dir, 0700)
			if e = os.WriteFile(filepath.Join(dir, a.SHA256), v, 0600); e != nil {
				t.Fatal(e)
			}
		}
		dir := filepath.Join(bundle, "managed-jre")
		os.MkdirAll(dir, 0700)
		os.WriteFile(filepath.Join(dir, "manifest.json"), java, 0600)
	}
	return Options{Root: filepath.Join(root, "app"), Bundle: bundle, TrustedKey: hex.EncodeToString(pub), Offline: offline, NoStart: true}
}
func TestInstallRepairUninstallKeepsGameData(t *testing.T) {
	root := t.TempDir()
	opts := signedBundle(t, root, true)
	if e := Install(context.Background(), opts); e != nil {
		t.Fatal(e)
	}
	game := filepath.Join(opts.Root, "profiles", "Project", "profile", "saves", "world1.dat")
	os.MkdirAll(filepath.Dir(game), 0700)
	os.WriteFile(game, []byte("save data"), 0600)
	if e := os.RemoveAll(opts.Bundle); e != nil {
		t.Fatal(e)
	}
	if e := Repair(context.Background(), opts); e != nil {
		t.Fatal("repair must work without removable media:", e)
	}
	raw, e := os.ReadFile(filepath.Join(root, "invocations"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(raw), "--no-desktop") != 2 || !strings.Contains(string(raw), "--offline") {
		t.Fatalf("incorrect launch args: %s", raw)
	}
	if e = Uninstall(opts); e != nil {
		t.Fatal(e)
	}
	if data, e := os.ReadFile(game); e != nil || string(data) != "save data" {
		t.Fatal("uninstall deleted user save")
	}
	if _, e = os.Stat(filepath.Join(opts.Root, ".neverlauncher-installer")); !os.IsNotExist(e) {
		t.Fatal("installer-owned files remain")
	}
}
func TestTamperedSignedBundleRejected(t *testing.T) {
	root := t.TempDir()
	opts := signedBundle(t, root, false)
	if _, _, e := VerifyBundle(opts.Bundle, opts.TrustedKey, false); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(opts.Bundle, binaryName())
	if e := os.WriteFile(path, []byte("changed"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, _, e := VerifyBundle(opts.Bundle, opts.TrustedKey, false); e == nil {
		t.Fatal("tampered executable was accepted")
	}
	if e := Install(context.Background(), opts); e == nil {
		t.Fatal("installer accepted tampered binary")
	}
}
func TestOfflineMissingObjectRejected(t *testing.T) {
	root := t.TempDir()
	opts := signedBundle(t, root, true)
	entries, _ := os.ReadDir(filepath.Join(opts.Bundle, "objects"))
	os.Remove(filepath.Join(opts.Bundle, "objects", entries[0].Name()))
	if _, _, e := VerifyBundle(opts.Bundle, opts.TrustedKey, true); e == nil {
		t.Fatal("offline bundle missing signed object")
	}
}
func TestCannotReplaceRootTrust(t *testing.T) {
	root := t.TempDir()
	opts := signedBundle(t, root, false)
	opts.TrustedKey = strings.Repeat("0", 64)
	if _, _, e := VerifyBundle(opts.Bundle, opts.TrustedKey, false); e == nil {
		t.Fatal("untrusted signing root accepted")
	}
}

func TestRepairCorruptedInstalledPrestarterFromRetainedOffline(t *testing.T) {
	root := t.TempDir()
	opts := signedBundle(t, root, true)
	if err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	cfg, id, err := VerifyBundle(opts.Bundle, opts.TrustedKey, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = cfg
	release := filepath.Join(opts.Root, ".neverlauncher-installer", "releases", id+"-"+runtime.GOOS+"-"+runtime.GOARCH)
	if err = os.WriteFile(filepath.Join(release, binaryName()), []byte("corrupted"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(opts.Bundle); err != nil {
		t.Fatal(err)
	}
	if err = Repair(context.Background(), opts); err != nil {
		t.Fatal("offline repair failed: ", err)
	}
	if _, err = os.Stat(filepath.Join(root, "invocations")); err != nil {
		t.Fatal(err)
	}
	if err = Uninstall(opts); err != nil {
		t.Fatal(err)
	}
}
