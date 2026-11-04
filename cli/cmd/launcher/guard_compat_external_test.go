package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExternalNativeCompatibility05010(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only external native policy")
	}
	for _, bad := range []string{"relative.so", "/tmp/../x.so", "/proc/self/maps.so", "/tmp/a\\b.so", "/tmp/a.jar", "/tmp//foo.so", "/tmp/foo.so/"} {
		if guardCompatExternalNativePath05010(bad) {
			t.Errorf("accepted unsafe path: %s", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "approved.so")
	if err := os.WriteFile(path, []byte("known overlay image"), 0600); err != nil {
		t.Fatal(err)
	}
	if !guardCompatExternalNativePath05010(path) {
		t.Fatal("real external path rejected")
	}
	hash, err := guardCompatExternalNativeHash05010(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 {
		t.Fatalf("bad digest %s", hash)
	}
	if err = os.WriteFile(path, []byte("modified overlay image"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := guardCompatExternalNativeHash05010(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed == hash {
		t.Fatal("tampering went unnoticed")
	}
	link := filepath.Join(filepath.Dir(path), "link.so")
	if err = os.Symlink(path, link); err == nil {
		if _, e := guardCompatExternalNativeHash05010(link); e == nil {
			t.Fatal("symlink accepted")
		}
	}
	if !strings.HasPrefix(hash, "0") && hash == changed {
		t.Fatal("hash collision")
	}
}

func TestSignedExternalModulePolicy05010(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only external native policy")
	}
	root, key, private := compatFixture0502(t)
	path := filepath.Join(t.TempDir(), "recording-overlay.so")
	if err := os.WriteFile(path, []byte("an exact external module"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := guardCompatExternalNativeHash05010(path)
	if err != nil {
		t.Fatal(err)
	}
	policy := policyFixture0502()
	policy.ExternalNativeModules = []guardCompatExternalNative05010{{Path: path, SHA256: hash}}
	if err := guardCompatInstall0502(root, signCompat0502(t, policy, private), key); err != nil {
		t.Fatal(err)
	}
	launch := func() error {
		return guardCompatValidateLaunch0502(root, policy.ProjectID, policy.Minecraft, policy.Loader, nil, nil)
	}
	if err := launch(); err != nil {
		t.Fatalf("signed overlay refused: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("modified overlay allowed: %v", err)
	}
	if err := os.WriteFile(path, []byte("an exact external module"), 0600); err != nil {
		t.Fatal(err)
	}
	policy.Epoch++
	policy.RevokedDigests = []string{hash}
	if err := guardCompatInstall0502(root, signCompat0502(t, policy, private), key); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked overlay allowed: %v", err)
	}
}
