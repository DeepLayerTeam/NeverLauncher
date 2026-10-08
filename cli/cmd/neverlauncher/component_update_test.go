package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func devComponentManifest0157(t *testing.T, bundle string) componentUpdateManifest0157 {
	t.Helper()
	target, err := currentDeliveryTarget()
	if err != nil {
		t.Fatal(err)
	}
	manifest := componentUpdateManifest0157{
		SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: "0.15.7-test",
		Platform: target.Platform, Architecture: target.Architecture, Layout: "adjacent-files", TrustMode: "development-self-test",
	}
	for _, row := range []struct{ component, name, body string }{
		{"desktop", "neverlauncher-desktop", "desktop-new"},
		{"guard", "neverguard", "guard-new"},
		{"runtime", "neverruntime", "runtime-new"},
	} {
		path := filepath.Join(bundle, row.name)
		if err := os.WriteFile(path, []byte(row.body), 0o755); err != nil {
			t.Fatal(err)
		}
		hash, size, err := hashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Components = append(manifest.Components, componentUpdateArtifact0157{
			Component: row.component, SourcePath: row.name, TargetPath: row.name,
			SHA256: hash, Size: size, Executable: true,
		})
	}
	return manifest
}

func TestComponentUpdateAdjacentCommit0157(t *testing.T) {
	root := t.TempDir()
	bundle := t.TempDir()
	for _, name := range []string{"neverlauncher-desktop", "neverguard", "neverruntime"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("old-"+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	manifest := devComponentManifest0157(t, bundle)
	report, err := applyAdjacentComponentUpdate0157(manifest, bundle, root, filepath.Join(root, "neverlauncher-desktop"), true)
	if err != nil {
		t.Fatal(err)
	}
	if report["status"] != "committed" {
		t.Fatalf("unexpected status: %#v", report)
	}
	for _, component := range manifest.Components {
		if err := verifyUpdaterFile0156(filepath.Join(root, component.TargetPath), component.Size, component.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))); err != nil {
		t.Fatalf("component update state missing: %v", err)
	}
}

func TestComponentTreePostVerifyFailureRollsBack0157(t *testing.T) {
	root := t.TempDir()
	u, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(root, "NeverLauncher.app")
	if err := os.MkdirAll(filepath.Join(live, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(live, "Contents", "MacOS", "neverlauncher-desktop")
	if err := os.WriteFile(old, []byte("old-desktop"), 0o755); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(u.controlDir, "incoming", "NeverLauncher.app")
	if err := os.MkdirAll(filepath.Join(stage, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "Contents", "MacOS", "neverlauncher-desktop"), []byte("new-desktop"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = applyComponentTree0157(u, "NeverLauncher.app", stage, "0.15.6", "0.15.7", func(string) error {
		return errors.New("forced post-verify failure")
	})
	if err == nil {
		t.Fatal("expected rollback error")
	}
	body, readErr := os.ReadFile(old)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != "old-desktop" {
		t.Fatalf("rollback did not restore old app: %q", body)
	}
}

func TestComponentUpdateRequiresPinnedProductionArchive0157(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.zip")
	if err := os.WriteFile(path, []byte("not-an-archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hashPackagePin0157(path, "", false); err == nil {
		t.Fatal("production component update accepted an unpinned package")
	}
}
