package releasekeypaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseTrustKeyCannotBeAliasedIntoBundle0428(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "trusted.key")
	inside := filepath.Join(bundle, "in.key")
	if err := os.WriteFile(outside, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, outside); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, inside); err == nil {
		t.Fatal("accepted bundled key")
	}
	// Lexically outside the bundle, but resolves to bundled key.
	outsideAlias := filepath.Join(root, "malicious-link.key")
	if err := os.Symlink(inside, outsideAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, outsideAlias); err == nil {
		t.Fatal("accepted symlink to bundled key")
	}
	// Lexically inside the bundle, pointing out, also forbidden.
	insideAlias := filepath.Join(bundle, "external.key")
	if err := os.Symlink(outside, insideAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, insideAlias); err == nil {
		t.Fatal("accepted key path inside bundle")
	}
	// Alias of the bundle directory outside its location.
	bundleAlias := filepath.Join(root, "release-alias")
	if err := os.Symlink(bundle, bundleAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundleAlias, inside); err == nil {
		t.Fatal("accepted key in aliased release bundle")
	}
}
