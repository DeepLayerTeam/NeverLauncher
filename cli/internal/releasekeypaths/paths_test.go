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
	// Лексически вне пакета, но разрешается в ключ внутри пакета.
	outsideAlias := filepath.Join(root, "malicious-link.key")
	if err := os.Symlink(inside, outsideAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, outsideAlias); err == nil {
		t.Fatal("accepted symlink to bundled key")
	}
	// Лексически внутри пакета и указывает наружу — также запрещено.
	insideAlias := filepath.Join(bundle, "external.key")
	if err := os.Symlink(outside, insideAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, insideAlias); err == nil {
		t.Fatal("accepted key path inside bundle")
	}
	// Псевдоним каталога набора вне его расположения.
	bundleAlias := filepath.Join(root, "release-alias")
	if err := os.Symlink(bundle, bundleAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundleAlias, inside); err == nil {
		t.Fatal("accepted key in aliased release bundle")
	}
}
