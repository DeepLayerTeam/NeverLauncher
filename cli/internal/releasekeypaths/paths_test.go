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
		t.Fatal("Принят ключ, встроенный в пакет")
	}
	// Лексически вне пакета, но разрешается в ключ внутри пакета.
	outsideAlias := filepath.Join(root, "malicious-link.key")
	if err := os.Symlink(inside, outsideAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, outsideAlias); err == nil {
		t.Fatal("Принята символьная ссылка на ключ внутри пакета")
	}
	// Лексически внутри пакета и указывает наружу — также запрещено.
	insideAlias := filepath.Join(bundle, "external.key")
	if err := os.Symlink(outside, insideAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundle, insideAlias); err == nil {
		t.Fatal("Принят путь к ключу внутри пакета")
	}
	// Псевдоним каталога набора вне его расположения.
	bundleAlias := filepath.Join(root, "release-alias")
	if err := os.Symlink(bundle, bundleAlias); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundle(bundleAlias, inside); err == nil {
		t.Fatal("Принят ключ внутри пакета выпуска с альтернативным путём")
	}
}

func TestNewTrustStateOutsideBundle(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state.json")
	if err := OutsideBundleState(bundle, state); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundleState(bundle, filepath.Join(bundle, "state.json")); err == nil {
		t.Fatal("accepted state inside bundle")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(bundle, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := OutsideBundleState(bundle, filepath.Join(alias, "state.json")); err == nil {
		t.Fatal("accepted state in aliased bundle")
	}
	if err := os.Symlink(filepath.Join(bundle, "missing"), state); err != nil {
		t.Fatal(err)
	}
	if err := OutsideBundleState(bundle, state); err == nil {
		t.Fatal("accepted dangling symlink")
	}
}
