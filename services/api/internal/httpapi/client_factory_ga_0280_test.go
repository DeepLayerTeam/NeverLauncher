package httpapi

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactoryPackageVerified0280(t *testing.T) {
	root := t.TempDir()
	client := filepath.Join(root, "client")
	if err := os.MkdirAll(filepath.Join(client, ".neverlauncher"), 0700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("client-payload")
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(client, "mod.jar"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	lock := []byte(`{"reproducibilitySha256":"` + strings.Repeat("a", 64) + `"}`)
	if err := os.WriteFile(filepath.Join(client, ".neverlauncher", "install-plan.json"), lock, 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"reproducibilitySha256":"` + strings.Repeat("a", 64) + `","outputs":[{"path":"mod.jar","sha256":"` + sha + `","size":14}]}`)
	var plan factoryPlanView02710
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	archive, err := factoryPackageVerified0280(root, client, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(archive)
	z, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(z.File))
	}
	if err := os.WriteFile(filepath.Join(client, "mod.jar"), []byte("corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := factoryPackageVerified0280(root, client, plan); err == nil {
		t.Fatal("export accepted a modified client")
	}
	if err := os.WriteFile(filepath.Join(client, "mod.jar"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(client, "mod.jar")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(client, ".neverlauncher", "install-plan.json"), filepath.Join(client, "mod.jar")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := factoryPackageVerified0280(root, client, plan); err == nil {
		t.Fatal("export accepted a symlink")
	}
}
func TestFactoryPackageVerified0280RejectsTraversal(t *testing.T) {
	root := t.TempDir()
	client := filepath.Join(root, "client")
	var plan factoryPlanView02710
	raw := []byte(`{"reproducibilitySha256":"` + strings.Repeat("a", 64) + `","outputs":[{"path":"../outside.txt","sha256":"` + strings.Repeat("a", 64) + `","size":1}]}`)
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if _, err := factoryPackageVerified0280(root, client, plan); err == nil {
		t.Fatal("accepted traversing path")
	}
}
